#pragma once

#include "profiling.pb.h"
#include "secure_profiling_handler.h"
#include "secure_profiling_internal_metrics.h"

#include <analyzer_fd.h>
#include <atomic>
#include <draios.pb.h>
#include <sinsp.h>
#include <thread>
#include <unordered_set>

extern sinsp_evttables g_infotables;

#define BL_MAX_FILE_TABLE_SIZE 256
#define BL_MAX_DIRS_TABLE_SIZE 1024
#define BL_MAX_PROG_TABLE_SIZE 1024
#define BL_STARTUP_TIME_NS (30LL * 1000000000)
#define ASYNC_PROC_PARSING

enum file_category : uint32_t
{
	NONE = (1 << 0),
	UNCATEGORIZED = (1 << 1),
	FAILED_OPS = (1 << 2),
	READ_ONLY = (1 << 3),
	READ_WRITE = (1 << 4),
};

//
// The state of the /proc parser thread
//
class proc_parser_state
{
public:
	proc_parser_state(sinsp_baseliner* bl, uint64_t time)
	{
		m_bl = bl;
		m_time = time;
		m_done = false;
		m_inspector = NULL;
	}

	~proc_parser_state()
	{
		if (m_inspector != NULL)
		{
			delete m_inspector;
		}
	}

	sinsp_baseliner* m_bl;
	uint64_t m_time;
	sinsp* m_inspector;

	std::atomic<bool> m_done;
};

//
// This class stores the set of files that a program accesses
//
class blfiletable
{
public:
	blfiletable()
	{
		m_is_r_full = false;
		m_is_rw_full = false;
		m_is_c_full = false;
		m_is_other_full = false;
		m_is_uncategorized_full = false;
		m_is_failed_full = false;
		m_max_table_size = BL_MAX_FILE_TABLE_SIZE;
	}

	void clear()
	{
		m_is_r_full = false;
		m_is_rw_full = false;
		m_is_c_full = false;
		m_is_other_full = false;
		m_is_uncategorized_full = false;
		m_is_failed_full = false;
		m_r.clear();
		m_rw.clear();
		m_c.clear();
		m_other.clear();
		m_uncategorized.clear();
		m_failed.clear();
	}

	inline void insert(std::set<std::string>* table, std::string* name) { table->insert(*name); }

	inline void erase_from_uncategorized(std::string* name)
	{
		if (m_uncategorized.size() != 0)
		{
			auto it = m_uncategorized.find(*name);

			if (it != m_uncategorized.end())
			{
				m_uncategorized.erase(it);
			}
		}
	}

	inline void erase_from_r(std::string* name)
	{
		if (m_r.size() != 0)
		{
			auto it = m_r.find(*name);

			if (it != m_r.end())
			{
				m_r.erase(it);
			}
		}
	}

	inline void add(std::string& name, file_category cat)
	{
		if (cat & FAILED_OPS)
		{
			if (!m_is_failed_full)
			{
				insert(&m_failed, &name);
				if (m_failed.size() >= m_max_table_size)
				{
					m_is_failed_full = true;
				}
			}
		}
		else if (cat & READ_WRITE)
		{
			if (!m_is_rw_full)
			{
				insert(&m_rw, &name);
				if (m_rw.size() >= m_max_table_size)
				{
					m_is_rw_full = true;
				}

				erase_from_uncategorized(&name);
				erase_from_r(&name);
			}
		}
		else if (cat & READ_ONLY)
		{
			if (!m_is_r_full)
			{
				insert(&m_r, &name);
				if (m_r.size() >= m_max_table_size)
				{
					m_is_r_full = true;
				}

				erase_from_uncategorized(&name);
			}
		}
		else if (cat & UNCATEGORIZED)
		{
			if (!m_is_uncategorized_full)
			{
				insert(&m_uncategorized, &name);
				if (m_uncategorized.size() >= m_max_table_size)
				{
					m_is_uncategorized_full = true;
				}
			}
		}
		else
		{
			if (!m_is_other_full)
			{
				insert(&m_other, &name);
				if (m_other.size() >= m_max_table_size)
				{
					m_is_other_full = true;
				}

				erase_from_uncategorized(&name);
			}
		}
	}

	//
	// Convert a filename into a directory by filtering out the last part and
	// then add it as we would add a normal file
	//
	inline static std::string file_to_dir(std::string& filename)
	{
		size_t pos = filename.rfind('/');

		if (pos != std::string::npos)
		{
			if (pos < filename.size() - 1)
			{
				std::string ts(filename, 0, pos + 1);
				return ts;
			}
		}
		else
		{
			std::string ts("/");
			return ts;
		}

		return "/";
	}

	//
	// Convert a filename into a directory by filtering out the last part and
	// then add it as we would add a normal file
	//
	inline static std::string reduce_dir(std::string& filename)
	{
		size_t pos = filename.rfind('/');

		if (pos != std::string::npos)
		{
			if (pos < filename.size() - 1)
			{
				std::string ts(filename, 0, pos + 1);
				return ts;
			}
		}
		else
		{
			std::string ts("/");
			return ts;
		}

		ASSERT(false);
	}

	inline static file_category flags2filecategory(file_category orig_category, uint32_t openflags)
	{
		if (openflags & PPM_O_WRONLY)
		{
			return static_cast<file_category>(orig_category | file_category::READ_WRITE);
		}
		else if (openflags & PPM_O_RDONLY)
		{
			return static_cast<file_category>(orig_category | file_category::READ_ONLY);
		}
		else
		{
			return orig_category;
		}
	}

	void serialize_protobuf(secure::profiling::sub_category_container* cat)
	{
		if (m_r.size() != 0)
		{
			secure::profiling::sub_category* sr = cat->add_subcats();
			sr->set_name("r");
			sr->set_full(m_is_r_full);

			for (auto it : m_r)
			{
				sr->add_d(it);
			}
		}

		if (m_rw.size() != 0)
		{
			secure::profiling::sub_category* srw = cat->add_subcats();
			srw->set_name("rw");
			srw->set_full(m_is_r_full);

			for (auto it : m_rw)
			{
				srw->add_d(it);
			}
		}

		if (m_other.size() != 0)
		{
			secure::profiling::sub_category* sother = cat->add_subcats();
			sother->set_name("other");
			sother->set_full(m_is_other_full);

			for (auto it : m_other)
			{
				sother->add_d(it);
			}
		}

		if (m_uncategorized.size() != 0)
		{
			secure::profiling::sub_category* suncategorized = cat->add_subcats();
			suncategorized->set_name("uncategorized");
			suncategorized->set_full(m_is_uncategorized_full);

			for (auto it : m_uncategorized)
			{
				suncategorized->add_d(it);
			}
		}

		if (m_failed.size() != 0)
		{
			secure::profiling::sub_category* sfailed = cat->add_subcats();
			sfailed->set_name("failed");
			sfailed->set_full(m_is_failed_full);

			for (auto it : m_failed)
			{
				sfailed->add_d(it);
			}
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if (m_r.size() != 0)
		{
			for (auto it : m_r)
			{
				echild[it] = 1;
			}
			element["r"]["d"] = echild;
			element["r"]["full"] = m_is_r_full;
			echild.clear();
		}

		if (m_rw.size() != 0)
		{
			for (auto it : m_rw)
			{
				echild[it] = 1;
			}
			element["rw"]["d"] = echild;
			element["rw"]["full"] = m_is_rw_full;
			echild.clear();
		}

		if (m_other.size() != 0)
		{
			for (auto it : m_other)
			{
				echild[it] = 1;
			}
			element["other"]["d"] = echild;
			element["other"]["full"] = m_is_other_full;
			echild.clear();
		}

		if (m_uncategorized.size() != 0)
		{
			for (auto it : m_uncategorized)
			{
				echild[it] = 1;
			}
			element["uncategorized"]["d"] = echild;
			element["uncategorized"]["full"] = m_is_uncategorized_full;
			echild.clear();
		}

		if (m_failed.size() != 0)
		{
			for (auto it : m_failed)
			{
				echild[it] = 1;
			}
			element["failed"]["d"] = echild;
			element["failed"]["full"] = m_is_failed_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_r.size() != 0) || (m_rw.size() != 0) || (m_c.size() != 0) ||
		       (m_other.size() != 0) || (m_uncategorized.size() != 0) || (m_failed.size() != 0);
	}

	std::set<std::string> m_r;      // entries opened for reading only
	std::set<std::string> m_rw;     // entries opened for read and write
	std::set<std::string> m_c;      // entries opened with the create flag
	std::set<std::string> m_other;  // entries that have only flags different from read or write
	std::set<std::string>
	    m_uncategorized;  // entries not categorized yet, likely because they come from scanning
	                      // proc, where we don't extract open flags yet
	std::set<std::string> m_failed;  // entries coming from failed operations
	bool m_is_r_full;
	bool m_is_rw_full;
	bool m_is_c_full;
	bool m_is_other_full;
	bool m_is_uncategorized_full;
	bool m_is_failed_full;
	uint32_t m_max_table_size;
};

//
// This class manages two blfiletable tables, one for the process startup phase and one
// for regular long term activity
//
class blfiletable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add(std::string& name, file_category cat, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add(name, cat);
		}
		else
		{
			m_regular_table.add(name, cat);
		}
	}

	void serialize_protobuf(secure::profiling::category* cat)
	{
		if (m_startup_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if (m_regular_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if (!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if (!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data() { return m_startup_table.has_data() || m_regular_table.has_data(); }

	blfiletable m_startup_table;
	blfiletable m_regular_table;
};

//
// This class stores the set of programs that a process executes
//
class blprogtable
{
public:
	blprogtable() { m_is_p_full = false; }

	void clear()
	{
		m_is_p_full = false;
		m_p.clear();
	}

	inline void add(std::string& name)
	{
		if (!m_is_p_full)
		{
			m_p.insert(name);
			if (m_p.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_p_full = true;
			}
		}
	}

	void serialize_protobuf(secure::profiling::sub_category_container* cat)
	{
		if (m_p.size() != 0)
		{
			secure::profiling::sub_category* sp = cat->add_subcats();
			sp->set_name("p");
			sp->set_full(m_is_p_full);

			for (auto it : m_p)
			{
				sp->add_d(it);
			}
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if (m_p.size() != 0)
		{
			for (auto it : m_p)
			{
				echild[it] = 1;
			}
			element["p"]["d"] = echild;
			element["p"]["full"] = m_is_p_full;
			echild.clear();
		}
	}

	bool has_data() { return (m_p.size() != 0); }

	std::set<std::string> m_p;
	bool m_is_p_full;
};

//
// This class stores the set of system calls that a program accesses
//
class syscallstable
{
public:
	syscallstable() { m_is_p_full = false; }

	void clear()
	{
		m_is_p_full = false;
		m_p.clear();
	}

	inline void add(uint32_t val)
	{
		if (!m_is_p_full)
		{
			m_p.insert(val);
			if (m_p.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_p_full = true;
			}
		}
	}

	inline const char* id_to_str(uint32_t id)
	{
		if ((id & 0xffff) != 0)
		{
			return sinsp_utils::event_name_by_id(id);
		}
		else
		{
			id = id >> 16;
			if (id < PPM_SC_MAX)
			{
				return g_infotables.m_syscall_info_table[id].name;
			}
			else
			{
				ASSERT(false);
				return "NA";
			}
		}
	}

	void serialize_protobuf(secure::profiling::sub_category_container* cat)
	{
		if (m_p.size() != 0)
		{
			secure::profiling::sub_category* sp = cat->add_subcats();
			sp->set_name("p");
			sp->set_full(m_is_p_full);

			for (auto it : m_p)
			{
				sp->add_d(id_to_str(it));
			}
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if (m_p.size() != 0)
		{
			for (auto it : m_p)
			{
				echild[id_to_str(it)] = 1;
			}
			element["p"]["d"] = echild;
			element["p"]["full"] = m_is_p_full;
			echild.clear();
		}
	}

	bool has_data() { return (m_p.size() != 0); }

	std::set<uint32_t> m_p;
	bool m_is_p_full;
};

//
// This class manages two tables that require a simple add, one for the process startup phase and
// one for regular long term activity
//
template<class A, typename B>
class simpletable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add(B val, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add(val);
		}
		else
		{
			m_regular_table.add(val);
		}
	}

	void serialize_protobuf(secure::profiling::category* cat)
	{
		if (m_startup_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if (m_regular_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if (!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if (!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data() { return m_startup_table.has_data() || m_regular_table.has_data(); }

	A m_startup_table;
	A m_regular_table;
};

//
// This class keeps track of the ports that a program uses
//
class blporttable
{
public:
	blporttable()
	{
		m_is_l_tcp_full = false;
		m_is_r_tcp_full = false;
		m_is_l_udp_full = false;
		m_is_r_udp_full = false;
	}

	void clear()
	{
		m_is_l_tcp_full = false;
		m_is_r_tcp_full = false;
		m_l_tcp.clear();
		m_r_tcp.clear();
		m_is_l_udp_full = false;
		m_is_r_udp_full = false;
		m_l_udp.clear();
		m_r_udp.clear();
	}

	inline void add_l_tcp(uint16_t port)
	{
		if (!m_is_l_tcp_full)
		{
			m_l_tcp.insert(port);
			if (m_l_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_l_tcp_full = true;
			}
		}
	}

	inline void add_r_tcp(uint16_t port)
	{
		if (!m_is_r_tcp_full)
		{
			m_r_tcp.insert(port);
			if (m_r_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_r_tcp_full = true;
			}
		}
	}

	inline void add_l_udp(uint16_t port)
	{
		if (!m_is_l_udp_full)
		{
			m_l_udp.insert(port);
			if (m_l_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_l_udp_full = true;
			}
		}
	}

	inline void add_r_udp(uint16_t port)
	{
		if (!m_is_r_udp_full)
		{
			m_r_udp.insert(port);
			if (m_r_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_r_udp_full = true;
			}
		}
	}

	inline void add(blporttable& other)
	{
		if (!m_is_r_tcp_full)
		{
			for (auto it : other.m_r_tcp)
			{
				add_r_tcp(it);
			}
		}

		if (!m_is_l_tcp_full)
		{
			for (auto it : other.m_l_tcp)
			{
				add_l_tcp(it);
			}
		}

		if (!m_is_r_udp_full)
		{
			for (auto it : other.m_r_udp)
			{
				add_r_udp(it);
			}
		}

		if (!m_is_l_udp_full)
		{
			for (auto it : other.m_l_udp)
			{
				add_l_udp(it);
			}
		}
	}

	void serialize_protobuf(secure::profiling::sub_category_container* cat)
	{
		if (m_l_tcp.size() != 0)
		{
			secure::profiling::sub_category* sl_tcp = cat->add_subcats();
			sl_tcp->set_name("l_tcp");
			sl_tcp->set_full(m_is_l_tcp_full);

			for (auto it : m_l_tcp)
			{
				sl_tcp->add_d(std::to_string(it));
			}
		}

		if (m_r_tcp.size() != 0)
		{
			secure::profiling::sub_category* sr_tcp = cat->add_subcats();
			sr_tcp->set_name("r_tcp");
			sr_tcp->set_full(m_is_r_tcp_full);

			for (auto it : m_r_tcp)
			{
				sr_tcp->add_d(std::to_string(it));
			}
		}

		if (m_l_udp.size() != 0)
		{
			secure::profiling::sub_category* sl_udp = cat->add_subcats();
			sl_udp->set_name("l_udp");
			sl_udp->set_full(m_is_l_udp_full);

			for (auto it : m_l_udp)
			{
				sl_udp->add_d(std::to_string(it));
			}
		}

		if (m_r_udp.size() != 0)
		{
			secure::profiling::sub_category* sr_udp = cat->add_subcats();
			sr_udp->set_name("r_udp");
			sr_udp->set_full(m_is_r_udp_full);

			for (auto it : m_r_udp)
			{
				sr_udp->add_d(std::to_string(it));
			}
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if (m_l_tcp.size() != 0)
		{
			for (auto it : m_l_tcp)
			{
				echild[std::to_string(it)] = 1;
			}
			element["l_tcp"]["d"] = echild;
			element["l_tcp"]["full"] = m_is_l_tcp_full;
			echild.clear();
		}

		if (m_r_tcp.size() != 0)
		{
			for (auto it : m_r_tcp)
			{
				echild[std::to_string(it)] = 1;
			}
			element["r_tcp"]["d"] = echild;
			element["r_tcp"]["full"] = m_is_r_tcp_full;
			echild.clear();
		}

		if (m_l_udp.size() != 0)
		{
			for (auto it : m_l_udp)
			{
				echild[std::to_string(it)] = 1;
			}
			element["l_udp"]["d"] = echild;
			element["l_udp"]["full"] = m_is_l_udp_full;
			echild.clear();
		}

		if (m_r_udp.size() != 0)
		{
			for (auto it : m_r_udp)
			{
				echild[std::to_string(it)] = 1;
			}
			element["r_udp"]["d"] = echild;
			element["r_udp"]["full"] = m_is_r_udp_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_l_tcp.size() != 0) || (m_r_tcp.size() != 0) || (m_l_udp.size() != 0) ||
		       (m_r_udp.size() != 0);
	}

	std::set<uint16_t> m_l_tcp;  // local TCP server ports
	std::set<uint16_t> m_r_tcp;  // remote TCP server ports
	std::set<uint16_t> m_l_udp;  // local TCP server ports
	std::set<uint16_t> m_r_udp;  // remote TCP server ports
	bool m_is_l_tcp_full;
	bool m_is_r_tcp_full;
	bool m_is_l_udp_full;
	bool m_is_r_udp_full;
};

//
// This class manages two blporttable tables, one for the process startup phase and one
// for regular long term activity
//
class blporttable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add_l_tcp(uint16_t port, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_l_tcp(port);
		}
		else
		{
			m_regular_table.add_l_tcp(port);
		}
	}

	inline void add_r_tcp(uint16_t port, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_r_tcp(port);
		}
		else
		{
			m_regular_table.add_r_tcp(port);
		}
	}

	inline void add_l_udp(uint16_t port, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_l_udp(port);
		}
		else
		{
			m_regular_table.add_l_udp(port);
		}
	}

	inline void add_r_udp(uint16_t port, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_r_udp(port);
		}
		else
		{
			m_regular_table.add_r_udp(port);
		}
	}

	void serialize_protobuf(secure::profiling::category* cat)
	{
		if (m_startup_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if (m_regular_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if (!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if (!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data() { return m_startup_table.has_data() || m_regular_table.has_data(); }

	blporttable m_startup_table;
	blporttable m_regular_table;
};

//
// This class keeps track of the ports that a program uses
//
class bl_ip_endpoint_table
{
public:
	bl_ip_endpoint_table()
	{
		m_is_c_tcp_full = false;
		m_is_s_tcp_full = false;
		m_is_udp_full = false;
	}

	void clear()
	{
		m_is_c_tcp_full = false;
		m_is_s_tcp_full = false;
		m_c_tcp.clear();
		m_s_tcp.clear();
		m_is_udp_full = false;
		m_udp.clear();
	}

	inline void add_c_tcp(uint32_t ip)
	{
		if (!m_is_c_tcp_full)
		{
			m_c_tcp.insert(ip);
			if (m_c_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_c_tcp_full = true;
			}
		}
	}

	inline void add_s_tcp(uint32_t ip)
	{
		if (!m_is_s_tcp_full)
		{
			m_s_tcp.insert(ip);
			if (m_s_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_s_tcp_full = true;
			}
		}
	}

	inline void add_udp(uint32_t ip)
	{
		if (!m_is_udp_full)
		{
			m_udp.insert(ip);
			if (m_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_udp_full = true;
			}
		}
	}

	inline void add(bl_ip_endpoint_table& other)
	{
		if (!m_is_c_tcp_full)
		{
			for (auto it : other.m_c_tcp)
			{
				add_c_tcp(it);
			}
		}

		if (!m_is_s_tcp_full)
		{
			for (auto it : other.m_s_tcp)
			{
				add_s_tcp(it);
			}
		}

		if (!m_is_udp_full)
		{
			for (auto it : other.m_udp)
			{
				add_udp(it);
			}
		}
	}

	static uint32_t c_subnet(uint32_t ip) { return ip & 0x00FFFFFF; }

	void serialize_protobuf(secure::profiling::sub_category_container* cat)
	{
		char addrbuff[32];

		if (m_c_tcp.size() != 0)
		{
			secure::profiling::sub_category* sc_tcp = cat->add_subcats();
			sc_tcp->set_name("c_tcp");
			sc_tcp->set_full(m_is_c_tcp_full);

			for (auto it : m_c_tcp)
			{
				sc_tcp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}

		if (m_s_tcp.size() != 0)
		{
			secure::profiling::sub_category* ss_tcp = cat->add_subcats();
			ss_tcp->set_name("s_tcp");
			ss_tcp->set_full(m_is_s_tcp_full);

			for (auto it : m_s_tcp)
			{
				ss_tcp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}

		if (m_udp.size() != 0)
		{
			secure::profiling::sub_category* sudp = cat->add_subcats();
			sudp->set_name("udp");
			sudp->set_full(m_is_udp_full);

			for (auto it : m_udp)
			{
				sudp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;
		char addrbuff[32];

		if (m_c_tcp.size() != 0)
		{
			for (auto it : m_c_tcp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["c_tcp"]["d"] = echild;
			element["c_tcp"]["full"] = m_is_c_tcp_full;
			echild.clear();
		}

		if (m_s_tcp.size() != 0)
		{
			for (auto it : m_s_tcp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["s_tcp"]["d"] = echild;
			element["s_tcp"]["full"] = m_is_s_tcp_full;
			echild.clear();
		}

		if (m_udp.size() != 0)
		{
			for (auto it : m_udp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["udp"]["d"] = echild;
			element["udp"]["full"] = m_is_udp_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_c_tcp.size() != 0) || (m_s_tcp.size() != 0) || (m_udp.size() != 0);
	}

	std::set<uint32_t> m_c_tcp;  // TCP client endpoints
	std::set<uint32_t> m_s_tcp;  // TCP server endpoints
	std::set<uint32_t> m_udp;    // UDP endpoints
	bool m_is_c_tcp_full;
	bool m_is_s_tcp_full;
	bool m_is_udp_full;
};

//
// This class manages two bl_ip_endpoint_table tables, one for the process startup phase and one
// for regular long term activity
//
class bl_ip_endpoint_table_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add_c_tcp(uint32_t ip, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_c_tcp(ip);
		}
		else
		{
			m_regular_table.add_c_tcp(ip);
		}
	}

	inline void add_s_tcp(uint32_t ip, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_s_tcp(ip);
		}
		else
		{
			m_regular_table.add_s_tcp(ip);
		}
	}

	inline void add_udp(uint32_t ip, uint64_t time_from_clone)
	{
		if (time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_udp(ip);
		}
		else
		{
			m_regular_table.add_udp(ip);
		}
	}

	void serialize_protobuf(secure::profiling::category* cat)
	{
		if (m_startup_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if (m_regular_table.has_data())
		{
			secure::profiling::sub_category_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if (!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if (!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data() { return m_startup_table.has_data() || m_regular_table.has_data(); }

	bl_ip_endpoint_table m_startup_table;
	bl_ip_endpoint_table m_regular_table;
};

//
// Program State
//
class blprogram
{
public:
	blprogram()
	{
		m_dirs.m_regular_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
		m_dirs.m_startup_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
	}

	blprogram(std::string& comm) { m_comm = comm; }

	std::string m_comm;  // Command name (e.g. "top")
	std::string m_exe;   // argv[0] (e.g. "sshd: user@pts/4")
	std::vector<uint64_t> m_pids;
	// std::string m_parent_comm; // Parent command name (e.g. "top")
	// std::vector<std::string> m_args; // Command line arguments (e.g. "-d1")
	// std::vector<std::string> m_env; // Environment variables
	std::string m_container_id;  // heuristic-based container id
	uint32_t m_user_id;          // user id
	blfiletable_split m_files;
	blfiletable_split m_dirs;
	simpletable_split<blprogtable, std::string&> m_executed_programs;
	blporttable_split m_server_ports;
	blporttable_split m_bound_ports;
	bl_ip_endpoint_table_split m_ip_endpoints;
	bl_ip_endpoint_table_split m_c_subnet_endpoints;
	simpletable_split<syscallstable, uint32_t> m_syscalls;
};

class secure_profiling_data_ready_handler
{
public:
	virtual ~secure_profiling_data_ready_handler() = default;
	/// secure_profiling_data_ready is an analyzer interface provided to secure_profiling
	/// in order to call secure_profiling_handler
	/// \param ts
	/// \param secure_profilings
	virtual void secure_profiling_data_ready(
	    uint64_t ts,
	    const secure::profiling::fingerprint* secure_profiling_fingerprint) = 0;
};

//
// The baseliner class
//
class sinsp_baseliner
{
public:
	sinsp_baseliner(sinsp_analyzer& m_analyzer, sinsp* m_inspector);
	~sinsp_baseliner();

	void init();
	void set_data_handler(secure_profiling_data_ready_handler* handler);
	const secure::profiling::fingerprint* get_fingerprint(uint64_t timestamp);	
	void set_internal_metrics(secure_profiling_internal_metrics* internal_metrics);
	void set_baseline_runtime_enable_start_time(uint64_t ts);
	void load_tables(uint64_t time);
	void clear_tables();
	void register_callbacks(sinsp_fd_listener* listener);
	void serialize_json(std::string filename);
#ifdef ASYNC_PROC_PARSING
	void merge_proc_data();
#endif
	void serialize_protobuf();
	void emit_as_protobuf(uint64_t time);
	void flush(uint64_t time);

	void on_file_open(sinsp_evt* evt, std::string& name, uint32_t openflags);
	void on_new_proc(sinsp_evt* evt, sinsp_threadinfo* tinfo);
	void on_connect(sinsp_evt* evt);
	void on_accept(sinsp_evt* evt, sinsp_fdinfo_t* fdinfo);
	void on_bind(sinsp_evt* evt);
	inline void extract_from_event(sinsp_evt* evt);
	void process_event(sinsp_evt* evt);

	void init_programs(sinsp* inspector, uint64_t time, bool skip_fds);
	inline blprogram* get_program(sinsp_threadinfo* tinfo);
	inline void add_fd_from_io_evt(sinsp_evt* evt, enum ppm_event_category category);

	sinsp* get_inspector();
	void start_baseline_calculation();
	bool is_baseline_runtime_start_init();
	bool should_start_baseline_calculation();
	void enable_baseline_calculation();
	void disable_baseline_calculation();
	bool is_baseline_runtime_enabled() const;
	bool is_drops_buffer_rate_critical(float max_drops_buffer_rate_percentage) const;

private:
	// Protobuf containing fingerprints emitted to the collector
	secure::profiling::fingerprint* m_secure_profiling_fingerprint_batch;
	secure_profiling_data_ready_handler* m_profiling_data_handler;
	secure_profiling_internal_metrics* m_profiling_internal_metrics;

	// Statistics about an in progress baseliner capture.  This is
	// a subset of scap_stats, containing only the relevant field
	// needed for the baseliner.
	struct baseliner_stats
	{
		uint64_t n_evts;          ///< Total number of events that were received by the driver.
		uint64_t n_drops_buffer;  ///< Number of dropped events caused by full buffer.
		baseliner_stats()
		{
			n_evts = 0;
			n_drops_buffer = 0;
		}
	};

	sinsp* m_inspector;
	sinsp_analyzer& m_analyzer;
	sinsp_network_interfaces* m_ifaddr_list;
	std::unordered_map<size_t, blprogram*> m_progtable;
#ifdef ASYNC_PROC_PARSING
	std::thread* m_procparser_thread;
	proc_parser_state* m_procparser_state;
#endif
	std::unordered_multimap<uint16_t, std::shared_ptr<sinsp_filter_check>> m_nofd_fs_extractors;
	bool m_do_baseline_calculation;
	uint64_t m_baseline_runtime_enable_start_time;
	bool m_baseline_runtime_start_init;

	// The baseliner stats stores counters in order to compute the
	// buffer drop ratio, during a baseliner capture.  They
	// contain meaningful data only if the baseliner is turned on
	// (i.e. m_do_baseline_calculation set to true), and values
	// are set 0 otherwise.  They are updated at baseliner start
	// and at each emission with the progressive values coming
	// from the relevant scap_stats counters.
	baseliner_stats m_baseliner_stats;
};
