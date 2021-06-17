#pragma once

#include "analyzer.h"
#include "metrics.h"
#include "type_config.h"

class sinsp_analyzer;

//
// Connection information class
//
class SINSP_PUBLIC sinsp_connection
{
public:
	enum analysis_flags
	{
		AF_NONE = 0,
		// Connection has been closed. It will have to be removed from the
		// connection table.
		AF_CLOSED = (1 << 0),
		// Connection has been closed and reopened with the same key.
		// I've seen this happen with unix sockets. A successive unix socket pair
		// can be assigned the same addresses of a just closed one.
		// When that happens, the old connection is removed and the new one is
		// added with the AF_REUSED flag, so that the analyzer can detect that
		// connection is different.
		AF_REUSED = (1 << 1),
		// This connection hasn't been established yet (nonblocking connect() was called)
		AF_PENDING = (1 << 2),
		// this connection has failed due to:
		// - connect() error
		// - getsockopt(SOL_SOCKET, SO_ERROR) reporting an error
		// - read/write error
		AF_FAILED = (1 << 3),
	};

	struct state_transition
	{
		state_transition(uint64_t timestamp_, uint8_t state_, int error_code_)
		    : timestamp(timestamp_),
		      state(state_),
		      error_code(error_code_)
		{
		}

		uint64_t timestamp;
		uint8_t state;
		int error_code;
	};

	sinsp_connection();
	sinsp_connection(uint64_t timestamp);
	void reset();
	void reset_server();
	void reset_client();
	void clear();
	bool is_active() const;
	bool is_client_only() const;
	bool is_server_only() const;
	bool is_client_and_server() const;

	void set_state(int errorcode);

	std::vector<state_transition> get_state_history();
	inline void record_state_transition(uint64_t timestamp)
	{
		if (m_record_state_history)
		{
			m_state_history.emplace_back(timestamp, m_analysis_flags, m_error_code);
		}
	}

	int64_t m_spid;
	int64_t m_stid;
	int64_t m_sfd;
	std::string m_scomm;

	int64_t m_dpid;
	int64_t m_dtid;
	int64_t m_dfd;
	std::string m_dcomm;

	uint64_t m_timestamp;
	int8_t m_refcount;

	//
	// Analyzer state
	//
	uint8_t m_analysis_flags;  // Flags word used by the analysis engine.
	int32_t m_error_code;      // last syscall error code
	sinsp_connection_counters m_metrics;
	sinsp_transaction_counters m_transaction_metrics;

	bool m_record_state_history = false;
	std::shared_ptr<sinsp_threadinfo> m_sproc;
	std::shared_ptr<sinsp_threadinfo> m_dproc;

private:
	std::vector<state_transition> m_state_history;
};

class sinsp_connection_aggregator
{
public:
	sinsp_connection_aggregator(const std::set<double>* percentiles = nullptr)
	    : m_transaction_metrics(percentiles),
	      m_count(0)
	{
	}
	void clear();
	void to_protobuf(draiosproto::connection_categories* proto, uint32_t sampling_ratio) const;
	void add(sinsp_connection* conn);
	void add_client(sinsp_connection* conn);
	void add_server(sinsp_connection* conn);
	template<typename ProtobufType>
	static void filter_and_emit(
	    const std::unordered_map<uint16_t, sinsp_connection_aggregator>& map,
	    ProtobufType* proto,
	    uint16_t top,
	    uint32_t sampling_ratio);

private:
	bool is_active() const
	{
		uint32_t totops = m_metrics.m_client.m_count_in + m_metrics.m_client.m_count_out +
		                  m_metrics.m_server.m_count_in + m_metrics.m_server.m_count_out;

		return (totops != 0);
	}
	bool operator<(const sinsp_connection_aggregator& other) const;
	sinsp_connection_counters m_metrics;
	sinsp_transaction_counters m_transaction_metrics;
	uint32_t m_count;
};

template<typename ProtobufType>
void sinsp_connection_aggregator::filter_and_emit(
    const std::unordered_map<uint16_t, sinsp_connection_aggregator>& map,
    ProtobufType* proto,
    uint16_t top,
    uint32_t sampling_ratio)
{
	// Filter the top N
	using map_it_t = std::unordered_map<uint16_t, sinsp_connection_aggregator>::const_iterator;
	std::vector<map_it_t> to_emit_connections;
	for (auto agcit = map.begin(); agcit != map.end(); ++agcit)
	{
		to_emit_connections.push_back(agcit);
	}
	auto to_emit_connections_end = to_emit_connections.end();

	if (to_emit_connections.size() > top)
	{
		to_emit_connections_end = to_emit_connections.begin() + top;
		partial_sort(
		    to_emit_connections.begin(),
		    to_emit_connections_end,
		    to_emit_connections.end(),
		    [](const map_it_t& src, const map_it_t& dst) { return dst->second < src->second; });
	}

	for (auto agcit = to_emit_connections.begin(); agcit != to_emit_connections_end; ++agcit)
	{
		if (!(*agcit)->second.is_active())
		{
			continue;
		}
		auto network_by_server_port = proto->add_network_by_serverports();
		network_by_server_port->set_port((*agcit)->first);
		auto counters = network_by_server_port->mutable_counters();
		(*agcit)->second.to_protobuf(counters, sampling_ratio);
	}
}

// this is really "owned" by the sinsp_connection manager, but because it's a template,
// static fields become messy. SO we'll put them here.
class SINSP_PUBLIC sinsp_connection_manager_configuration
{
private:  // configs
	static type_config<uint32_t> c_max_connection_table_size;
	static type_config<uint64_t> c_connection_timeout_ns;
	static type_config<uint64_t>::ptr c_connection_pruning_interval_ns;

	template<typename Tkey, typename THash, typename TCompare>
	friend class sinsp_connection_manager;
};

template<class TKey, class THash, class TCompare>
class SINSP_PUBLIC sinsp_connection_manager
{
public:
#ifndef _WIN32
	typedef class std::unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator iterator_t;
#endif

	// Returns the pointer to the new connection
	sinsp_connection_manager(sinsp* inspector, sinsp_analyzer& analyzer)
	    : m_inspector(inspector),
	      m_analyzer(analyzer),
	      m_n_drops(0)
	{
		m_track_pending_connections = m_analyzer.audit_tap_track_pending();
	}
	sinsp_connection* add_connection(const TKey& key,
	                                 std::string* comm,
	                                 int64_t pid,
	                                 int64_t tid,
	                                 int64_t fd,
	                                 bool isclient,
	                                 uint64_t timestamp,
	                                 uint8_t flags,
	                                 int32_t error_code);
	sinsp_connection* remove_connection(const TKey& key);
	sinsp_connection* get_connection(const TKey& key, uint64_t timestamp);
	void remove_expired_connections(uint64_t current_ts);

	size_t size() { return m_connections.size(); }

	void clear() { m_connections.clear(); }

	uint32_t get_n_drops() { return m_n_drops; }

	void clear_n_drops() { m_n_drops = 0; }

	std::unordered_map<TKey, sinsp_connection, THash, TCompare> m_connections;
	sinsp* m_inspector;
	sinsp_analyzer& m_analyzer;
	uint64_t m_last_connection_removal_ts;
	uint32_t m_n_drops;
	std::set<double> m_percentiles;

	bool m_track_pending_connections = false;

	using on_new_tcp_connection_cb = std::function<
	    void(const _ipv4tuple&, sinsp_connection&, sinsp_connection::state_transition)>;
	std::list<on_new_tcp_connection_cb> m_on_new_tcp_connection_callbacks;
	void subscribe_on_new_tcp_connection(on_new_tcp_connection_cb callback)
	{
		m_on_new_tcp_connection_callbacks.emplace_back(callback);
	}
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey, THash, TCompare>::add_connection(
    const TKey& key,
    std::string* comm,
    int64_t pid,
    int64_t tid,
    int64_t fd,
    bool isclient,
    uint64_t timestamp,
    uint8_t flags,
    int32_t error_code)
{
	typename std::unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	//
	// First of all, make sure there's space for this connection in the table
	//
	if (m_connections.size() >=
	    sinsp_connection_manager_configuration::c_max_connection_table_size.get_value())
	{
		m_n_drops++;
		return NULL;
	}

	ASSERT((flags & ~(sinsp_connection::AF_PENDING | sinsp_connection::AF_FAILED)) == 0);

	// Check if the tuple is already present into m_connections map
	bool new_tuple = m_connections.find(key) == m_connections.end();

	//
	// Insert the new connection
	//
	sinsp_connection& conn = m_connections[key];

	// Save refcount before updating it
	uint8_t prev_refcount = conn.m_refcount;

	// Get L4 proto from current key
	uint8_t l4proto = 0;
	if (std::is_same<TKey, _ipv4tuple>::value)
	{
		const _ipv4tuple& tuple = (const _ipv4tuple&)key;
		l4proto = tuple.m_fields.m_l4proto;
	}

	conn.m_record_state_history = m_analyzer.audit_tap_enabled();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	if (conn.m_record_state_history ||
	    m_analyzer.secure_audit_enabled() ||
	    m_analyzer.secure_netsec_enabled())
	{
		proc = m_inspector->get_thread_ref(pid,
		                                   false /*don't query the os if not found*/,
		                                   true /*lookup only*/);
	}

	if (m_percentiles.size() && !conn.m_transaction_metrics.has_percentiles())
	{
		conn.m_transaction_metrics.set_percentiles(m_percentiles);
	}

	if (conn.m_timestamp == 0)
	{
		conn.m_timestamp = timestamp;
		conn.m_refcount = 1;
		conn.m_analysis_flags = flags;
		conn.m_error_code = error_code;
		if (isclient)
		{
			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = pid;
			conn.m_scomm = *comm;
			conn.m_sproc = proc;
			conn.m_dtid = 0;
			conn.m_dfd = 0;
			conn.m_dpid = 0;
			conn.m_dproc = nullptr;
		}
		else
		{
			conn.m_stid = 0;
			conn.m_sfd = 0;
			conn.m_spid = 0;
			conn.m_sproc = nullptr;
			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = pid;
			conn.m_dcomm = *comm;
			conn.m_dproc = proc;
		}
	}
	else
	{
		conn.m_timestamp = timestamp;
		conn.m_error_code = error_code;

		//		ASSERT(conn.m_analysis_flags != sinsp_connection::AF_CLOSED);
		//		ASSERT(conn.m_refcount <= 2);
		if (isclient)
		{
			// ASSERT(conn.m_stid == 0);
			// ASSERT(conn.m_sfd == 0);
			// ASSERT(conn.m_spid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a currently open one.
			//
			if (conn.m_stid != 0)
			{
				if ((conn.m_analysis_flags &
				     (sinsp_connection::AF_CLOSED | sinsp_connection::AF_REUSED)) &&
				    conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				if (conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}
			}

			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = pid;
			conn.m_scomm = *comm;
			conn.m_sproc = proc;
		}
		else
		{
			// ASSERT(conn.m_dtid == 0);
			// ASSERT(conn.m_dfd == 0);
			// ASSERT(conn.m_dpid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a currently open one.
			//
			if (conn.m_dtid != 0)
			{
				if ((conn.m_analysis_flags &
				     (sinsp_connection::AF_CLOSED | sinsp_connection::AF_REUSED)) &&
				    conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				if (conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}
			}

			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = pid;
			conn.m_dcomm = *comm;
			conn.m_dproc = proc;
		}
		conn.m_analysis_flags &= ~(sinsp_connection::AF_PENDING | sinsp_connection::AF_FAILED);
		conn.m_analysis_flags |= flags;
	}

	if (!(conn.m_analysis_flags & sinsp_connection::AF_PENDING) || m_track_pending_connections)
	{
		conn.record_state_transition(timestamp);

		// Only if it is TCP and not CLOSED or PENDING
		// Discard multiple state transitions
		// Consider only new_tuple inserted
		// Or refcount increment (this means a new connection or a transition
		// from client_only/server_only to client_and_server)
		// Or REUSED connections
		if (l4proto == SCAP_L4_TCP &&                                  // TCP
			!(conn.m_analysis_flags & sinsp_connection::AF_CLOSED) &&  // !CLOSED connection
			!(conn.m_analysis_flags & sinsp_connection::AF_PENDING)  &&// !PENDING connection
		    (new_tuple ||  // New tuple inserted into m_connections map
		     (conn.m_refcount - prev_refcount ==
		      1) ||  // 0->1 new connection; 1->2 client_only/server_only -> client_and_server
		     (conn.m_analysis_flags & sinsp_connection::AF_REUSED)  // REUSED connection
		     ))
		{
			for (const auto& on_new_tcp_connection_cb : m_on_new_tcp_connection_callbacks)
			{
				on_new_tcp_connection_cb(
				    key,
				    conn,
				    std::move(sinsp_connection::state_transition(timestamp,
				                                                 conn.m_analysis_flags,
				                                                 conn.m_error_code)));
			}
		}
	}

	return &conn;
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey, THash, TCompare>::remove_connection(
    const TKey& key)
{
	typename std::unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	cit = m_connections.find(key);
	if (cit == m_connections.end())
	{
		return nullptr;
	}
	else
	{
		cit->second.m_refcount--;
		ASSERT((cit->second.m_refcount >= 0 && cit->second.m_refcount <= 2) ||
		       ((cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED) != 0));

		if (cit->second.m_refcount <= 0)
		{
			auto prev_flags = cit->second.m_analysis_flags;
			cit->second.m_analysis_flags |= sinsp_connection::AF_CLOSED;
			if (prev_flags != cit->second.m_analysis_flags)
			{
				cit->second.record_state_transition(sinsp_utils::get_current_time_ns());
			}
		}
		return &cit->second;
	}
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey, THash, TCompare>::get_connection(
    const TKey& key,
    uint64_t timestamp)
{
	typename std::unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;
	cit = m_connections.find(key);
	if (cit != m_connections.end())
	{
		cit->second.m_timestamp = timestamp;
		return &(cit->second);
	}
	else
	{
		return NULL;
	}
};

template<class TKey, class THash, class TCompare>
void sinsp_connection_manager<TKey, THash, TCompare>::remove_expired_connections(
    uint64_t current_ts)
{
	if (0 == m_last_connection_removal_ts)
	{
		m_last_connection_removal_ts = current_ts;
		return;
	}

	uint64_t deltats = current_ts - m_last_connection_removal_ts;

	if (deltats <=
	    sinsp_connection_manager_configuration::c_connection_pruning_interval_ns->get_value())
	{
		return;
	}

	typename std::unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit =
	    m_connections.begin();
	while (cit != m_connections.end())
	{
		if (current_ts - cit->second.m_timestamp >
		    sinsp_connection_manager_configuration::c_connection_timeout_ns.get_value())
		{
			cit = m_connections.erase(cit);
		}
		else
		{
			++cit;
		}
	}

	m_last_connection_removal_ts = current_ts;
};

class SINSP_PUBLIC sinsp_ipv4_connection_manager
    : public sinsp_connection_manager<ipv4tuple, ip4t_hash, ip4t_cmp>
{
public:
	sinsp_ipv4_connection_manager(sinsp* inspector, sinsp_analyzer& analyzer)
	    : sinsp_connection_manager<ipv4tuple, ip4t_hash, ip4t_cmp>(inspector, analyzer)
	{
		m_last_connection_removal_ts = 0;
	}
};

class SINSP_PUBLIC sinsp_unix_connection_manager
    : public sinsp_connection_manager<unix_tuple, unixt_hash, unixt_cmp>
{
public:
	sinsp_unix_connection_manager(sinsp* inspector, sinsp_analyzer& analyzer)
	    : sinsp_connection_manager<unix_tuple, unixt_hash, unixt_cmp>(inspector, analyzer)
	{
		m_last_connection_removal_ts = 0;
	}
};

class SINSP_PUBLIC sinsp_pipe_connection_manager
    : public sinsp_connection_manager<uint64_t, std::hash<uint64_t>, std::equal_to<uint64_t>>
{
public:
	sinsp_pipe_connection_manager(sinsp* inspector, sinsp_analyzer& analyzer)
	    : sinsp_connection_manager<uint64_t, std::hash<uint64_t>, std::equal_to<uint64_t>>(
	          inspector,
	          analyzer)
	{
		m_last_connection_removal_ts = 0;
	}
};
