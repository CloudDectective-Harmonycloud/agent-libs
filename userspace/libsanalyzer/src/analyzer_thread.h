#pragma once

#include "analyzer_file_stat.h"
#include "analyzer_settings.h"
#include "analyzer_thread_type.h"
#include "analyzer_utils.h" /* make_unique */
#include "app_checks_proxy_interface.h"
#include "delays.h"
#include "env_hash.h"
#include "procfs_parser.h"
#include "protostate.h"
#include "transactinfo.h"

#include <chrono>
#include <memory>

class audit_tap;

///////////////////////////////////////////////////////////////////////////////
// Information that is included only in processes that are main threads
///////////////////////////////////////////////////////////////////////////////
class sinsp_procinfo
{
public:
	void clear();
	uint64_t get_tot_cputime();

	// True if this process is outside the top list that goes in the sample.
	bool m_exclude_from_sample;
	// Aggreaged metrics for the process.
	// This field is allocated only for process main threads.
	sinsp_counters m_proc_metrics;
	// Aggreaged transaction metrics for the process.
	// This field is allocated only for process main threads.
	sinsp_transaction_counters m_proc_transaction_metrics;
	// The ratio between the number of connections waiting to be served and
	// the total connection queue length for this process.
	uint32_t m_connection_queue_usage_pct;
	// The ratio between open FDs and maximum available FDs fir this thread
	uint32_t m_fd_usage_pct;
	// the process capcity score calculated with our secret sauce algorithms
	float m_capacity_score;
	// the process capacity stolen by CPU steal time, calculated with our secret sauce algorithms
	float m_stolen_capacity_score;
	// the process CPU load
	double m_cpuload;
	// total virtual memory
	uint32_t m_vmsize_kb;
	// resident non-swapped memory
	uint32_t m_vmrss_kb;
	// swapped memory
	uint32_t m_vmswap_kb;
	// number of major page faults since start
	uint64_t m_pfmajor;
	// number of minor page faults since start
	uint64_t m_pfminor;
	// list of processes that are part of this program
	std::set<int64_t> m_program_pids;
	std::set<int64_t> m_program_uids;
	// Number of child threads or processes that served transactions
	uint64_t m_n_transaction_threads;
	// The metrics for transaction coming from the external world
	sinsp_transaction_counters m_external_transaction_metrics;
	// State for delay computation
	sinsp_delays_info m_transaction_delays;
	// Time spent by this process on each of the CPUs
	std::vector<uint64_t> m_cpu_time_ns;
	// Syscall error table
	sinsp_error_counters m_syscall_errors;
	// Completed transactions lists
	std::vector<std::vector<sinsp_trlist_entry>> m_server_transactions_per_cpu;
	std::vector<std::vector<sinsp_trlist_entry>> m_client_transactions_per_cpu;
	// The protocol state
	sinsp_protostate m_protostate;
	// Number of FDs
	uint32_t m_fd_count;
	uint64_t m_start_count = 0;
	// number of process instances
	int m_proc_count = 0;
	unsigned m_threads_count = 0;
	// Per-process file I/O stats
	analyzer_top_file_stat_map m_files_stat;
	analyzer_top_device_stat_map m_devs_stat;
};

class proc_config;

// Holds state allocated only per main_thread
struct main_thread_analyzer_info
{
	sinsp_protostate m_protostate;
	std::vector<std::vector<sinsp_trlist_entry>> m_server_transactions_per_cpu;
	std::vector<std::vector<sinsp_trlist_entry>> m_client_transactions_per_cpu;

	// hash of all environment variables
	env_hash m_env_hash;

	// per-file and per-device I/O stats for this process
	analyzer_top_file_stat_map m_files_stat;
	analyzer_top_device_stat_map m_devs_stat;

	void hash_environment(THREAD_TYPE* tinfo, const env_hash::regex_list_t& blacklist);
};

///////////////////////////////////////////////////////////////////////////////
// Thread-related analyzer state
// WARNING: This class is allocated with `placement new`, so destructor must be
//          called manually.
///////////////////////////////////////////////////////////////////////////////
#ifdef USE_AGENT_THREAD
class thread_analyzer_info : public sinsp_threadinfo
#else
class thread_analyzer_info
#endif
{
public:
	//
	// thread flags
	//
	// clang-format off
	enum flags
	{
		AF_NONE = 0,
		AF_INVALID = (1 << 0),
		AF_PARTIAL_METRIC = (1 << 1),  // Used by the event analyzer to flag that part of the last event has already been measured because the sampling time elapsed
		AF_IS_LOCAL_IPV4_SERVER = (1 << 2), // set if this thread serves IPv4 transactions coming from the same machine.
		AF_IS_REMOTE_IPV4_SERVER = (1 << 3), // set if this thread serves IPv4 transactions coming from another machine.
		AF_IS_UNIX_SERVER = (1 << 4), // set if this thread serves unix transactions.
		AF_IS_LOCAL_IPV4_CLIENT = (1 << 5), // set if this thread creates IPv4 transactions toward localhost.
		AF_IS_REMOTE_IPV4_CLIENT = (1 << 6), // set if this thread creates IPv4 transactions toward another host.
		AF_IS_UNIX_CLIENT = (1 << 7), // set if this thread creates unix transactions.
		AF_IS_MAIN_PROGRAM_THREAD = (1 << 8),  // set for main program threads.
		AF_APP_CHECK_FOUND = (1 << 9),
		AF_IS_DESCENDENT_OF_SHELL = (1 << 10),  // Set if there is a shell (bash, tcsh...) among the ancestors of this thread
		AF_IS_NOT_DESCENDENT_OF_SHELL = (1 << 11),  // Set if there is NOT a shell (bash, tcsh...) among the ancestors of this thread. This means that the ancestors have been navigated with negative result.
		AF_IS_NET_CLIENT = (1 << 12),  // Set if the thread called connect().
		AF_IS_INTERACTIVE_COMMAND = (1 << 13),
		AF_IS_DESCENDANT_OF_CONTAINER_INIT = (1 << 14)
	};
	// clang-format on

	thread_analyzer_info(sinsp* inspector,
	                     sinsp_analyzer* analyzer);
	thread_analyzer_info(sinsp* inspector,
	                     sinsp_analyzer* analyzer,
	                     std::shared_ptr<audit_tap>& audit_tap);
	~thread_analyzer_info();

	thread_analyzer_info(const thread_analyzer_info&) = delete;
	thread_analyzer_info(thread_analyzer_info&&) = delete;
	thread_analyzer_info& operator=(const thread_analyzer_info&) = delete;

#ifdef USE_AGENT_THREAD
	void init();
#else
	void init(sinsp_threadinfo* tinfo);
#endif
	const sinsp_counters* get_metrics();
	void allocate_procinfo_if_not_present();
	void propagate_flag(flags flags, thread_analyzer_info* other);
	void propagate_flag_bidirectional(flags flag, thread_analyzer_info* other);
	void add_all_metrics(thread_analyzer_info* other);
	void clear_all_metrics();
	void clear_role_flags();
	void flush_inactive_transactions(uint64_t sample_end_time,
	                                 uint64_t timeout_ns,
	                                 bool is_subsampling);
	void add_completed_server_transaction(sinsp_partial_transaction* tr, bool isexternal);
	void add_completed_client_transaction(sinsp_partial_transaction* tr, bool isexternal);

	inline bool is_main_program_thread()
	{
		return (m_th_analysis_flags & AF_IS_MAIN_PROGRAM_THREAD) != 0;
	}

	inline void set_main_program_thread(bool is_main_program_thread)
	{
		if (is_main_program_thread)
		{
			m_th_analysis_flags |= AF_IS_MAIN_PROGRAM_THREAD;
		}
		else
		{
			m_th_analysis_flags &= ~AF_IS_MAIN_PROGRAM_THREAD;
		}
	}

	const proc_config& get_proc_config();

	inline const std::set<uint16_t>& listening_ports() const
	{
		if (!m_listening_ports)
		{
			scan_listening_ports();
		}
		return *m_listening_ports;
	}

	inline bool found_prom_check() const { return m_prom_check_found; }
	inline void set_found_prom_check() { m_prom_check_found = true; }
	inline void clear_found_prom_check() { m_prom_check_found = false; }

	bool found_app_check_by_fnmatch(const std::string& pattern) const;
	inline bool found_app_check_by_name(const std::string& name) const
	{
		return (m_app_checks_found.find(name) != m_app_checks_found.end());
	}
	inline bool found_app_check(const app_check& check) const
	{
		return found_app_check_by_name(check.name());
	}
	inline void set_found_app_check(const app_check& check)
	{
		m_app_checks_found.emplace(check.name());
	}
	inline void clear_found_app_checks() { m_app_checks_found.clear(); }

	// Global state
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	std::shared_ptr<audit_tap> m_tap;
#ifndef USE_AGENT_THREAD
	sinsp_threadinfo* m_tinfo;
#endif
	int64_t m_main_thread_pid;

	// Flags word used by the analysis engine.
	uint16_t m_th_analysis_flags;
	// The analyzer metrics
	sinsp_counters m_metrics;
	// The transaction metrics
	sinsp_transaction_counters m_transaction_metrics;
	// The metrics for transaction coming from the external world
	sinsp_transaction_counters m_external_transaction_metrics;
	// Process-specific information
	sinsp_procinfo* m_procinfo = nullptr;
	// The ratio between the number of connections waiting to be served and
	// the total connection queue length for this process.
	uint32_t m_connection_queue_usage_pct;
	// This is used for CPU load calculation
	uint64_t m_old_proc_jiffies;
	// the process CPU load
	double m_cpuload;
	// number of major page at last flush
	uint64_t m_old_pfmajor;
	// number of minor page at last flush
	uint64_t m_old_pfminor;
	// Time and duration of the last select, poll or epoll
	uint64_t m_last_wait_end_time_ns;
	int64_t m_last_wait_duration_ns;

	// Time spent by this process on each of the CPUs
	std::vector<uint64_t> m_cpu_time_ns;
	// Syscall error table
	sinsp_error_counters m_syscall_errors;
	// Completed transactions lists
	std::unique_ptr<proc_config> m_proc_config;

	bool m_called_execve;
	uint64_t m_last_cmdline_sync_ns;
	std::set<double> m_percentiles;
	// Used just by nodriver mode
	sinsp_proc_file_stats m_file_io_stats;
	bool m_root_refreshed;

	main_thread_analyzer_info* main_thread_ainfo()
	{
#ifdef USE_AGENT_THREAD
		THREAD_TYPE* main_thread = get_main_thread_info();
		if (main_thread != nullptr && this != main_thread)
#else
		THREAD_TYPE* main_thread = m_tinfo->get_main_thread();
		if (main_thread != nullptr && m_tinfo != main_thread)
#endif
		{
			return GET_AGENT_THREAD(main_thread)->main_thread_ainfo();
		}
		else
		{
			if (!m_main_thread_ainfo)
			{
				m_main_thread_ainfo = make_unique<main_thread_analyzer_info>();
				m_main_thread_ainfo->m_server_transactions_per_cpu.resize(
				    m_inspector->get_machine_info()->num_cpus);
				m_main_thread_ainfo->m_client_transactions_per_cpu.resize(
				    m_inspector->get_machine_info()->num_cpus);
				if (!m_percentiles.empty())
				{
					m_main_thread_ainfo->m_protostate.set_percentiles(m_percentiles);
				}
			}
			return m_main_thread_ainfo.get();
		}
	}

	void scan_listening_ports(
	    bool add_procfs_scan = false,
	    uint32_t procfs_scan_interval = DEFAULT_PROCFS_SCAN_INTERVAL_SECS) const;

	inline void set_exclude_from_sample(bool val) { m_procinfo->m_exclude_from_sample = val; }

	inline bool get_exclude_from_sample() const { return m_procinfo->m_exclude_from_sample; }

	inline THREAD_TYPE* get_main_thread_info()
	{
#ifdef USE_AGENT_THREAD
		sinsp_threadinfo* sinsp_main_thread = get_main_thread();
		thread_analyzer_info* analyzer_main_thread =
		    dynamic_cast<thread_analyzer_info*>(sinsp_main_thread);
		ASSERT(sinsp_main_thread == analyzer_main_thread);
		return analyzer_main_thread;
#else
		return m_tinfo->get_main_thread();
#endif
	}

	inline THREAD_TYPE* get_parent_thread_info()
	{
#ifdef USE_AGENT_THREAD
		sinsp_threadinfo* sinsp_thread = get_parent_thread();
		thread_analyzer_info* analyzer_thread = dynamic_cast<thread_analyzer_info*>(sinsp_thread);
		ASSERT(sinsp_thread == analyzer_thread);
		return analyzer_thread;
#else
		return m_tinfo->get_parent_thread();
#endif
	}

	static inline THREAD_TYPE* get_thread_from_event(sinsp_evt* evt)
	{
#ifdef USE_AGENT_THREAD
		thread_analyzer_info* analyzer_thread =
		    dynamic_cast<thread_analyzer_info*>(evt->get_thread_info());
		ASSERT(evt->get_thread_info() == analyzer_thread);
		return analyzer_thread;
#else
		return evt->get_thread_info();
#endif
	}

private:
	static const uint32_t RESCAN_PORT_INTERVAL_SECS = 20;
	using time_point_t = std::chrono::time_point<std::chrono::steady_clock>;
	std::unique_ptr<main_thread_analyzer_info> m_main_thread_ainfo;
	mutable std::unique_ptr<std::set<uint16_t>> m_listening_ports;
	mutable std::set<uint16_t> m_procfs_found_ports;
	std::set<std::string> m_app_checks_found;
	bool m_prom_check_found;
	mutable time_point_t m_last_port_scan;
	mutable time_point_t m_last_procfs_port_scan;

	static std::string ports_to_string(const std::set<uint16_t>& ports);

	friend class test_helper;
};

///////////////////////////////////////////////////////////////////////////////
// Thread table changes listener
///////////////////////////////////////////////////////////////////////////////
class audit_tap;

class analyzer_threadtable_listener : public sinsp_threadtable_listener
{
public:
	analyzer_threadtable_listener(sinsp* inspector, sinsp_analyzer& analyzer);
	void on_thread_created(sinsp_threadinfo* tinfo);
	void on_thread_destroyed(sinsp_threadinfo* tinfo);

	void set_audit_tap(const std::shared_ptr<audit_tap>& tap);

private:
	sinsp* m_inspector;
	sinsp_analyzer& m_analyzer;
	std::shared_ptr<audit_tap> m_tap;
};

///////////////////////////////////////////////////////////////////////////////
// Support for thread sorting
///////////////////////////////////////////////////////////////////////////////
bool threadinfo_cmp_cpu(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_memory(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_io(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_net(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_transactions(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_evtcnt(THREAD_TYPE* src, THREAD_TYPE* dst);

bool threadinfo_cmp_cpu_cs(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_memory_cs(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_io_cs(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_net_cs(THREAD_TYPE* src, THREAD_TYPE* dst);
bool threadinfo_cmp_transactions_cs(THREAD_TYPE* src, THREAD_TYPE* dst);
