#pragma once

#include "analyzer_utils.h"
#include "app_checks_proxy_interface.h"
#include "jmx_proxy.h"
#include "prometheus.h"
#include "sinsp_curl.h"
#include "statsite_proxy.h"
#include "user_event.h"

#include <analyzer_int.h>
#include <atomic>
#include <container_analyzer.h>
#include <delays.h>
#include <memory>
#include <set>
#include <string>
#include <tracer_emitter.h>
#include <unordered_map>
#include <unordered_set>
#ifndef CYGWING_AGENT
#include "k8s_api_handler.h"
#endif
#include "mounted_fs.h"
#include "procfs_parser.h"
#ifndef CYGWING_AGENT
#include "coclient.h"
#include "custom_container.h"
#else
#include "Poco/RegularExpression.h"
#endif
#include "analyzer_emitter.h"
#include "analyzer_file_stat.h"
#include "analyzer_flush_message.h"
#include "analyzer_thread.h"
#include "app_check_emitter.h"
#include "audit_tap_handler.h"
#include "baseliner.h"
#include "cpu_profiler.h"
#include "env_hash.h"
#include "environment_emitter.h"
#include "internal_metrics.h"
#include "jmx_emitter.h"
#include "k8s_limits.h"
#include "k8s_user_event_message_handler.h"
#include "label_limits.h"
#include "metric_limits.h"
#include "process_emitter.h"
#include "procfs_scanner.h"
#include "secure_audit_data_ready_handler.h"
#include "secure_audit_handler.h"
#include "secure_audit_internal_metrics.h"
#include "secure_profiling_internal_metrics.h"
#include "statsd_emitter.h"
#include "userdb.h"

#include "include/sinsp_external_processor.h"
#include "thread_safe_container/blocking_queue.h"

#include <nlohmann/json.hpp>

namespace dragent
{
class metric_serializer;
}

class audit_tap;
class secure_audit;

typedef void (*sinsp_analyzer_callback)(char* buffer, uint32_t buflen);

class sinsp_scores;
class mounted_fs;
class sinsp_procfs_parser;
class mounted_fs_proxy;
class sinsp_sched_analyzer2;
class sinsp_delays;
class sinsp_analyzer_fd_listener;
class sinsp_configuration;
class sinsp_counters;
class sinsp_analyzer_parsers;
class sinsp_chisel;
class sinsp_chisel_details;
#ifndef CYGWING_AGENT
class infrastructure_state;
class k8s;
class k8s_delegator;
class mesos;
class new_k8s_delegator;
class docker;
class containerd_events;
#endif
class uri;
class sinsp_baseliner;
class tracer_emitter;
class metric_limits;
class sinsp_ipv4_connection_manager;
class sinsp_connection_aggregator;
class sinsp_container_manager;
class promscrape;

//
// Aggregated connection table: entry and hashing infrastructure
//
typedef union _process_tuple {
	struct
	{
		uint64_t m_spid;
		uint64_t m_dpid;
		uint32_t m_sip;
		uint32_t m_dip;
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l4proto;
		uint8_t m_state;
	} m_fields;
	uint8_t m_all[30];
} process_tuple;

struct process_tuple_hash
{
	size_t operator()(process_tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;
		std::hash<uint32_t> hasher32;
		std::hash<uint16_t> hasher16;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)t.m_all + 8) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)t.m_all + 16) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher32(*(uint32_t*)(t.m_all + 24)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher16(*(uint16_t*)(t.m_all + 28)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct process_tuple_cmp
{
	bool operator()(process_tuple t1, process_tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

//
// Description of an executed command
//
class sinsp_executed_command
{
public:
	enum flags
	{
		FL_NONE = 0,
		FL_PIPE_HEAD = 1,
		FL_PIPE_MIDDLE = 2,
		FL_PIPE_TAIL = 4,
		FL_EXCLUDED = 8,
		FL_EXEONLY = 16,
	};

	sinsp_executed_command()
	{
		m_flags = FL_NONE;
		m_count = 1;
	}

	uint32_t m_flags;
	uint64_t m_ts;
	std::string m_exe;
	uint64_t m_shell_id;              // this is equivalent to the shell ID in spy_users
	uint32_t m_login_shell_distance;  // This is equivalent to the indentation in spy_users
	std::string m_cmdline;
	uint32_t m_count;    // how many times this command has been repeated
	std::string m_comm;  // program executable name
	uint64_t m_pid;      // process pid
	uint64_t m_ppid;     // parent process pid
	uint64_t m_uid;      // user ID
	std::string m_cwd;   // process' current working directory
	uint32_t m_tty;      // tty
	draiosproto::command_category m_category;
};

#ifndef _WIN32
class self_cputime_analyzer
{
public:
	self_cputime_analyzer() : m_index(0), m_previouscputime(0)
	{
		m_flushtime.fill(0);
		m_othertime.fill(0);
	}

	void begin_flush();
	void end_flush();
	double calc_flush_percent();

private:
	static const auto LAST_SAMPLES = 10U;

	uint64_t read_cputime();
	void incr_index() { m_index = (m_index + 1) % LAST_SAMPLES; }

	std::array<uint64_t, LAST_SAMPLES> m_flushtime;
	std::array<uint64_t, LAST_SAMPLES> m_othertime;
	unsigned m_index;
	uint64_t m_previouscputime;
};
#endif  // _WIN32

class stress_tool_matcher
{
public:
	stress_tool_matcher()
	{
		// m_comm_list.push_back("dd");
		//
		// XXX Populate this with the list of stress tools to match
		//
	}

	bool match(std::string comm)
	{
		for (auto it = m_comm_list.begin(); it != m_comm_list.end(); ++it)
		{
			if (*it == comm)
			{
				return true;
			}
		}

		return false;
	}

	static void set_comm_list(const std::vector<std::string>& comms);

private:
	static std::vector<std::string> m_comm_list;
};

// An abstract interface representing an object that can receive json k8s audit events.
class secure_k8s_audit_event_sink_iface {
public:
	virtual void receive_k8s_audit_event(
		const nlohmann::json& j,
		std::vector<std::string>& k8s_active_filters,
		std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters) = 0;
};

//
// The main analyzer class
//
class SINSP_PUBLIC sinsp_analyzer : public secure_profiling_internal_metrics,
                                    public secure_profiling_data_ready_handler,
                                    public secure_audit_internal_metrics,
                                    public secure_audit_data_ready_handler,
                                    public libsinsp::event_processor,
                                    public secure_k8s_audit_event_sink_iface
{
public:
	typedef thread_safe_container::blocking_queue<std::shared_ptr<flush_data_message>> flush_queue;
	enum mode_switch_state
	{
		MSR_NONE = 0,
		MSR_SWITCHED_TO_NODRIVER = 1,
		MSR_REQUEST_NODRIVER = 2,
		MSR_REQUEST_REGULAR = 3,
	};

	// only use default root_dir if you don't need coclient
	// (it needs root_dir properly set to locate the cointerface server socket)
	sinsp_analyzer(sinsp* inspector,
	               std::string root_dir,
	               const internal_metrics::sptr_t& internal_metrics,
	               audit_tap_handler& tap_handler,
	               secure_audit_handler& secure_audit_handler,
	               secure_profiling_handler& secure_profiling_handler,
	               flush_queue* flush_queue,
	               std::function<bool()> check_disable_dropping,
	               const metric_limits::sptr_t& the_metric_limits = nullptr,
	               const label_limits::sptr_t& the_label_limits = nullptr,
	               const k8s_limits::sptr_t& the_k8s_limits = nullptr,
	               std::shared_ptr<app_checks_proxy_interface> the_app_checks_proxy = nullptr,
	               std::shared_ptr<promscrape> promscrape = nullptr);
	~sinsp_analyzer();

	//
	// Called by the engine after opening the event source and before
	// receiving the first event. Can be used to make adjustments based on
	// the user's changes to the configuration.
	//
	void on_capture_start();

	//
	// Get and set the library configuration settings
	//
	sinsp_configuration* get_configuration();
	const sinsp_configuration* get_configuration_read_only();
	void set_configuration(const sinsp_configuration& configuration);

	//
	// Chisel helpers
	//
	void add_chisel_dirs();
	void initialize_chisels();
	void add_chisel(sinsp_chisel* ch);
	void add_chisel(sinsp_chisel_details* cd);
	inline void add_chisel_metric(statsd_metric* metric) { m_chisel_metrics.push_back(*metric); }

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt, libsinsp::event_return rc);

	void add_syscall_time(sinsp_counters* metrics,
	                      const sinsp_evt::category* cat,
	                      uint64_t delta,
	                      uint32_t bytes,
	                      bool inc_count);

	uint64_t get_last_sample_time_ns() { return m_next_flush_time_ns; }

	//
	// Connection lookup
	//
	sinsp_connection* get_connection(const ipv4tuple& tuple, uint64_t timestamp);
	void remove_expired_connections(uint64_t ts);

#ifdef GATHER_INTERNAL_STATS
	//
	// Get processing stats
	//
	sinsp_stats get_stats();
#endif  // GATHER_INTERNAL_STATS

	//
	// The library configuration manager
	//
	sinsp_configuration* m_configuration;

	//
	// Fills the given buffer with a string contaning the memory usage report.
	// Returns the size of the string, or -1 if the given buffer is too small.
	//
	int32_t generate_memory_report(OUT char* reportbuf,
	                               uint32_t reportbuflen,
	                               bool do_complete_report = false);

	void set_capture_in_progress(bool in_progress) { m_capture_in_progress = in_progress; }

#ifndef _WIN32
	inline void enable_jmx(bool print_json, unsigned sampling)
	{
		m_jmx_proxy = make_unique<jmx_proxy>();
		m_jmx_proxy->m_print_json = print_json;
		m_jmx_sampling = sampling;
	}

	void set_statsd_iofds(const std::pair<FILE*, FILE*>& iofds, bool forwarder);
#endif

	void set_protocols_enabled(bool value) { m_protocols_enabled = value; }

	void set_procfs_scan_thread(bool value) { m_procfs_scan_thread = value; }

	void set_remotefs_enabled(bool value) { m_remotefs_enabled = value; }

	uint64_t get_acked_sampling_ratio() const { return m_acked_sampling_ratio; }

	uint64_t get_sample_duration() const;

	// the ack of the sampling ratio change happens via an event picked up
	// by the analyzer parser, who sets this
	void ack_sampling_ratio(uint64_t value) { m_acked_sampling_ratio = value; }

	void set_statsd_capture_localhost(bool value)
	{
#ifndef _WIN32
		m_statsd_capture_localhost.store(value, std::memory_order_relaxed);
#endif
	}

#ifndef _WIN32
	void set_app_checks(const std::vector<app_check>& checks)
	{
		std::unordered_set<std::string> check_unique_names;
		m_app_checks.clear();
		for (const auto& c : checks)
		{
			auto res = check_unique_names.emplace(c.name());
			if (res.second)
			{
				// This means there wasn't already a check like this
				m_app_checks.push_back(c);
			}
		}
	}

#ifndef CYGWING_AGENT
	void set_prometheus_conf(const prometheus_conf& pconf) { m_prom_conf = pconf; }

	void set_custom_container_conf(custom_container::resolver&& conf)
	{
		std::swap(m_custom_container, conf);
	}
#endif
#endif  // _WIN32

	inline const thread_analyzer_info* get_agent_thread()
	{
		return get_thread_by_pid(m_inspector->m_sysdig_pid);
	}

	inline thread_analyzer_info* get_thread_by_pid(uint64_t pid)
	{
		sinsp_threadinfo* sinsp_thread = m_inspector->m_thread_manager->m_threadtable.get(pid);
		thread_analyzer_info* analyzer_thread = dynamic_cast<thread_analyzer_info*>(sinsp_thread);
		ASSERT(sinsp_thread == analyzer_thread);
		return analyzer_thread;
	}

	inline const thread_analyzer_info* get_thread_by_pid(uint64_t tid,
	                                            bool query_os_if_not_found,
	                                            bool lookup_only)
	{
		sinsp_threadinfo* sinsp_thread =
		    m_inspector->get_thread(tid, query_os_if_not_found, lookup_only);
		thread_analyzer_info* analyzer_thread = dynamic_cast<thread_analyzer_info*>(sinsp_thread);
		ASSERT(sinsp_thread == analyzer_thread);
		return analyzer_thread;
	}

	inline thread_analyzer_info* get_mutable_thread_by_pid(uint64_t tid,
	                                              bool query_os_if_not_found,
	                                              bool lookup_only)
	{
		sinsp_threadinfo* sinsp_thread =
		    m_inspector->get_thread(tid, query_os_if_not_found, lookup_only);
		thread_analyzer_info* analyzer_thread = dynamic_cast<thread_analyzer_info*>(sinsp_thread);
		ASSERT(sinsp_thread == analyzer_thread);
		return analyzer_thread;
	}

	inline std::shared_ptr<thread_analyzer_info> get_thread_ref(int64_t tid,
	                                                   bool query_os_if_not_found,
	                                                   bool lookup_only,
	                                                   bool main_thread = false)
	{
		return sinsp_analyzer::get_thread_ref(*m_inspector,
		                                      tid,
		                                      query_os_if_not_found,
		                                      lookup_only,
		                                      main_thread);
	}

	static inline std::shared_ptr<thread_analyzer_info> get_thread_ref(sinsp& inspector,
	                                                          int64_t tid,
	                                                          bool query_os_if_not_found,
	                                                          bool lookup_only,
	                                                          bool main_thread = false)
	{
		auto sinsp_thread =
		    inspector.get_thread_ref(tid, query_os_if_not_found, lookup_only, main_thread);
		auto analyzer_thread = std::dynamic_pointer_cast<thread_analyzer_info>(sinsp_thread);
		ASSERT(sinsp_thread == analyzer_thread);
		return analyzer_thread;
	}
	inline sinsp_container_info::ptr_t get_container(const std::string& container_id)
	{
		return m_inspector->m_container_manager.get_container(container_id);
	}

	void set_containers_limit(const uint32_t value)
	{
		m_containers_limit = std::min(value, CONTAINERS_HARD_LIMIT);
	}

	void set_container_patterns(const std::vector<std::string>& patterns)
	{
		m_container_patterns = patterns;
	}

	void set_containers_labels_max_len(const uint32_t len) { m_containers_labels_max_len = len; }

	void set_fs_usage_from_external_proc(bool value);

	void set_user_event_queue(user_event_queue::ptr_t user_event_queue)
	{
		m_user_event_queue = user_event_queue;

		if (m_k8s_user_event_handler)
		{
			m_k8s_user_event_handler->set_user_event_queue(user_event_queue);
		}
	}

	void init_k8s_user_event_handler();

	void set_simpledriver_mode() { m_simpledriver_enabled = true; }

	void set_track_connection_status(bool value)
	{
		m_inspector->m_parser->m_track_connection_status = value;
	}

	void set_emit_tracers(bool enabled);

	void set_percentiles();
	void emit_percentiles_config();

#ifndef CYGWING_AGENT

	/**
	 * Access to the infrastructure_state class which manages 
	 * kubernetes state. 
	 */
	const infrastructure_state* infra_state() const;

	/**
	 * Writable access to the infrastructure_state class which 
	 * manages kubernetes state. This is purposely named different 
	 * than the const access so that mutable acess can be audited 
	 * more easily. 
	 */
	infrastructure_state* mutable_infra_state();

	void set_use_new_k8s(bool v) { m_use_new_k8s = v; }

	void set_k8s_local_update_frequency(uint16_t value) { m_k8s_local_update_frequency = value; }

	void set_k8s_cluster_update_frequency(uint16_t value)
	{
		m_k8s_cluster_update_frequency = value;
	}

	void set_coclient_max_loop_evts(const uint32_t max_evts)
	{
		coclient::set_max_loop_evts(max_evts);
	}
#endif

	bool recent_sinsp_events_dropped()
	{
		return ((m_internal_metrics->get_n_drops() + m_internal_metrics->get_n_drops_buffer()) > 0);
	}

	void dump_config_test()
	{
#ifndef CYGWING_AGENT
		m_custom_container.dump_container_table();
#endif
	}

	void set_flush_log_time(uint64_t flush_log_ns) { m_flush_log_time = flush_log_ns; }

	void set_flush_log_time_duration(uint64_t flush_log_duration_ns)
	{
		m_flush_log_time_duration = flush_log_duration_ns;
	}

	void set_flush_log_time_cooldown(uint64_t flush_log_cooldown_ns)
	{
		m_flush_log_time_cooldown = flush_log_cooldown_ns;
	}

	void set_username_lookups(bool enabled) { m_username_lookups = enabled; }

	void set_top_files(int per_prog, int per_container, int per_host)
	{
		m_top_files_per_prog = per_prog;
		m_top_files_per_container = per_container;
		m_top_files_per_host = per_host;
	}

	void set_top_devices(int per_prog, int per_container, int per_host)
	{
		m_top_file_devices_per_prog = per_prog;
		m_top_file_devices_per_container = per_container;
		m_top_file_devices_per_host = per_host;
	}

	inline bool detailed_fileio_reporting() const
	{
		return m_top_files_per_prog > 0 || m_top_files_per_container > 0;
	}

	inline bool fileio_device_reporting() const { return m_top_file_devices_per_host > 0; }

	inline bool detailed_fileio_device_reporting() const
	{
		return m_top_file_devices_per_prog > 0 || m_top_file_devices_per_container > 0;
	}

	void rearm_tracer_logging();
	inline uint64_t flush_tracer_timeout();

	void set_max_n_external_clients(uint32_t val) { m_max_n_external_clients = val; }
	void set_top_connections_in_sample(uint32_t val) { m_top_connections_in_sample = val; }
	void set_top_processes_in_sample(uint32_t val) { m_top_processes_in_sample = val; }
	void set_top_processes_per_container(uint32_t val) { m_top_processes_per_container = val; }
	void set_report_source_port(bool val) { m_report_source_port = val; }
	void set_url_groups(const std::set<std::string>& groups)
	{
		sinsp_protostate::set_url_groups(groups);
	}
	void set_connection_truncate_report_interval(int sec)
	{
		m_connection_truncate_report_interval = sec;
	}
	void set_connection_truncate_log_interval(int sec) { m_connection_truncate_log_interval = sec; }

	void set_track_environment(bool val) { m_track_environment = val; }
	bool is_tracking_environment() const { return m_track_environment; }

	void set_envs_per_flush(uint32_t val) { m_env_hash_config.m_envs_per_flush = val; }
	void set_max_env_size(size_t val) { m_env_hash_config.m_max_env_size = val; }
	void set_env_blacklist(std::unique_ptr<env_hash::regex_list_t>&& blacklist)
	{
		m_env_hash_config.m_env_blacklist = std::move(blacklist);
	}
	void set_env_hash_ttl(uint64_t secs);
	void set_env_emit(bool metrics, bool audit_tap)
	{
		m_env_hash_config.m_send_metrics = metrics;
		m_env_hash_config.m_send_audit_tap = audit_tap;
	}

	void enable_audit_tap();
	bool audit_tap_enabled() const { return m_tap != nullptr; }
	bool audit_tap_track_pending() const { return m_tap_track_pending; }

	void enable_secure_audit();
	bool secure_audit_enabled() const { return m_secure_audit != nullptr; }

	void secure_audit_data_ready(uint64_t ts, const secure::Audit* secure_audits) override;
	void set_secure_audit_internal_metrics(int n_sent_protobufs, uint64_t flush_time_ms) override;

	void set_secure_audit_sent_counters(int n_executed_commands,
	                                    int n_connections,
	                                    int n_k8s,
	                                    int n_file_accesses,
	                                    int n_executed_commands_dropped,
	                                    int n_connections_dropped,
	                                    int n_k8s_dropped,
	                                    int n_file_accesses_dropped,
	                                    int n_connections_not_interactive_dropped,
	                                    int n_file_accesses_not_interactive_dropped,
	                                    int n_k8s_enrich_errors) override;

	// Just calls next function
	void receive_k8s_audit_event(
	   const nlohmann::json& j,
	   std::vector<std::string>& k8s_active_filters,
	   std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters) override;

	void secure_audit_filter_and_append_k8s_audit(
	    const nlohmann::json& j,
	    std::vector<std::string>& k8s_active_filters,
	    std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters);

	void enable_secure_profiling();
	bool secure_profiling_enabled() const { return m_falco_baseliner != nullptr; }
	void set_secure_profiling_internal_metrics(int n_sent_protobufs, uint64_t flush_time_ms) override;

	/**
	 * Dump the infrastructure state to a file in the log directory.
	 */
	void dump_infrastructure_state_on_next_flush();

	void incr_command_lines_category(draiosproto::command_category cat, uint64_t delta = 1);

	/**
	 * Return true if the agent should terminate because something has
	 * gone wrong in the analyzer, false otherwise.
	 */
	bool should_terminate() const;

	/**
	 * Returns the current number of server programs.
	 */
	size_t num_server_programs() const;

	/**
	 * Returns true if the analyzer has CPU idle information, false
	 * otherwise.
	 */
	bool has_cpu_idle_data() const;

	/**
	 * Returns the CPU idle data for the given cpuid.
	 * Precondition: has_idle_cpu_data() returns true.
	 */
	double get_cpu_idle_data(size_t cpuid) const;

	/**
	 * Returns true if this analyzer has CPU steal information, false
	 * otherwise.
	 */
	bool has_cpu_steal_data() const;

	/**
	 * Returns the CPU steal data for the given cpuid.
	 * Precondition: has_idle_cpu_data() returns true.
	 */
	double get_cpu_steal_data(size_t cpuid) const;

	/**
	 * Returns true if this analyzer has CPU load information, false
	 * otherwise.
	 */
	bool has_cpu_load_data() const;

	/**
	 * Returns the CPU load data for the given cpuid.
	 * Precondition: has_idle_cpu_data() returns true.
	 */
	double get_cpu_load_data(size_t cpuid) const;

	/**
	 * Returns the environment blacklist.
	 * Precondition: get_track_environment() returns true.
	 */
	const env_hash::regex_list_t& get_environment_blacklist() const;

	/**
	 * Find the name of the Java process with the given pid.
	 *
	 * @param[in] pid   The ID of the process.
	 * @param[out] name The name of the process.
	 *
	 * @returns true if a Java process with the given pid was found,
	 *          false otherwise.
	 */
	bool find_java_process_name(int pid, std::string& name) const;

	/**
	 * Return the thread memory ID.
	 */
	uint32_t get_thread_memory_id() const;

	/**
	 * Return the number of IPv4 connections that were dropped because
	 * the ipv4_connection_manager didn't have room in the connection
	 * table.
	 */
	uint32_t get_num_dropped_ipv4_connections() const;

	/**
	 * Inject a statsd metric into statsite.  If the given tinfo is non-
	 * nullptr, and if it has a container id associated with it, then
	 * inject both a container metric and a host metric; otherwise
	 * inject only the host metric.  If this sinsp_analyzer doesn't
	 * currently have a statsite_proxy, then this method does nothing.
	 *
	 * @param[in] container_id    The ID of the container, or the empty
	 *                            string if there is no container id.
	 * @param[in] dest_is_ipv4_localhost true if the destination is
	 *                            127.0.0.1, false otherwise.
	 * @param[in] data            The stat
	 * @param[in] len             The length of data
	 */
	void inject_statsd_metric(const std::string& container_id,
	                          bool dest_is_ipv4_localhost,
	                          const char* data,
	                          uint32_t len);

	/**
	 * Attempts to resolve a custom container.
	 */
	bool resolve_custom_container(sinsp_container_manager* manager,
	                              thread_analyzer_info* tinfo,
	                              bool query_os_for_missing_info);

	/**
	 * Remove the IPv4 connection associated with the given ipv4info.
	 */
	void remove_ipv4_connection(const ipv4tuple& ipv4info);

	/**
	 * Return the current size of the thread table.
	 */
	uint32_t get_thread_count() const;

	/**
	 * Enable or disable simulated drop mode.
	 */
	void simulate_drop_mode(bool enabled);

	/**
	 * If the agent is configured to detect stress tool, then determine
	 * if the given command is a stress tool.  If so, and if we're not
	 * in NODRIVER mode, switch to NODRIVER mode.
	 *
	 * @param[in] command The command that might be the name of a stress
	 *                    tool.
	 * @returns true if a stress tool was detected, false otherwise.
	 */
	bool detect_and_match_stress_tool(const std::string& command);

	/**
	 * Add the given command to the set of commands that have been
	 * executed by the given container_id.
	 */
	void add_executed_command(const std::string& container_id,
	                          const sinsp_executed_command& command);

	/**
	 * Set the last dropmode switch time to the given time.
	 */
	void set_last_dropmode_switch_time(uint64_t last_dropmode_switch_time);

	void flush(sinsp_evt* evt, uint64_t ts, bool is_eof, analyzer_emitter::flush_flags flushflags);

	/**
	 * Returns the current mode switch state.
	 */
	mode_switch_state get_mode_switch_state() const;

	/**
	 * Sets the current mode switch state to the given state.
	 */
	void set_mode_switch_state(mode_switch_state state);

	/**
	 * Returns the previous flush time in nanoseconds.
	 */
	uint64_t get_prev_flush_time_ns() const;

	/**
	 * Returns true if the analyzer has a statsite proxy, false otherwise.
	 */
	bool has_statsite_proxy() const;

	/**
	 * Notifies statsite_fowarder of the current list of containers
	 * (if statsite_fowarder is enabled); otherwise does nothing.
	 */
	static void send_containers_to_statsite_fowarder(
	    sinsp_analyzer& m_analyzer,
	    const std::vector<std::string>& containers,
	    const analyzer_emitter::progtable_by_container_t& progtable_by_container);

	/**
	 * The container_emitter class is responsible for sorting and deciding
	 * which containers to emit. It makes callbacks to this when it has one
	 * that needs to be reported.
	 *
	 * emit_container is called when a container is to be emitted.
	 */
	void emit_container(const std::string& container_id,
	                    unsigned* statsd_limit,
	                    uint64_t total_cpu_shares,
	                    thread_analyzer_info* tinfo,
	                    analyzer_emitter::flush_flags flushflags,
	                    const std::list<uint32_t>& groups);

	/**
	 * coalesce all stats from containers which weren't emitted into the proper
	 * protobuf
	 */
	void coalesce_unemitted_stats(const std::vector<std::string>& emitted_containers);

	/**
	 * Accessor for metrics
	 */
	const draiosproto::metrics* metrics() const { return m_metrics.get(); }

	/**
	 * Sets the metrics dir for serializing to a file
	 */
	void set_metrics_dir(const std::string& metrics_dir);

	/**
	 * Gets the metrics dir for serializing to a file
	 */
	std::string get_metrics_dir();

	/**
	 * allows us to allocate agent flavor of threadinfo instead of sinsp version
	 */
	sinsp_threadinfo* build_threadinfo(sinsp* inspector) override;

	/**
	 * @brief set up the CPU profiler
	 * Called after construction, once we have all the configuration
	 * initialized
	 */
	void init_cpu_profiler();

	VISIBILITY_PRIVATE
	typedef bool (sinsp_analyzer::*server_check_func_t)(std::string&);

	//
	// Test tool detection state
	//
	mode_switch_state m_mode_switch_state;
	stress_tool_matcher m_stress_tool_matcher;

	void chisels_on_capture_start();
	void chisels_on_capture_end();
	void chisels_do_timeout(sinsp_evt* ev);
	template<class Iterator>
	void filter_top_programs_normaldriver_deprecated(Iterator progtable_begin,
	                                                 Iterator progtable_end,
	                                                 bool cs_only,
	                                                 uint32_t howmany);
	template<class Iterator>
	void filter_top_programs_simpledriver_deprecated(Iterator progtable_begin,
	                                                 Iterator progtable_end,
	                                                 bool cs_only,
	                                                 uint32_t howmany);
	template<class Iterator>
	inline void filter_top_programs_deprecated(Iterator progtable_begin,
	                                           Iterator progtable_end,
	                                           bool cs_only,
	                                           uint32_t howmany);

	/**
	 * emit most things. This function is largely misnamed as it emits far more than
	 * just processes
	 */
	void emit_processes(sinsp_evt* evt,
	                    uint64_t sample_duration,
	                    bool is_eof,
	                    analyzer_emitter::flush_flags flushflags,
	                    const tracer_emitter& f_trc);

	/**
	 * Iterate through the process list and generate the programs, 
	 * java processes and other lists for which we want to emit 
	 * data. 
	 */  
	bool aggregate_processes_into_programs(sinsp_threadinfo& sinsp_tinfo,
					       const sinsp_evt* evt,
					       const uint64_t sample_duration,
					       const analyzer_emitter::flush_flags flushflags,
					       analyzer_emitter::progtable_t &progtable,
					       analyzer_emitter::progtable_by_container_t &progtable_by_container,
					       vector<thread_analyzer_info*> &java_process_requests,
					       vector<app_process> &app_checks_processes,
					       vector<prom_process> &prom_procs,
					       uint64_t &process_count,
					       bool &can_disable_nodriver);

	/**
	 * emit process data. This function emits data scoped to processes. It is
	 * deprecated as it is to be replaced by the process_emitter class
	 */
	void emit_processes_deprecated(
	    std::set<uint64_t>& all_uids,
	    analyzer_emitter::flush_flags flushflags,
	    const analyzer_emitter::progtable_t& progtable,
	    const analyzer_emitter::progtable_by_container_t& progtable_by_container,
	    const std::vector<std::string>& emitted_containers,
	    tracer_emitter& proc_trc,
	    jmx_emitter& jmx_emitter_instance,
	    environment_emitter& environment_emitter_instance,
	    process_emitter& process_emitter_instance);
	void flush_processes();
	void emit_aggregated_connections();
	void emit_full_connections();
	template<typename T>
	void emit_connection(T& conn,
	                     draiosproto::connection_state& conn_state,
	                     std::pair<const _process_tuple, sinsp_connection>& acit);
	template<typename T>
	void emit_full_connection(T& conn,
	                          draiosproto::connection_state& conn_state,
	                          std::pair<const _ipv4tuple, sinsp_connection>& cit);
	std::string detect_local_server(const std::string& protocol,
	                                uint32_t port,
	                                server_check_func_t check_func);
	void log_timed_error(time_t& last_attempt, const std::string& err);
#ifndef CYGWING_AGENT
	typedef sinsp_configuration::k8s_ext_list_t k8s_ext_list_t;
	typedef sinsp_configuration::k8s_ext_list_ptr_t k8s_ext_list_ptr_t;
	bool check_k8s_delegation();
	bool check_k8s_delegation_impl();
	k8s_ext_list_ptr_t k8s_discover_ext(const std::string& addr);
	void init_k8s_ssl(const uri& url);
	k8s* get_k8s(const uri& k8s_api, const std::string& msg);
	void collect_k8s(const std::string& k8s_api);
	void get_k8s_data();
	void emit_k8s();
	void reset_k8s(time_t& last_attempt, const std::string& err);
	// Return the cluster name that must be set
	// for the orch state. This is what will be
	// displayed on the front end.
	std::string get_k8s_cluster_name();
	// Append the cluster name as a "cluster:$NAME" tag
	// if no "cluster:*" tag is already configured
	std::string get_host_tags_with_cluster();
	uint32_t get_mesos_api_server_port(thread_analyzer_info* main_tinfo);
#endif
	thread_analyzer_info* get_main_thread_info(int64_t& tid) const;
	std::string& detect_mesos(std::string& mesos_api_server, uint32_t port);
	std::string detect_mesos(thread_analyzer_info* main_tinfo = 0);
	bool check_mesos_server(std::string& addr);
	void make_mesos(std::string&& json);
	void get_mesos(const std::string& mesos_uri);
	void get_mesos_data();
	void emit_mesos();
	void reset_mesos(const std::string& errmsg = "");
	void emit_docker_events();
	void emit_containerd_events();

	void secure_profiling_data_ready(
	    uint64_t ts,
	    const secure::profiling::fingerprint* secure_profiling_fingerprints) override;
	void emit_baseline(sinsp_evt* evt, bool is_eof, const tracer_emitter& f_trc);

	// set m_my_cpuload to the main thread's cpu usage in percent (100 == one whole cpu)
	// calculated since the previous call to this method
	void calculate_analyzer_cpu_usage();

	void update_percentile_data_serialization(const analyzer_emitter::progtable_by_container_t&);
	void gather_k8s_infrastructure_state(uint32_t flushflags,
	                                     const std::vector<std::string>& emitted_containers);
	void clean_containers(const analyzer_emitter::progtable_by_container_t&);

	template<class S>
	void check_dump_infrastructure_state(const S& state,
	                                     const std::string& descriptor,
	                                     bool& should_dump);

	// deprecated in favor of smart container filtering
	std::vector<std::string> emit_containers_deprecated(
	    const analyzer_emitter::progtable_by_container_t& active_containers,
	    analyzer_emitter::flush_flags flushflags);

	void adjust_sampling_ratio();
	void add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat);
	void emit_executed_commands(draiosproto::metrics* host_dest,
	                            draiosproto::container* container_dest,
	                            std::vector<sinsp_executed_command>* commands);

#ifndef _WIN32
	bool is_jmx_flushtime()
	{
		return (m_prev_flush_time_ns / ONE_SECOND_IN_NS) % m_jmx_sampling == 0;
	}
#endif
	void emit_chisel_metrics();
	void emit_user_events();
	void match_prom_checks(const thread_analyzer_info* tinfo,
	                       thread_analyzer_info* mtinfo,
	                       std::vector<prom_process>& prom_procs,
	                       bool use_host_filter);
	void match_checks_list(thread_analyzer_info* tinfo,
	                       thread_analyzer_info* mtinfo,
	                       const std::vector<app_check>& checks,
	                       std::vector<app_process>& app_checks_processes,
	                       const char* location);
	std::vector<long> get_n_tracepoint_diff();

	/**
	 * Handle tasks to be done at the end of flush (most notably sending the
	 * metrics to the serializer).
	 */
	void flush_done_handler(const sinsp_evt* evt);

	uint32_t get_num_cpus();

	/**
	 * Determine from /proc/<pid>/comm whether this is a java process
	 * @param comm The comm proc content
	 * @return True if this is a java process. False otherwise
	 */
	bool is_java_process(const std::string& comm) const;

	uint32_t m_n_flushes;
	uint64_t m_prev_flushes_duration_ns;
	double m_prev_flush_cpu_pct;
	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;

	uint64_t m_flush_log_time;
	uint64_t m_flush_log_time_duration;
	uint64_t m_flush_log_time_cooldown;

	uint64_t m_flush_log_time_end;
	uint64_t m_flush_log_time_restart;

	uint64_t m_prev_sample_evtnum;
	uint64_t m_prev_sample_num_drop_events;

	/**
	 * Have metrics ever been sent?  This is atomic because it can
	 * be read from/written to on different threads.
	 */
	std::atomic<bool> m_sent_metrics;
	std::unique_ptr<cpu_profiler> m_cpu_profiler;

	sinsp_analyzer_parsers* m_parser;
	bool m_initialized;  // In some cases (e.g. when parsing the containers list from a file) some
	                     // events will go through the analyzer before on_capture_start is called.
	                     // We use this flag to skip processing those events.

	//
	// Tables
	//
	sinsp_transaction_table* m_trans_table;
	sinsp_ipv4_connection_manager* m_ipv4_connections;

	//
	// Pointer to context that we use frequently
	//
	sinsp* m_inspector;
	const scap_machine_info* m_machine_info;

	//
	// The score calculation class
	//
	sinsp_scores* m_score_calculator;

	//
	// This is the protobuf class that we use to pack things
	//
	std::unique_ptr<draiosproto::metrics> m_metrics;

	//
	// Checking Docker swarm state every 10 seconds
	//
#ifndef CYGWING_AGENT
	run_on_interval m_swarmstate_interval = {SWARM_POLL_INTERVAL};
	coclient m_coclient;
#endif

	//
	// Installation root
	//
	std::string m_root_dir;

	//
	// State required for CPU load calculation
	//
	sinsp_procfs_parser* m_procfs_parser;
	sinsp_proc_stat m_proc_stat;

	//
	// The aggregated host metrics
	//
	sinsp_host_metrics m_host_metrics;
	sinsp_counters m_host_req_metrics;

	bool m_procfs_scan_thread;
	bool m_protocols_enabled;
	bool m_remotefs_enabled;

	bool m_simpledriver_enabled;

	//
	// The scheduler analyzer
	//
	sinsp_sched_analyzer2* m_sched_analyzer2;

	//
	// Thread-related state
	//
	uint32_t m_thread_memory_id;

	//
	// FD-related state
	//
	sinsp_analyzer_fd_listener* m_fd_listener;

	//
	// Transaction-related state
	//
	std::set<uint64_t> m_server_programs;
	sinsp_transaction_counters m_host_transaction_counters;
	uint64_t m_client_tr_time_by_servers;
	std::vector<std::vector<sinsp_trlist_entry>> m_host_server_transactions;
	std::vector<std::vector<sinsp_trlist_entry>> m_host_client_transactions;
	// Network I/O info for the whole host.
	// We calculate this separately because we want to exclude intra-host traffic
	sinsp_counter_time_bytes m_io_net;
	sinsp_delays_info m_host_transaction_delays;

	//
	// Support for delay calculation
	//
	sinsp_delays* m_delay_calculator;

	//
	// Command list
	//
	std::unordered_map<std::string, std::vector<sinsp_executed_command>> m_executed_commands;

	//
	// Container metrics
	//
	std::unordered_map<std::string, analyzer_container_state> m_containers;
	run_on_interval m_containers_cleaner_interval = {60 * ONE_SECOND_IN_NS};
	run_on_interval m_containers_check_interval = {60 * ONE_SECOND_IN_NS};

	std::vector<const thread_analyzer_info*> m_threads_to_remove;

	//
	// Subsampling-related stuff
	//

	// represents what the analyzer has last set the sampling ratio to
	uint32_t m_requested_sampling_ratio;
	// represents what we believe the current state of the driver is. has no affect
	// on the computation of the sampling ratio, only used in some calculations
	uint64_t m_acked_sampling_ratio;

	bool m_capture_in_progress;
	uint64_t m_last_dropmode_switch_time;
	std::vector<long> m_last_total_evts_by_cpu;
	threshold_filter<long> m_total_evts_switcher;
	threshold_filter<double> m_very_high_cpu_switcher;
	uint32_t m_seconds_above_thresholds;
	uint32_t m_seconds_below_thresholds;
	double m_my_cpuload;
	bool m_skip_proc_parsing;
	uint64_t m_prev_flush_wall_time;

	//
	// Baseliner
	//
	sinsp_baseliner* m_falco_baseliner = nullptr;
	uint64_t m_last_falco_dump_ts = 0;

#ifndef CYGWING_AGENT
	infrastructure_state* m_infrastructure_state = nullptr;
#endif

	//
	// Chisel-generated metrics infrastructure
	//
	std::vector<sinsp_chisel*> m_chisels;
	std::vector<statsd_metric> m_chisel_metrics;
	bool m_run_chisels;

	internal_metrics::sptr_t m_internal_metrics;

	libsanalyzer::statsd_emitter::ptr m_statsd_emitter;

#ifndef _WIN32
	std::unique_ptr<jmx_proxy> m_jmx_proxy;
	unsigned int m_jmx_sampling;
	// indexed by pid
	std::unordered_map<int, java_process> m_jmx_metrics;
	// sent and total jmx metrics indexed by container (empty string if host)
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_jmx_metrics_by_containers;

	std::shared_ptr<statsite_proxy> m_statsite_proxy;
	std::unique_ptr<posix_queue> m_statsite_forwader_queue;

	// sent and total app checks indexed by container (empty string if host)
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_app_checks_by_containers;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_prometheus_by_containers;

	std::atomic<bool> m_statsd_capture_localhost;

	std::vector<app_check> m_app_checks;
	std::shared_ptr<app_checks_proxy_interface> m_app_checks_proxy;

	std::unique_ptr<mounted_fs_proxy> m_mounted_fs_proxy;
	std::unordered_map<std::string, std::vector<mounted_fs>> m_mounted_fs_map;
	std::unique_ptr<mounted_fs_reader> m_mounted_fs_reader;
	std::unordered_map<dev_t, std::string> m_device_map;

#ifndef CYGWING_AGENT
	prometheus_conf m_prom_conf;
	custom_container::resolver m_custom_container;
#endif
#endif

#ifndef CYGWING_AGENT
	std::unique_ptr<k8s> m_k8s;
	bool m_use_new_k8s;
	std::unique_ptr<k8s_delegator> m_k8s_delegator;
#ifndef _WIN32
	sinsp_ssl::ptr_t m_k8s_ssl;
	sinsp_bearer_token::ptr_t m_k8s_bt;
#endif
	std::shared_ptr<k8s_handler::collector_t> m_k8s_collector;
	std::unique_ptr<k8s_api_handler> m_k8s_api_handler;
	bool m_k8s_api_detected = false;
	std::unique_ptr<k8s_api_handler> m_k8s_ext_handler;
	k8s_ext_list_ptr_t m_ext_list_ptr;
	bool m_k8s_ext_detect_done = false;
	int m_k8s_retry_seconds = 60;  // TODO move to config?

	std::unique_ptr<draiosproto::swarm_state> m_docker_swarm_state;
	std::unique_ptr<mesos> m_mesos;

	// Used to generate mesos-specific app check state
	std::shared_ptr<app_process_conf_vals> m_mesos_conf_vals;

	// Used to generate marathon-specific app check state
	std::shared_ptr<app_process_conf_vals> m_marathon_conf_vals;

	// flag indicating that mesos connection either exist or has existed once
	// used to filter logs about Mesos API server unavailablity
	bool m_mesos_present = false;
	time_t m_last_mesos_refresh;
	uint64_t m_mesos_last_failure_ns;
	int64_t m_mesos_master_tid = -1;
	int64_t m_mesos_slave_tid = -1;
	const uint32_t MESOS_MASTER_PORT = 5050;
	const uint32_t MESOS_SLAVE_PORT = 5051;

	std::unique_ptr<docker> m_docker;
	bool m_has_docker;

	std::unique_ptr<containerd_events> m_containerd_events;

	int m_detect_retry_seconds = 60;  // TODO move to config?
	std::unique_ptr<new_k8s_delegator> m_new_k8s_delegator;

	bool m_is_k8s_delegated = false;
#endif  // CYGWING_AGENT

	std::vector<std::string> m_container_patterns;
	uint32_t m_containers_limit;
	uint32_t m_containers_labels_max_len;
#ifndef _WIN32
	self_cputime_analyzer m_cputime_analyzer;
#endif

	const metric_limits::sptr_t m_metric_limits;
	const label_limits::sptr_t m_label_limits;

	// The user event queue is a glogger construct that we pass around, and once it is created,
	// glogger will catch certain classes of messages and process them. This is not an efficient way
	// to leak the abstraction, but it works?
	//
	// So the users of this only need to depend on it's existence, and until then, events will jst
	// go to the regular log. When the analyzer is allocated, this is left unset. It is set by a
	// call to set_user_event_queue, which happens in sinsp_worker initialization, where the
	// sinsp_worker passes its queue on.  It's version of the queue is set by a call from
	// dragent_app:make_event_channel.
	//
	// So this whole thing only works if the following is all true:
	// 1) dragent initializes the sinsp_worker version before sinsp_init, which is the case
	// 2) sinsp_worker is inited before analyzer flush, which is almost certianly the case
	//
	// So in short, it's a pretty flaky chain of things that have to happen in order, but so it is.
	user_event_queue::ptr_t m_user_event_queue;

	run_on_interval m_proclist_refresher_interval = {NODRIVER_PROCLIST_REFRESH_INTERVAL_NS};

	uint32_t m_max_n_external_clients = MAX_N_EXTERNAL_CLIENTS;
	uint32_t m_top_connections_in_sample = TOP_CONNECTIONS_IN_SAMPLE;
	uint32_t m_top_processes_in_sample = TOP_PROCESSES_IN_SAMPLE;
	uint32_t m_top_processes_per_container = TOP_PROCESSES_PER_CONTAINER;
	bool m_report_source_port = false;
	int m_connection_truncate_report_interval = 0;
	int m_connection_truncate_log_interval = 0;
	int m_connection_truncate_report_last = 0;
	int m_connection_truncate_log_last = 0;

	bool m_username_lookups = false;
	userdb m_userdb;

	bool m_track_environment = false;
	env_hash_config m_env_hash_config;

	int m_top_files_per_prog = 0;
	int m_top_files_per_container = 0;
	int m_top_files_per_host = TOP_FILES_IN_SAMPLE;

	int m_top_file_devices_per_prog = 0;
	int m_top_file_devices_per_container = 0;
	int m_top_file_devices_per_host = 0;

	std::map<draiosproto::command_category, uint64_t> m_command_categories;

	/**
	 * Configurable number of flushes between each time that k8
	 * metadata for the local npde is sent to the backend.
	 */
	uint16_t m_k8s_local_update_frequency = 1;

	/**
	 * Configurable number of flushes between each time that k8s
	 * metadata for the entire cluster is sent to the backend.
	 */
	uint16_t m_k8s_cluster_update_frequency = 1;

	/**
	 * This works alongside m_k8s_local_update_frequency to
	 * determine how often k8s metadata should be added.
	 */
	uint16_t m_flushes_since_k8_local_flush = 0;

	/**
	 * This works alongside m_k8s_cluster_update_frequency to
	 * determine how often k8s metadata should be added.
	 */
	uint16_t m_flushes_since_k8_cluster_flush = 0;

	/**
	 * Set to true to dump the local infrastructure state to a file on
	 * next flush.
	 */
	bool m_dump_local_infrastructure_state_on_next_flush = false;

	/**
	 * Set to true to dump the global infrastructure state to a file on
	 * next flush.
	 */
	bool m_dump_global_infrastructure_state_on_next_flush = false;

	std::shared_ptr<audit_tap> m_tap;
	bool m_tap_track_pending = false;
	std::shared_ptr<secure_audit> m_secure_audit;

	/**
	 * Kill flag.  If this is set to true, the agent will restart.
	 * Possible causes:
	 *     - too many tid collisions
	 */
	bool m_die;

	/**
	 * class that manages the k8s event listener
	 */
	k8s_user_event_message_handler* m_k8s_user_event_handler = nullptr;
	bool m_get_events = false;

	friend class test_helper;

	audit_tap_handler& m_audit_tap_handler;
	secure_audit_handler& m_secure_audit_handler;
	secure_profiling_handler& m_secure_profiling_handler;

	std::function<bool()> m_check_disable_dropping;

	process_manager m_process_manager;

	std::mutex m_metrics_dir_mutex;
	std::string m_metrics_dir;

	/**
	 * Message queue to send flush data down the pipeline.
	 */
	flush_queue* m_flush_queue;

	std::shared_ptr<promscrape> m_promscrape;

	//
	// Please do not add any friends.
	//
	void mounted_fs_request(const tracer_emitter& proc_trc,
				const analyzer_emitter::progtable_by_container_t& progtable_by_container) const;
};
