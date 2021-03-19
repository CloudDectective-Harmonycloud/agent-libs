#pragma once

#include "main.h"
#include "common_logger.h"
#include "user_event.h"
#include "metric_limits.h"
#include "custom_container.h"

#include <atomic>
#include <memory>
#include <set>
#include <map>
#include <string>

#include "yaml_configuration.h"

///////////////////////////////////////////////////////////////////////////////
// Configuration defaults
///////////////////////////////////////////////////////////////////////////////
//
// The size of the write buffer for the socket that we use to send the data to
// the backend. If this buffer fills up, we will drop upcoming samples.
//
#define DEFAULT_DATA_SOCKET_BUF_SIZE (256 * 1024)

//
// The number of analyzer samples that we store in memory when we lose connection
// to the backend. After MAX_SAMPLE_STORE_SIZE samples, we will start dropping.
//
#define MAX_SAMPLE_STORE_SIZE 300

//
// The maximum number of policy events that can be queued for sending
// to the backend.
//
#define MAX_QUEUED_POLICY_EVENTS 500

static const int PIPE_BUFFER_SIZE = 1048576;
#define SDJAGENT_JMX_TIMEOUT "2000"


class aws_metadata
{
public:
	aws_metadata():
		m_public_ipv4(0)
	{}

	uint32_t m_public_ipv4; // http://169.254.169.254/latest/meta-data/public-ipv4
	std::string m_instance_id; // http://169.254.169.254/latest/meta-data/public-ipv4
	std::string m_account_id;
	std::string m_region;
};

class dragent_configuration;

class dragent_auto_configuration
{
public:
	dragent_auto_configuration(const std::string &config_filename,
				   const std::string &config_directory,
				   const std::string &config_header);

	virtual ~dragent_auto_configuration()
	{
	};

	int save(dragent_configuration &config, const std::string &config_data, std::string &errstr);

	void init_digest();

	std::string digest();

	const std::string config_path();

	void set_config_directory(const std::string &config_directory);

	virtual bool validate(const std::string &new_config_data, std::string &errstr) = 0;

	virtual void apply(dragent_configuration &config) = 0;

protected:
	std::string m_config_filename;
	std::string m_config_directory;
	std::string m_config_header;

private:
	SHA1Engine m_sha1_engine;
	DigestEngine::Digest m_digest;
};

enum class dragent_mode_t {
	/**
	 * Include all data, including system call data, in metrics
	 * protobuf.
	 */
	STANDARD,
	/**
	 * Do not use system call data. This will get process data from
	 * /proc instead of from system calls.
	 */
	NODRIVER,
	/**
	 * This tells the driver to only process the subset of syscalls.
	 * This is useful for customers that are mostly interested in
	 * prometheus or statsd and don't want the processor overhead of
	 * syscall handling.
	 */
	SIMPLEDRIVER
};

class dragent_configuration
{
public:
	dragent_configuration();

	/**
	 * Initialize the configuration with a yaml file
	 */
	void init(Application* app, bool use_installed_dragent_yaml,
                  const std::string* conf_file_override_path = nullptr);

	/**
	 * Initialize the configuration to defaults.
	 */
	void init();

	void print_configuration() const;
	static Message::Priority string_to_priority(const std::string& priostr);
	static bool get_memory_usage_mb(uint64_t* memory);
	static std::string get_distribution();
	bool load_error() const { return m_load_error; }

	// Static so that the signal handler can reach it
	static std::atomic<bool> m_signal_dump;
	static std::atomic<bool> m_enable_trace;
	static std::atomic<bool> m_send_log_report;

	std::string m_raw_file_priority;
	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	Message::Priority m_min_event_priority;
	bool m_curl_debug;

	// the operation of the root dir is a bit hokey.
	// we have a "default" root dir that is the effectively the install dir. we use that
	// to find a few things, like the yaml files. afterwards, we generate the configured
	// root dir (c_root_dir) from the yaml, or otherwise set it to the default.
	static type_config<std::string> c_root_dir;
	std::string m_default_root_dir;

	std::string m_conf_file;
	std::unique_ptr<yaml_configuration> m_config;

	std::string m_defaults_conf_file;
	std::string m_log_dir;
	uint16_t m_log_rotate;
	// Log size in megabytes
	uint16_t m_max_log_size;
	bool m_globally_readable_log_files;
	std::string m_customer_id;
	std::string m_server_addr;
	uint16_t m_server_port;
	bool m_ssl_enabled;
	std::string m_ssl_ca_certificate;
	std::vector<std::string> m_ssl_ca_cert_paths;
	bool m_compression_enabled;
	std::string m_dump_dir;
	std::string m_input_filename;
	uint64_t m_evtcnt;
	bool m_config_test;

	// parameters used by cpu usage tuning
	long m_tracepoint_hits_threshold;
	unsigned m_tracepoint_hits_ntimes;
	double m_cpu_usage_max_sr_threshold;
	unsigned m_cpu_usage_max_sr_ntimes;

	bool m_autoupdate_enabled;
	bool m_print_protobuf;
	std::string m_json_parse_errors_logfile;
	double m_json_parse_errors_events_rate;
	uint32_t m_json_parse_errors_events_max_burst;
	bool m_watchdog_enabled;
	uint64_t m_watchdog_sinsp_worker_timeout_s;
	uint64_t m_watchdog_sinsp_worker_debug_timeout_s;
	uint64_t m_watchdog_connection_manager_timeout_s;
	uint64_t m_watchdog_subprocesses_logger_timeout_s;
	uint64_t m_watchdog_analyzer_tid_collision_check_interval_s;
	uint64_t m_watchdog_sinsp_data_handler_timeout_s;
#ifndef CYGWING_AGENT
	uint64_t m_watchdog_heap_profiling_interval_s;
#endif
	uint64_t m_dirty_shutdown_report_log_size_b;
	uint64_t m_dirty_shutdown_default_report_log_size_b;
	uint64_t m_dirty_shutdown_trace_report_log_size_b;

	typedef std::map<std::string, uint64_t> ProcessValue64Map;
	typedef std::map<std::string, int> ProcessValueMap;

	/**
	 * The amount of memory that each subprocess is allowed to use.
	 * If exceeded, the entire dragent application will be
	 * restarted.
	 */
	ProcessValue64Map m_watchdog_max_memory_usage_subprocesses_mb;

	/**
	 * The amount of time that each subprocess is allowed to run
	 * before updating the appropriate watchdog heartbeat. If
	 * exceeded, the entire dragent application will be restarted.
	 */
	ProcessValue64Map m_watchdog_subprocesses_timeout_s;

	/**
	 * The priority to assign to each subprocess. This is only
	 * supported on linux and sets the "nice" value of the
	 * subprocess. The default nice value is 0 and both positive and
	 * negative values are allowed; lower nice values shall cause
	 * more favorable scheduling.
	 */
	ProcessValueMap m_subprocesses_priority;

	bool m_capture_dragent_events;
	aws_metadata m_aws_metadata;
	uint16_t m_jmx_sampling;
	bool m_protocols_enabled;
	uint32_t m_protocols_truncation_size;
	bool m_remotefs_enabled;
	std::string m_java_binary;
	std::string m_sdjagent_opts;
	bool m_sysdig_capture_enabled;
	uint32_t m_max_sysdig_captures;
	double m_sysdig_capture_transmit_rate;
	int32_t m_sysdig_capture_compression_level;

	std::vector<app_check> m_app_checks;
	std::string m_python_binary;
	uint32_t m_containers_labels_max_len;
	std::vector<std::string> m_container_patterns;
	std::vector<sinsp_chisel_details> m_chisel_details;
	bool m_system_supports_containers;
#ifndef CYGWING_AGENT
	prometheus_conf m_prom_conf;
	bool m_promex_enabled;
	std::string m_promex_url;
	std::string m_promex_connect_url;
	std::string m_promex_container_labels;
	custom_container::resolver m_custom_container;
#endif

	typedef std::set<std::string>      k8s_ext_list_t;
	typedef std::shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	int m_k8s_delegated_nodes = 0;
	k8s_ext_list_t m_k8s_extensions;
	bool m_use_new_k8s;

	/**
	 * The frequency, in units of flushes, that the k8s metadata for
	 * the local containers is sent to the backend.
	 */
	uint16_t m_k8s_local_update_frequency = 1;

	/**
	 * The frequency, in units of flushes, that the k8s metadata for
	 * the entire cluster is sent to the backend.
	 */
	uint16_t m_k8s_cluster_update_frequency = 1;

	std::string m_k8s_cluster_name;

	std::string m_mesos_state_uri;
	std::vector<std::string> m_marathon_uris;
	bool m_mesos_autodetect;
	int m_mesos_timeout_ms;
	bool m_mesos_follow_leader;
	bool m_marathon_follow_leader;
#ifndef CYGWING_AGENT
	mesos::credentials_t m_mesos_credentials;
	mesos::credentials_t m_marathon_credentials;
	mesos::credentials_t m_dcos_enterprise_credentials;
	std::set<std::string> m_marathon_skip_labels;
#endif

	sinsp_configuration::command_capture_mode_t m_command_lines_capture_mode;
	std::set<std::string> m_command_lines_valid_ancestors;
	bool m_command_lines_include_container_healthchecks;

	user_event_filter_t::ptr_t m_k8s_event_filter;
	user_event_filter_t::ptr_t m_docker_event_filter;
	user_event_filter_t::ptr_t m_containerd_event_filter;

	bool m_excess_metric_log = false;
	filter_vec_t m_metrics_filter;
	filter_vec_t m_k8s_filter;
	uint16_t m_k8s_cache_size;
	bool m_excess_k8s_log = false;
	unsigned m_metrics_cache;
	filter_vec_t m_labels_filter;
	uint16_t m_labels_cache;
	bool m_excess_labels_log = false;
	mount_points_filter_vec m_mounts_filter;
	unsigned m_mounts_limit_size;
	bool m_enable_coredump;
	bool m_auto_config;
	bool m_emit_tracers = false;
	bool m_enable_grpc_tracing = false;
	unsigned long m_rlimit_msgqueue;

	std::string m_falco_default_rules_filename;
	std::string m_falco_fallback_default_rules_filename;
	std::string m_falco_auto_rules_filename;
	std::string m_falco_rules_filename;
	double m_falco_engine_sampling_multiplier;
	std::set<std::string> m_falco_engine_disabled_rule_patterns;

	/**
	 * Set when a new auto rules file is downloaded. Monitored by
	 * sinsp_agent and when set will reload the falco engine and
	 * clear.
	 */
	std::atomic_bool m_reset_falco_engine;

	std::vector<std::string> m_suppressed_comms;
	std::vector<uint16_t> m_suppressed_types;

	uint64_t m_user_events_rate;
	uint64_t m_user_max_burst_events;

	// since we translate this mode into other configs consumable by feature manager,
	// we have to cache whether it was set explicitly so we can forward that as well
	dragent_mode_t m_mode;
	bool m_mode_explicitly_set;

	bool m_detect_stress_tools = false;
	std::vector<std::string> m_stress_tools;
	bool m_large_envs;

	uint32_t m_coclient_max_loop_evts = 100;

	std::set<double> m_percentiles;
	static const unsigned MAX_PERCENTILES = 4;
	std::vector<double> m_ignored_percentiles;
	std::shared_ptr<proc_filter::group_pctl_conf> m_group_pctl_conf;
	std::shared_ptr<proc_filter::conf> m_container_filter;

	/**
	 * Enable to route K8s user events through cointerface instead of dragent
	 * dragent will only serve as a middleman in this case. Leave false
	 * to cause dragent to directly talk to K8s API server to fetch events
	 */
	bool m_go_k8s_user_events = false;

 	bool m_cointerface_cpu_profile_enabled;
	int32_t m_cointerface_events_per_profile;
	int32_t m_cointerface_total_profiles;
	bool m_cointerface_mem_profile_enabled;

	bool m_statsite_check_format;

	unsigned m_snaplen;

	uint16_t m_monitor_files_freq_sec = 0;
	std::set<std::string> m_monitor_files;

	bool m_query_docker_image_info;

	uint64_t m_flush_log_time;
	uint64_t m_flush_log_time_duration;
	uint64_t m_flush_log_time_cooldown;

	uint32_t m_max_n_external_clients = MAX_N_EXTERNAL_CLIENTS;
	uint32_t m_top_connections_in_sample = TOP_CONNECTIONS_IN_SAMPLE;
	uint32_t m_top_processes_in_sample = TOP_PROCESSES_IN_SAMPLE;
	uint32_t m_top_processes_per_container = TOP_PROCESSES_PER_CONTAINER;
	bool m_report_source_port = false;

	std::set<std::string> m_url_groups;
	bool m_url_groups_enabled = false;

	bool m_track_connection_status;
	int m_connection_truncate_report_interval;
	int m_connection_truncate_log_interval;

	bool m_username_lookups = false;

	bool m_track_environment = false;
	uint32_t m_envs_per_flush;
	size_t m_max_env_size;
	std::unique_ptr<env_hash::regex_list_t> m_env_blacklist;
	uint64_t m_env_hash_ttl;
	bool m_env_metrics = true;
	bool m_env_audit_tap = true;

	bool m_audit_tap_enabled = false;

	std::unordered_map<std::string, std::unordered_map<std::string, std::string>>m_secure_audit_k8s_filters;
	std::vector<std::string>m_secure_audit_k8s_active_filters;

	int m_top_files_per_prog = 0;
	int m_top_files_per_container = 0;
	int m_top_files_per_host = TOP_FILES_IN_SAMPLE;

	int m_top_file_devices_per_prog = 0;
	int m_top_file_devices_per_container = 0;
	int m_top_file_devices_per_host = 0;

	std::set<std::string> m_procfs_scan_procs;

	bool java_present() const
	{
		return !m_java_binary.empty();
	}

	bool python_present() const
	{
#ifndef CYGWING_AGENT
		return !m_python_binary.empty();
#else
		return false;
#endif
	}

	std::string machine_id() const
	{
		return m_machine_id_prefix + m_machine_id;
	}

	void refresh_aws_metadata();
	void refresh_machine_id();
	bool check_python_version26();
	static size_t curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json);
	static std::string curl_get(const std::string& uri, const std::string& buffer);

	// Returns 0 if already up-to-date, 1 if updated, -1 if
	// error. On error, &errstr is updated with the source of the
	// error.
	int save_auto_config(const std::string &config_filename, const std::string& config_data, std::string &errstr);

	void set_auto_config_directory(const std::string &config_directory);

	static type_config<bool> c_enable_aws_metadata;

    // AWS metadata
	std::string get_aws_instance_id();
	std::string get_aws_account_id();
	std::string get_aws_region();

	void set_machine_id_prefix(std::string prefix) { m_machine_id_prefix = prefix; }

	std::string relpath_to_absolute(const std::string& relpath)
	{
		return Path(c_root_dir.get_value()).append(relpath).toString();
	}

private:
	inline static bool is_executable(const std::string& path);
	void write_statsite_configuration();
	void add_event_filter(user_event_filter_t::ptr_t& flt, const std::string& system, const std::string& component);
	void add_percentiles();
	std::string get_install_prefix(const Application* app);
	void sanitize_limits(filter_vec_t& filters);


	std::map<std::string, std::unique_ptr<dragent_auto_configuration>> m_supported_auto_configs;
	bool m_load_error;

	friend class aws_metadata_refresher;

	std::string m_machine_id;
	std::string m_machine_id_prefix;
};

class aws_metadata_refresher: public Runnable
{
public:
	aws_metadata_refresher(dragent_configuration &configuration):
		m_refreshed(false),
		m_running(false),
		m_configuration(configuration)
	{}

	void run()
	{
		m_running.store(true, std::memory_order_relaxed);
		m_configuration.refresh_aws_metadata();
		m_refreshed.store(true, std::memory_order_relaxed);
	}

	void reset()
	{
		m_running.store(false, std::memory_order_relaxed);
		m_refreshed.store(false, std::memory_order_relaxed);
	}

	bool done()
	{
		return m_refreshed.load(std::memory_order_relaxed);
	}

	bool is_running()
	{
		return m_running.load(std::memory_order_relaxed);
	}

private:
	std::atomic<bool> m_refreshed;
	std::atomic<bool> m_running;
	dragent_configuration &m_configuration;
};
