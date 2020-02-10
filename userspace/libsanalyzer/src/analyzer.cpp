#define DUMP_TO_DISK
#define BUFFERSIZE 512  // b64 needs this macro
#define __STDC_FORMAT_MACROS
#include "analyzer.h"
#include "analyzer_fd.h"
#include "analyzer_flush_message.h"
#include "analyzer_int.h"
#include "analyzer_parsers.h"
#include "analyzer_thread.h"
#include "app_check_emitter.h"
#include "audit_tap.h"
#include "baseliner.h"
#include "chisel.h"
#include "configuration_manager.h"
#include "connectinfo.h"
#include "container_emitter.h"
#include "delays.h"
#include "draios.pb.h"
#include "environment_emitter.h"
#include "jmx_emitter.h"
#include "json_query.h"
#include "label_limits.h"
#include "metric_limits.h"
#include "metrics.h"
#include "null_statsd_emitter.h"
#include "parsers.h"
#include "proc_config.h"
#include "procfs_parser.h"
#include "sched_analyzer.h"
#include "scores.h"
#include "secure_audit.h"
#include "sinsp.h"
#include "sinsp_errno.h"
#include "sinsp_int.h"
#include "statsd_emitter_factory.h"
#include "statsite_config.h"
#include "tracer_emitter.h"
#include "type_config.h"
#include "uri.h"
#include "user_event_logger.h"

#include "../../driver/ppm_ringbuffer.h"
#include "Poco/File.h"
#include "Poco/RegularExpression.h"
#include "b64/encode.h"
#include "third-party/jsoncpp/json/json.h"
#include "utils/profiler.h"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/util/json_util.h>

#include <algorithm>
#include <fcntl.h>
#include <gperftools/profiler.h>
#include <iostream>
#include <math.h>
#include <memory>
#include <numeric>
#include <stdio.h>
#include <stdlib.h>

#ifndef CYGWING_AGENT
#include "container_info.h"
#include "cri.h"
#include "infrastructure_state.h"
#include "k8s.h"
#include "k8s_config.h"
#include "k8s_delegator.h"
#include "k8s_proto.h"
#include "k8s_state.h"
#include "mesos.h"
#include "mesos_proto.h"
#include "mesos_state.h"
#include "metric_forwarding_configuration.h"
#include "security_config.h"

#include "container_events/containerd.h"
#include "container_events/docker.h"
#else  // CYGWING_AGENT
#include "dragent_win_hal_public.h"
#include "proc_filter.h"
#endif  // CYGWING_AGENT

#ifdef _WIN32
#include <process.h>
#include <time.h>
#include <winsock2.h>
#define getpid _getpid
#else
#include <endian.h>
#include <netinet/in.h>
#include <sys/socket.h>
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
#include <sys/syscall.h>
#endif
#include <sys/resource.h>
#include <sys/time.h>
#endif  // _WIN32
#ifndef _WIN32
#include <google/protobuf/io/gzip_stream.h>
#endif

using namespace std;
using namespace libsanalyzer;
using namespace google::protobuf::io;

typedef container_emitter<sinsp_analyzer, analyzer_emitter::flush_flags> analyzer_container_emitter;

namespace
{
template<typename T>
void init_host_level_percentiles(T& metrics, const std::set<double>& pctls)
{
	metrics.set_percentiles(pctls);
	metrics.set_serialize_pctl_data(true);
}

type_config<bool> c_dragent_cpu_profile(false,
                                        "Create dragent cpu profiles and save to the log directory",
                                        "dragent_cpu_profile_enabled");

type_config<int32_t> c_dragent_cpu_profile_seconds(
    120,
    "The number of seconds to collect data for a single cpu profile",
    "dragent_profile_time_seconds");

type_config<int32_t> c_dragent_cpu_profile_total_profiles(
    30,
    "The total number of cpu profiles to collect before overwriting old profiles",
    "dragent_total_profiles");

type_config<bool>::ptr c_test_only_send_infra_state_containers =
    type_config_builder<bool>(
        false,
        "Send all containers from infrastructure_state as local to the current node",
        "send_infra_state_containers")
        .hidden()
        .mutable_only_in_internal_build()
        .build();

type_config<uint32_t>::ptr c_drop_upper_threshold =
    type_config_builder<uint32_t>(
        5,
        "Percent of time alotted to event processing before we increase sampling",
        "autodrop",
        "upper_threshold")
        .max(100)
        .build();

type_config<uint32_t>::ptr c_drop_lower_threshold =
    type_config_builder<uint32_t>(
        3,
        "Percent of time alotted to event processing before we decrease sampling",
        "autodrop",
        "lower_threshold")
        .max(100)
        .build();

type_config<uint32_t>::ptr c_drop_upper_threshold_baseliner =
    type_config_builder<uint32_t>(30,
                                  "Percent of time alotted to event processing before we increase "
                                  "sampling when baseliner enabled",
                                  "autodrop",
                                  "baseliner_upper_threshold")
        .max(100)
        .build();

type_config<uint32_t>::ptr c_drop_lower_threshold_baseliner =
    type_config_builder<uint32_t>(27,
                                  "Percent of time alotted to event processing before we decrease "
                                  "sampling when baseliner enabled",
                                  "autodrop",
                                  "baseliner_lower_threshold")
        .max(100)
        .build();

type_config<bool>::ptr c_adjust_threshold_for_cpu_count =
    type_config_builder<bool>(true,
                              "Allow thressholds to scale with increasing CPU core count."
                              "autodrop",
                              "adjust_for_cpu_count")
        .build();

type_config<uint32_t>::ptr c_drop_seconds_before_action =
    type_config_builder<uint32_t>(5,
                                  "Consecutive seconds crossing a threshold before we take action",
                                  "autodrop",
                                  "seconds_before_action")
        .build();

type_config<bool>::ptr c_autodrop_enabled =
    type_config_builder<bool>(true,
                              "Set to false to disable dropping events in response to load",
                              "autodrop",
                              "enabled")
        .build();

// would prefer to be autodrop.sampling_ratio, but alternate_key untested
type_config<uint32_t>::ptr c_fixed_sampling_ratio =
    type_config_builder<uint32_t>(0,
                                  "Set to non-zero to force sampling at the given ratio. Overrides "
                                  "all other autodrop configs.",
                                  "subsampling",
                                  "ratio")
        .build();

type_config<uint64_t>::ptr c_flush_interval =
    type_config_builder<uint64_t>(
        1 * NSECS_PER_SEC,
        "Change the interval afterwhich sinsp will send a flush event. Not guaranteed to work.",
        "flush_interval")
        .hidden()
        .build();
}  // end namespace

const uint64_t flush_data_message::NO_EVENT_NUMBER = std::numeric_limits<uint64_t>::max();

sinsp_analyzer::sinsp_analyzer(sinsp* inspector,
                               std::string root_dir,
                               const internal_metrics::sptr_t& internal_metrics,
                               audit_tap_handler& tap_handler,
                               secure_audit_handler& secure_audit_handler,
                               secure_profiling_handler& secure_profiling_handler,
                               sinsp_analyzer::flush_queue* flush_queue,
                               std::function<bool()> check_disable_dropping,
                               const metric_limits::sptr_t& the_metric_limits,
                               const label_limits::sptr_t& the_label_limits,
                               const k8s_limits::sptr_t& the_k8s_limits,
                               std::shared_ptr<app_checks_proxy_interface> the_app_checks_proxy)
    : m_configuration(new sinsp_configuration()),
      m_inspector(inspector),
      m_metrics(make_unique<draiosproto::metrics>()),
#ifndef CYGWING_AGENT
      m_coclient(root_dir),
#endif
      m_root_dir(root_dir),
      m_requested_sampling_ratio(1),
      m_acked_sampling_ratio(1),
      m_last_total_evts_by_cpu(sinsp::num_possible_cpus(), 0),
      m_total_evts_switcher("driver overhead"),
      m_very_high_cpu_switcher("agent cpu usage with sr=128"),
      m_internal_metrics(internal_metrics),
      m_statsd_emitter(new null_statsd_emitter()),
      m_app_checks_proxy(std::move(the_app_checks_proxy)),
      m_metric_limits(the_metric_limits),
      m_label_limits(the_label_limits),
      m_audit_tap_handler(tap_handler),
      m_secure_audit_handler(secure_audit_handler),
      m_secure_profiling_handler(secure_profiling_handler),
      m_check_disable_dropping(check_disable_dropping),
      m_metrics_dir_mutex(),
      m_metrics_dir(""),
      m_flush_queue(flush_queue)
{
	ASSERT(m_internal_metrics);
	m_initialized = false;
	m_n_flushes = 0;
	m_prev_flushes_duration_ns = 0;
	m_prev_flush_cpu_pct = 0.0;
	m_next_flush_time_ns = 0;
	m_prev_flush_time_ns = 0;
	m_prev_sample_num_drop_events = 0;

	m_flush_log_time = tracer_emitter::no_timeout;
	m_flush_log_time_duration = 0;
	m_flush_log_time_cooldown = 0;
	m_flush_log_time_end = 0;
	m_flush_log_time_restart = 0;

	m_prev_sample_evtnum = 0;
	m_client_tr_time_by_servers = 0;

	m_sent_metrics = false;
	m_trace_started = false;
	m_last_profile_flush_ns = 0;
	m_trace_count = 0;

	m_procfs_parser = NULL;
	m_sched_analyzer2 = NULL;
	m_score_calculator = NULL;
	m_delay_calculator = NULL;

	m_ipv4_connections = NULL;
	m_trans_table = NULL;
	m_last_dropmode_switch_time = 0;
	m_seconds_above_thresholds = 0;
	m_seconds_below_thresholds = 0;
	m_my_cpuload = -1;
	m_skip_proc_parsing = false;
	m_simpledriver_enabled = false;
	m_prev_flush_wall_time = 0;
	m_mode_switch_state = sinsp_analyzer::MSR_NONE;
	m_die = false;
	m_run_chisels = false;

	m_parser = new sinsp_analyzer_parsers(this);

	m_falco_baseliner = new sinsp_baseliner(*this, m_inspector);

	m_tap = nullptr;
	m_secure_audit = nullptr;
#ifndef CYGWING_AGENT
	m_infrastructure_state = new infrastructure_state(*this, inspector, root_dir, the_k8s_limits);
#endif

	//
	// Listeners
	//
#ifndef USE_AGENT_THREAD
	m_thread_memory_id = inspector->reserve_thread_memory(sizeof(thread_analyzer_info));
#endif

	m_threadtable_listener = new analyzer_threadtable_listener(inspector, *this);
	inspector->m_thread_manager->set_listener((sinsp_threadtable_listener*)m_threadtable_listener);

	m_fd_listener = new sinsp_analyzer_fd_listener(inspector, this, m_falco_baseliner);
	inspector->m_parser->m_fd_listener = m_fd_listener;
#ifndef _WIN32
	m_jmx_sampling = 1;
#endif

#ifndef CYGWING_AGENT
	m_use_new_k8s = false;
#endif
	m_procfs_scan_thread = false;
	m_protocols_enabled = true;
	m_remotefs_enabled = false;
	m_containers_limit = CONTAINERS_HARD_LIMIT;

	//
	// Docker
	//
#ifndef CYGWING_AGENT
	m_has_docker = Poco::File(docker::get_socket_file()).exists();
#endif

	//
	// Chisels init
	//
	add_chisel_dirs();

#ifndef CYGWING_AGENT
	m_mesos_last_failure_ns = 0;
	m_last_mesos_refresh = 0;

	m_docker_swarm_state = make_unique<draiosproto::swarm_state>();
#endif
}

sinsp_analyzer::~sinsp_analyzer()
{
	if (c_dragent_cpu_profile.get_value())
	{
		utils::profiler::stop();
	}

	delete m_score_calculator;
	delete m_procfs_parser;
	delete m_sched_analyzer2;
	delete m_delay_calculator;
	delete m_threadtable_listener;
	delete m_fd_listener;
	delete m_ipv4_connections;

	delete m_trans_table;
	delete m_configuration;
	delete m_parser;

	for (vector<sinsp_chisel*>::iterator it = m_chisels.begin(); it != m_chisels.end(); ++it)
	{
		delete *it;
	}
	m_chisels.clear();

	if (m_falco_baseliner != NULL)
	{
		delete m_falco_baseliner;
	}

#ifndef CYGWING_AGENT
	if (m_infrastructure_state != NULL)
	{
		delete m_infrastructure_state;
	}
#endif

	if (m_k8s_user_event_handler)
	{
		delete m_k8s_user_event_handler;
	}
}

/// calculate analyzer thread CPU usage in percent
/// (100 == one full CPU)
static double calculate_thread_cpu_usage(uint64_t num_cpus, uint64_t current_jiffies)
{
	static const uint64_t ticks_per_sec = sysconf(_SC_CLK_TCK);

	static uint64_t prev_cpu_time_us = 0;
	static uint64_t prev_jiffies = 0;

	double thread_self_cpu_load = -1;

	struct rusage usage;
	if (getrusage(RUSAGE_THREAD, &usage) != 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "calculate_thread_cpu_usage: Unable to call getrusage, errno: %s",
		                strerror(errno));
		return -1;
	}

	// CPU time used by the thread since startup
	uint64_t curr_cpu_time_us = usage.ru_utime.tv_sec * USECS_PER_SEC + usage.ru_utime.tv_usec +
	                            usage.ru_stime.tv_sec * USECS_PER_SEC + usage.ru_stime.tv_usec;

	// elapsed CPU time in ticks since the last call
	// (this increases by ticks_per_sec every second for every CPU)
	uint64_t elapsed_us = (current_jiffies - prev_jiffies) * USECS_PER_SEC / ticks_per_sec;

	if (prev_cpu_time_us > 0 && elapsed_us > 0)
	{
		// get the thread CPU usage difference since last call
		// and scale it so that 100 == one CPU
		// except for losing precision, this would be best expressed as:
		// ((cur - prev) / (elapsed_us / num_cpus)) * 100
		thread_self_cpu_load =
		    ((double)(curr_cpu_time_us - prev_cpu_time_us) * 100 * num_cpus) / elapsed_us;
	}

	prev_cpu_time_us = curr_cpu_time_us;
	prev_jiffies = current_jiffies;
	return thread_self_cpu_load;
}

/// get analyzer thread CPU usage in percent adjusted for measured
/// stolen CPU time. This calculation is an estimation, since it is difficult to know exactly
/// how much time was stolen from this thread vs some other thread
void sinsp_analyzer::calculate_analyzer_cpu_usage()
{
#if defined(HAS_CAPTURE)
	// both the numerator and denominator of the calculation contained herein
	// include stolen time (as they come stright from /proc/stat). Therefore
	// the effective result of this calculation is
	//
	// A + AS/B
	//-----------
	//  B +  S
	//
	//  ==
	//
	//  A(1 + S/B)
	// ------------
	//   B +  S
	//
	//  ==
	//
	//  A((B+S)/B)
	// ------------
	//  B + S
	//
	//  ==
	//
	//  A
	// ---
	//  B
	double my_raw_cpu_load = calculate_thread_cpu_usage(m_machine_info->num_cpus,
	                                                    m_procfs_parser->get_global_cpu_jiffies());
	my_raw_cpu_load = std::max(my_raw_cpu_load, (double)0);
	m_my_cpuload = my_raw_cpu_load;

	uint64_t steal_pct = m_procfs_parser->global_steal_pct();
	steal_pct = std::max(steal_pct, (uint64_t)0);
	steal_pct = std::min(steal_pct, (uint64_t)100);

	// This is a bit of a weird way to do this, but the result is converting
	// A/B -> A/(B+S)
	//
	// A/B - A/B * S/(B+S)
	// A/B * (1 - S/(B+S))
	// A/B * B/(B+S)
	// A/(B+S)
	//
	// This would be equivalent of dividing by (steal_pct/100)
	m_my_cpuload -= (m_my_cpuload * ((double)steal_pct / 100));

	g_logger.log("Agent internal CPU time adjusted for steal time by factor " +
	                 std::to_string(m_my_cpuload / my_raw_cpu_load) +
	                 ": raw cpu load=" + std::to_string(my_raw_cpu_load) +
	                 " => adjusted cpu load=" + std::to_string(m_my_cpuload),
	             sinsp_logger::SEV_DEBUG);
#else
	m_my_cpuload = 0;
#endif
}

void sinsp_analyzer::emit_percentiles_config()
{
	const std::set<double>& pctls = m_configuration->get_percentiles();
	for (double p : pctls)
	{
		m_metrics->add_config_percentiles((uint32_t)round(p));
	}
}

void sinsp_analyzer::set_percentiles()
{
	const std::set<double>& pctls = m_configuration->get_percentiles();
	if (pctls.size())
	{
		init_host_level_percentiles(m_host_transaction_counters, pctls);
		init_host_level_percentiles(m_host_metrics, pctls);
		if (m_host_metrics.m_protostate)
		{
			init_host_level_percentiles(*(m_host_metrics.m_protostate), pctls);
		}
		init_host_level_percentiles(m_host_req_metrics, pctls);
		init_host_level_percentiles(m_io_net, pctls);

		auto conf = m_configuration->get_group_pctl_conf();
		if (conf)
		{
			m_containers_check_interval.interval(conf->check_interval() * ONE_SECOND_IN_NS);
		}
	}
}

#ifndef CYGWING_AGENT
infrastructure_state* sinsp_analyzer::infra_state()
{
	return m_infrastructure_state;
}
#endif

void sinsp_analyzer::on_capture_start()
{
	if (m_initialized)
	{
		// This is called twice when loading an scap file
		return;
	}

	m_initialized = true;
	if (m_procfs_parser != NULL)
	{
		//
		// Note, we can get here if we switch from regular to nodriver and vice
		// versa. In that case, sinsp is opened and closed and as a consequence
		// on_capture_start is called again. It's fine, because the analyzer
		// keeps running in the meantime.
		//
		// throw sinsp_exception("analyzer can be opened only once");
		return;
	}

	//
	// Start dropping of non-critical events
	//
	if (c_autodrop_enabled->get_value())
	{
		m_inspector->start_dropping_mode(1);
	}

	//
	// Enable dynamic snaplen on live captures
	//
	if (m_inspector->is_live())
	{
		if (m_inspector->dynamic_snaplen(true) != SCAP_SUCCESS)
		{
			const std::string err = scap_getlasterr(m_inspector->m_h);
			g_logger.log("analyzer: " + err, sinsp_logger::SEV_ERROR);
			throw sinsp_exception(err);
		}
	}

	//
	// Hardware-dependent inits
	//
	m_machine_info = m_inspector->get_machine_info();
	if (m_machine_info == NULL)
	{
		ASSERT(false);
		const std::string err = "analyzer: machine info missing, analyzer can't start";
		g_logger.log(err, sinsp_logger::SEV_ERROR);
		throw sinsp_exception(err);
	}

	auto cpu_max_sr_threshold = m_configuration->get_cpu_max_sr_threshold();
	m_very_high_cpu_switcher.set_threshold(cpu_max_sr_threshold.first * m_machine_info->num_cpus);
	m_very_high_cpu_switcher.set_ntimes_max(cpu_max_sr_threshold.second);

	auto tracepoint_hits_threshold = m_configuration->get_tracepoint_hits_threshold();
	m_total_evts_switcher.set_threshold(tracepoint_hits_threshold.first);
	m_total_evts_switcher.set_ntimes_max(tracepoint_hits_threshold.second);

#ifndef CYGWING_AGENT
	m_procfs_parser =
	    new sinsp_procfs_parser(m_machine_info->num_cpus,
	                            m_machine_info->memory_size_bytes / 1024,
	                            !m_inspector->is_capture(),
	                            m_configuration->get_procfs_scan_interval_ms() / 1000,
	                            m_configuration->get_procfs_scan_mem_interval_ms() / 1000);
#else
	m_procfs_parser =
	    new sinsp_procfs_parser(m_inspector,
	                            m_machine_info->num_cpus,
	                            m_machine_info->memory_size_bytes / 1024,
	                            !m_inspector->is_capture(),
	                            m_configuration->get_procfs_scan_interval_ms() / 1000,
	                            m_configuration->get_procfs_scan_mem_interval_ms() / 1000);
#endif
	m_mounted_fs_reader.reset(new mounted_fs_reader(m_remotefs_enabled,
	                                                m_configuration->get_mounts_filter(),
	                                                m_configuration->get_mounts_limit_size()));

	m_sched_analyzer2 = new sinsp_sched_analyzer2(*this, m_inspector, m_machine_info->num_cpus);
	m_score_calculator = new sinsp_scores(*this, m_inspector, m_sched_analyzer2);
	m_delay_calculator = new sinsp_delays(m_machine_info->num_cpus);

	//
	// Allocations
	//
	ASSERT(m_ipv4_connections == NULL);
	m_ipv4_connections = new sinsp_ipv4_connection_manager(m_inspector, *this);

	if (m_secure_audit != nullptr)
	{
		m_secure_audit->init(m_ipv4_connections, m_fd_listener);
	}

	const std::set<double>& pctls = m_configuration->get_percentiles();
	if (pctls.size())
	{
		m_ipv4_connections->m_percentiles = pctls;
	}
	m_fd_listener->set_ipv4_connection_manager(m_ipv4_connections);
	m_trans_table = new sinsp_transaction_table(*this);

	//
	// Notify the scheduler analyzer
	//
	ASSERT(m_sched_analyzer2 != NULL);
	m_parser->set_sched_analyzer2(m_sched_analyzer2);
	m_sched_analyzer2->on_capture_start();

	//
	// Call the chisels on_capture_start callback
	//
	chisels_on_capture_start();

	//
	// Start the falco baseliner
	//
	const bool do_baseline_calculation = m_configuration->get_falco_baselining_enabled();
	if (do_baseline_calculation)
	{
		glogf("starting falco baselining");
		m_falco_baseliner->init();
		m_falco_baseliner->enable_baseline_calculation();
	}

#ifndef CYGWING_AGENT
	if (security_config::is_enabled() || m_use_new_k8s || m_prom_conf.enabled())
	{
		glogf("initializing infrastructure state");
		m_infrastructure_state->init(m_configuration->get_machine_id(),
		                             get_host_tags_with_cluster());

		// Before connecting make sure all annotations we need are registered
		// so that cointerface will know to send them
		auto add_annot = [this](const std::string& str) {
			m_infrastructure_state->add_annotation_filter(str);
		};
		// Annotations for Prometheus autodetection
		if (m_prom_conf.enabled())
			m_prom_conf.register_annotations(add_annot);
		// Annotations for Percentiles
		const auto pctl_conf = get_configuration_read_only()->get_group_pctl_conf();
		if (pctl_conf && pctl_conf->enabled())
		{
			pctl_conf->register_annotations(add_annot);
		}
		// Annotations for container filter
		const auto filters = m_configuration->get_container_filter();
		if (filters && filters->enabled())
		{
			filters->register_annotations(add_annot);
		}

		// K8s url to use
		if (!m_infrastructure_state->get_k8s_url().empty())
		{
			m_infrastructure_state->subscribe_to_k8s();
			glogf("infrastructure state is now subscribed to k8s API server");

			if (m_configuration->get_go_k8s_user_events())
			{
				init_k8s_user_event_handler();

				m_k8s_user_event_handler->subscribe(
				    infrastructure_state::c_k8s_timeout_s.get_value(),
				    m_configuration->get_k8s_event_filter());
				glogf("k8s event message handler is now subscribed to the k8s APi server");
			}
		}
	}

#endif
}

void sinsp_analyzer::init_k8s_user_event_handler()
{
	std::function<bool()> is_delegated = [this]() -> bool { return m_is_k8s_delegated; };
	if (!m_k8s_user_event_handler)
	{
		m_k8s_user_event_handler = new k8s_user_event_message_handler(
		    K8S_EVENTS_POLL_INTERVAL_NS,
		    m_root_dir,
		    is_delegated,
		    m_configuration->get_add_event_scopes() ? infra_state() : nullptr);
	}

	glogf("initializing k8s event message handler");
	m_k8s_user_event_handler->set_machine_id(m_configuration->get_machine_id());
	m_k8s_user_event_handler->set_user_event_queue(m_user_event_queue);
}

void sinsp_analyzer::add_chisel_dirs()
{
	m_inspector->add_chisel_dir((m_root_dir + "/share/chisels").c_str(), false);

	//
	// sysdig that comes with dragent is always installed in /usr
	//
	m_inspector->add_chisel_dir("/usr" CHISELS_INSTALLATION_DIR, false);

	//
	// Add the directories configured in the SYSDIG_CHISEL_DIR environment variable
	//
	char* s_user_cdirs = getenv("SYSDIG_CHISEL_DIR");

	if (s_user_cdirs != NULL)
	{
		vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

		for (uint32_t j = 0; j < user_cdirs.size(); j++)
		{
			m_inspector->add_chisel_dir(user_cdirs[j], true);
		}
	}
}

void sinsp_analyzer::initialize_chisels()
{
	for (auto it = m_chisels.begin(); it != m_chisels.end();)
	{
		try
		{
			(*it)->on_init();
			++it;
		}
		catch (sinsp_exception e)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": " + e.what(),
			             sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
		catch (...)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": unknown error",
			             sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
	}
}

void sinsp_analyzer::add_chisel(sinsp_chisel* ch)
{
	m_chisels.push_back(ch);
	m_run_chisels = true;
}

void sinsp_analyzer::add_chisel(sinsp_chisel_details* cd)
{
	try
	{
		sinsp_chisel* ch = new sinsp_chisel(m_inspector, cd->m_name);
		ch->set_args(cd->m_args);
		add_chisel(ch);
	}
	catch (sinsp_exception e)
	{
		g_logger.log("unable to start chisel " + cd->m_name + ": " + e.what(),
		             sinsp_logger::SEV_WARNING);
	}
	catch (...)
	{
		g_logger.log("unable to start chisel " + cd->m_name + ": unknown error",
		             sinsp_logger::SEV_WARNING);
	}
}

void sinsp_analyzer::chisels_on_capture_start()
{
	for (auto it = m_chisels.begin(); it != m_chisels.end();)
	{
		try
		{
			(*it)->on_capture_start();
			++it;
		}
		catch (sinsp_exception e)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": " + e.what(),
			             sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
		catch (...)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": unknown error",
			             sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
	}
}

void sinsp_analyzer::chisels_on_capture_end()
{
	for (vector<sinsp_chisel*>::iterator it = m_chisels.begin(); it != m_chisels.end(); ++it)
	{
		(*it)->on_capture_end();
	}
}

void sinsp_analyzer::chisels_do_timeout(sinsp_evt* ev)
{
	for (vector<sinsp_chisel*>::iterator it = m_chisels.begin(); it != m_chisels.end(); ++it)
	{
		(*it)->do_timeout(ev);
	}
}

#ifndef CYGWING_AGENT
class mesos_conf_vals : public app_process_conf_vals
{
public:
	mesos_conf_vals(const uri::credentials_t& dcos_enterprise_credentials,
	                const uri::credentials_t& mesos_credentials,
	                const string& mesos_state_uri,
	                const string& auth_hostname)
	    : m_mesos_credentials(mesos_credentials),
	      m_auth(dcos_enterprise_credentials, auth_hostname)
	{
		auto protocol = dcos_enterprise_credentials.first.empty() ? "http" : "https";

		m_mesos_url = protocol + string("://") + uri(mesos_state_uri).get_host();
	};

	virtual ~mesos_conf_vals(){};

	Json::Value vals()
	{
		Json::Value conf_vals = Json::objectValue;

		conf_vals["auth_token"] = m_auth.get_token();
		conf_vals["mesos_url"] = m_mesos_url;
		conf_vals["mesos_creds"] = m_mesos_credentials.first + ":" + m_mesos_credentials.second;

		return conf_vals;
	}

private:
	const uri::credentials_t& m_mesos_credentials;
	string m_mesos_url;
	mesos_auth m_auth;
};

class marathon_conf_vals : public app_process_conf_vals
{
public:
	marathon_conf_vals(const uri::credentials_t& dcos_enterprise_credentials,
	                   const uri::credentials_t& marathon_credentials,
	                   const string& marathon_uri,
	                   const string& auth_hostname)
	    : m_marathon_credentials(marathon_credentials),
	      m_auth(dcos_enterprise_credentials, auth_hostname),
	      m_protocol(dcos_enterprise_credentials.first.empty() ? "http" : "https")
	{
		// Marathon listens on both http and https ports, so we embed
		// the port in the url depending on whether we're using http
		// or https.
		m_marathon_url = m_protocol + string("://") + uri(marathon_uri).get_host() + ":" +
		                 (m_protocol == "http" ? "8080" : "8443");
	};

	virtual ~marathon_conf_vals(){};

	const string& protocol() { return m_protocol; }

	Json::Value vals()
	{
		Json::Value conf_vals = Json::objectValue;

		conf_vals["auth_token"] = m_auth.get_token();
		conf_vals["marathon_url"] = m_marathon_url;
		conf_vals["marathon_creds"] =
		    m_marathon_credentials.first + ":" + m_marathon_credentials.second;

		return conf_vals;
	}

private:
	const uri::credentials_t& m_marathon_credentials;
	mesos_auth m_auth;
	string m_protocol;
	string m_marathon_url;
};
#endif  // CYGWING_AGENT

sinsp_configuration* sinsp_analyzer::get_configuration()
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if (m_inspector->m_h != NULL)
	{
		ASSERT(false);
		std::string err = "Attempting to get the configuration while the inspector is capturing";
		g_logger.log(err, sinsp_logger::SEV_ERROR);
		throw sinsp_exception(err);
	}

	return m_configuration;
}

const sinsp_configuration* sinsp_analyzer::get_configuration_read_only()
{
	return m_configuration;
}

void sinsp_analyzer::set_configuration(const sinsp_configuration& configuration)
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if (m_inspector->m_h != NULL)
	{
		ASSERT(false);
		std::string err = "Attempting to set the configuration while the inspector is capturing";
		g_logger.log(err, sinsp_logger::SEV_ERROR);
		throw sinsp_exception(err);
	}

	*m_configuration = configuration;
}

void sinsp_analyzer::remove_expired_connections(uint64_t ts)
{
	if (!m_simpledriver_enabled)
	{
		m_ipv4_connections->remove_expired_connections(ts);
	}
}

sinsp_connection* sinsp_analyzer::get_connection(const ipv4tuple& tuple, uint64_t timestamp)
{
	sinsp_connection* connection = m_ipv4_connections->get_connection(tuple, timestamp);
	if (NULL == connection)
	{
		// try to find the connection with source/destination reversed
		ipv4tuple tuple_reversed;
		tuple_reversed.m_fields.m_sip = tuple.m_fields.m_dip;
		tuple_reversed.m_fields.m_dip = tuple.m_fields.m_sip;
		tuple_reversed.m_fields.m_sport = tuple.m_fields.m_dport;
		tuple_reversed.m_fields.m_dport = tuple.m_fields.m_sport;
		tuple_reversed.m_fields.m_l4proto = tuple.m_fields.m_l4proto;
		connection = m_ipv4_connections->get_connection(tuple_reversed, timestamp);
		if (NULL != connection)
		{
			((ipv4tuple*)&tuple)->m_fields = tuple_reversed.m_fields;
		}
	}

	return connection;
}

void sinsp_analyzer::secure_audit_data_ready(const uint64_t ts,
                                             const secure::Audit* const secure_audits)
{
	m_secure_audit_handler.secure_audit_data_ready(ts, secure_audits);
}

void sinsp_analyzer::set_secure_audit_internal_metrics(const int n_sent_protobufs,
                                                       const uint64_t flush_time_ms)
{
	m_internal_metrics->set_secure_audit_n_sent_protobufs(n_sent_protobufs);
	m_internal_metrics->set_secure_audit_fl_ms(flush_time_ms);
}

void sinsp_analyzer::set_secure_audit_sent_counters(int n_executed_commands,
                                                    int n_connections,
                                                    int n_k8s,
                                                    int n_file_accesses,
                                                    int n_executed_commands_dropped,
                                                    int n_connections_dropped,
                                                    int n_k8s_dropped,
                                                    int n_file_accesses_dropped,
                                                    int n_connections_not_interactive_dropped,
                                                    int n_file_accesses_not_interactive_dropped,
                                                    int n_k8s_enrich_errors)
{
	m_internal_metrics->set_secure_audit_executed_commands_count(n_executed_commands);
	m_internal_metrics->set_secure_audit_connections_count(n_connections);
	m_internal_metrics->set_secure_audit_k8s_count(n_k8s);
	m_internal_metrics->set_secure_audit_executed_commands_dropped_count(
	    n_executed_commands_dropped);
	m_internal_metrics->set_secure_audit_file_accesses_count(n_file_accesses);

	m_internal_metrics->set_secure_audit_connections_dropped_count(n_connections_dropped);
	m_internal_metrics->set_secure_audit_file_accesses_dropped_count(n_file_accesses_dropped);
	m_internal_metrics->set_secure_audit_k8s_dropped_count(n_k8s_dropped);
	m_internal_metrics->set_secure_audit_connections_not_interactive_dropped(
	    n_connections_not_interactive_dropped);
	m_internal_metrics->set_secure_audit_file_accesses_not_interactive_dropped(
	    n_file_accesses_not_interactive_dropped);
	m_internal_metrics->set_secure_audit_k8s_enrich_errors(n_k8s_enrich_errors);
}

template<class Iterator>
void sinsp_analyzer::filter_top_programs_normaldriver_deprecated(Iterator progtable_begin,
                                                                 Iterator progtable_end,
                                                                 bool cs_only,
                                                                 uint32_t howmany)
{
	uint32_t j;

	vector<THREAD_TYPE*> prog_sortable_list;

	for (auto ptit = progtable_begin; ptit != progtable_end; (++ptit))
	{
		if (cs_only)
		{
			int is_cs = ((*ptit)->m_ainfo->m_th_analysis_flags &
			             (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
			              thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
			              thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT |
			              thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT));

			if (is_cs)
			{
				prog_sortable_list.push_back(*ptit);
			}
		}
		else
		{
			prog_sortable_list.push_back(*ptit);
		}
	}

	if (prog_sortable_list.size() <= howmany)
	{
		for (j = 0; j < prog_sortable_list.size(); j++)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}

		return;
	}

	//
	// Mark the top CPU consumers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             (cs_only) ? threadinfo_cmp_cpu_cs : threadinfo_cmp_cpu);

	for (j = 0; j < howmany; j++)
	{
		if (GET_AGENT_THREAD(prog_sortable_list[j])->m_cpuload > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top memory consumers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             (cs_only) ? threadinfo_cmp_memory_cs : threadinfo_cmp_memory);

	for (j = 0; j < howmany; j++)
	{
		if (prog_sortable_list[j]->m_vmsize_kb > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top disk I/O consumers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             (cs_only) ? threadinfo_cmp_io_cs : threadinfo_cmp_io);

	for (j = 0; j < howmany; j++)
	{
		ASSERT(GET_AGENT_THREAD(prog_sortable_list[j])->m_procinfo != NULL);

		if (GET_AGENT_THREAD(prog_sortable_list[j])
		        ->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top network I/O consumers
	//
	// does not work on NODRIVER mode
	if (!m_inspector->is_nodriver())
	{
		partial_sort(prog_sortable_list.begin(),
		             prog_sortable_list.begin() + howmany,
		             prog_sortable_list.end(),
		             (cs_only) ? threadinfo_cmp_net_cs : threadinfo_cmp_net);

		for (j = 0; j < howmany; j++)
		{
			ASSERT(GET_AGENT_THREAD(prog_sortable_list[j])->m_procinfo != NULL);

			if (GET_AGENT_THREAD(prog_sortable_list[j])
			        ->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0)
			{
				GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
			}
			else
			{
				break;
			}
		}
	}
}

//
// The simple driver only captures a very limited number of system calls, like clone, execve,
// connect and accept. As a consequence, process filtering needs to use simpler criteria.
//
template<class Iterator>
void sinsp_analyzer::filter_top_programs_simpledriver_deprecated(Iterator progtable_begin,
                                                                 Iterator progtable_end,
                                                                 bool cs_only,
                                                                 uint32_t howmany)
{
	uint32_t j;

	vector<THREAD_TYPE*> prog_sortable_list;

	for (auto ptit = progtable_begin; ptit != progtable_end; (++ptit))
	{
		if (cs_only)
		{
			uint64_t netops = GET_AGENT_THREAD((*ptit))->m_procinfo->m_proc_metrics.m_net.m_count;

			if (netops != 0)
			{
				prog_sortable_list.push_back(*ptit);
			}
		}
		else
		{
			prog_sortable_list.push_back(*ptit);
		}
	}

	if (prog_sortable_list.size() <= howmany)
	{
		for (j = 0; j < prog_sortable_list.size(); j++)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}

		return;
	}

	//
	// Mark the top CPU consumers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             (cs_only) ? threadinfo_cmp_cpu_cs : threadinfo_cmp_cpu);

	for (j = 0; j < howmany; j++)
	{
		if (GET_AGENT_THREAD(prog_sortable_list[j])->m_cpuload > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top memory consumers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             (cs_only) ? threadinfo_cmp_memory_cs : threadinfo_cmp_memory);

	for (j = 0; j < howmany; j++)
	{
		if (prog_sortable_list[j]->m_vmsize_kb > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top syscall producers
	//
	partial_sort(prog_sortable_list.begin(),
	             prog_sortable_list.begin() + howmany,
	             prog_sortable_list.end(),
	             threadinfo_cmp_evtcnt);

	for (j = 0; j < howmany; j++)
	{
		ASSERT(GET_AGENT_THREAD(prog_sortable_list[j])->m_procinfo != NULL);

		if (GET_AGENT_THREAD(prog_sortable_list[j])
		        ->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0)
		{
			GET_AGENT_THREAD(prog_sortable_list[j])->set_exclude_from_sample(false);
		}
		else
		{
			break;
		}
	}
}

template<class Iterator>
void sinsp_analyzer::filter_top_programs_deprecated(Iterator progtable_begin,
                                                    Iterator progtable_end,
                                                    bool cs_only,
                                                    uint32_t howmany)
{
	if (m_simpledriver_enabled)
	{
		filter_top_programs_simpledriver_deprecated(progtable_begin,
		                                            progtable_end,
		                                            cs_only,
		                                            howmany);
	}
	else
	{
		filter_top_programs_normaldriver_deprecated(progtable_begin,
		                                            progtable_end,
		                                            cs_only,
		                                            howmany);
	}
}

string sinsp_analyzer::detect_local_server(const string& protocol,
                                           uint32_t port,
                                           server_check_func_t check_func)
{
	if (m_inspector && m_inspector->m_network_interfaces)
	{
		for (const auto& iface : *m_inspector->m_network_interfaces->get_ipv4_list())
		{
			std::string addr(protocol);
			addr.append("://").append(iface.address()).append(1, ':').append(std::to_string(port));
			if ((this->*check_func)(addr))
			{
				return addr;
			}
		}
	}
	else
	{
		g_logger.log("Local server detection failed.", sinsp_logger::SEV_ERROR);
	}
	return "";
}

#ifndef CYGWING_AGENT
bool sinsp_analyzer::check_mesos_server(string& addr)
{
	uri url(addr);
	url.set_path(mesos::default_version_api);
	g_logger.log("Preparing to detect Mesos at [" + url.to_string(false) + "] ...",
	             sinsp_logger::SEV_TRACE);
	const mesos::credentials_t& creds = m_configuration->get_mesos_credentials();
	if (!creds.first.empty())
	{
		url.set_credentials(creds);
	}
	Json::Value root;
	Json::Reader reader;
	sinsp_curl sc(url, 500);
	sc.setopt(CURLOPT_SSL_VERIFYPEER, 0);
	sc.setopt(CURLOPT_SSL_VERIFYHOST, 0);
	if (reader.parse(sc.get_data(false), root))
	{
		g_logger.log("Detecting Mesos at [" + url.to_string(false) + ']', sinsp_logger::SEV_DEBUG);
		Json::Value ver = root["version"];
		if (!ver.isNull() && ver.isString())
		{
			if (!ver.asString().empty())
			{
				// Change path, to state api instead of version
				url.set_path(mesos::default_state_api);
				addr = url.to_string(true);
				m_configuration->set_mesos_state_uri(addr);  // set globally in config
				return true;
			}
		}
	}
	return false;
}

void sinsp_analyzer::make_mesos(string&& json)
{
	Json::Value root;
	Json::Reader reader;
	if (reader.parse(json, root, false))
	{
		Json::Value ver = root["version"];
		if (!ver.isNull())
		{
			const std::string& version = ver.asString();
			if (!version.empty())
			{
				string mesos_state = m_configuration->get_mesos_state_uri();
				vector<string> marathon_uris = m_configuration->get_marathon_uris();

				g_logger.log("Mesos master version [" + version + "] found at " +
				                 uri(mesos_state).to_string(false),
				             sinsp_logger::SEV_INFO);
				g_logger.log("Mesos state: [" +
				                 uri(mesos_state + mesos::default_state_api).to_string(false) + ']',
				             sinsp_logger::SEV_INFO);
				for (const auto& marathon_uri : marathon_uris)
				{
					g_logger.log(
					    "Mesos (Marathon) groups: [" +
					        uri(marathon_uri + mesos::default_groups_api).to_string(false) + ']',
					    sinsp_logger::SEV_INFO);
					g_logger.log("Mesos (Marathon) apps: [" +
					                 uri(marathon_uri + mesos::default_apps_api).to_string(false) +
					                 ']',
					             sinsp_logger::SEV_INFO);
				}

				m_mesos_present = true;
				if (m_mesos)
				{
					m_mesos.reset();
				}
				if (!m_configuration->get_dcos_enterprise_credentials().first.empty())
				{
					m_mesos.reset(new mesos(mesos_state,
					                        marathon_uris,
					                        m_configuration->get_mesos_follow_leader(),
					                        m_configuration->get_marathon_follow_leader(),
					                        m_configuration->get_dcos_enterprise_credentials(),
					                        m_configuration->get_mesos_timeout_ms()));
				}
				else
				{
					m_mesos.reset(new mesos(mesos_state,
					                        marathon_uris,
					                        m_configuration->get_mesos_follow_leader(),
					                        m_configuration->get_marathon_follow_leader(),
					                        m_configuration->get_mesos_credentials(),
					                        m_configuration->get_marathon_credentials(),
					                        m_configuration->get_mesos_timeout_ms()));
				}
				time(&m_last_mesos_refresh);
			}
		}
	}
}

void sinsp_analyzer::get_mesos(const string& mesos_uri)
{
	m_mesos.reset();
	uri url(mesos_uri);
	url.set_path(mesos::default_version_api);
	long tout = m_configuration->get_mesos_timeout_ms();

	try
	{
		sinsp_curl sc(url, tout);
		sc.setopt(CURLOPT_SSL_VERIFYPEER, 0);
		sc.setopt(CURLOPT_SSL_VERIFYHOST, 0);
		std::string json = sc.get_data();
		url.set_path(mesos::default_state_api);
		m_configuration->set_mesos_state_uri(url.to_string(true));
		make_mesos(std::move(json));
	}
	catch (std::exception& ex)
	{
		g_logger.log("Error connecting to Mesos at [" + uri(mesos_uri).to_string(false) +
		                 "]. Error: " + ex.what(),
		             sinsp_logger::SEV_ERROR);
	}
}

sinsp_analyzer::k8s_ext_list_ptr_t sinsp_analyzer::k8s_discover_ext(const std::string& k8s_api)
{
	const k8s_ext_list_t& ext_list = m_configuration->get_k8s_extensions();
	if (ext_list.size())
	{
		m_ext_list_ptr.reset(new k8s_ext_list_t(ext_list));
		m_k8s_ext_detect_done = true;
	}
	else
	{
		try
		{
			if (!m_k8s && !m_k8s_ext_detect_done)
			{
				g_logger.log("K8s API extensions handler: detecting extensions.",
				             sinsp_logger::SEV_TRACE);
				if (!m_k8s_ext_handler)
				{
					if (!m_k8s_collector)
					{
						m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
					}
					if (uri(k8s_api).is_secure())
					{
						init_k8s_ssl(k8s_api);
					}
					m_k8s_ext_handler.reset(new k8s_api_handler(m_k8s_collector,
					                                            k8s_api,
					                                            "/apis/extensions/v1beta1",
					                                            "[.resources[].name]",
					                                            "1.1",
					                                            m_k8s_ssl,
					                                            m_k8s_bt,
					                                            false));
					g_logger.log("K8s API extensions handler: collector created.",
					             sinsp_logger::SEV_TRACE);
					return nullptr;
				}
				else
				{
					g_logger.log("K8s API extensions handler: collecting data.",
					             sinsp_logger::SEV_TRACE);
					m_k8s_ext_handler->collect_data();
					if (m_k8s_ext_handler->connection_error())
					{
						throw sinsp_exception(" connection error.");
					}
					else if (m_k8s_ext_handler->ready())
					{
						g_logger.log("K8s API extensions handler: data received.",
						             sinsp_logger::SEV_TRACE);
						if (m_k8s_ext_handler->error())
						{
							g_logger.log(
							    "K8s API extensions handler: data error occurred while detecting "
							    "API extensions.",
							    sinsp_logger::SEV_WARNING);
							m_ext_list_ptr.reset();
						}
						else
						{
							const k8s_api_handler::api_list_t& exts =
							    m_k8s_ext_handler->extensions();
							std::ostringstream ostr;
							k8s_ext_list_t ext_list;
							for (const auto& ext : exts)
							{
								ext_list.insert(ext);
								ostr << std::endl << ext;
							}
							if (g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
							{
								g_logger.log(
								    "K8s API extensions handler: extensions found: " + ostr.str(),
								    sinsp_logger::SEV_DEBUG);
							}
							else
							{
								g_logger.log("K8s API extensions detected: " + ostr.str(),
								             sinsp_logger::SEV_INFO);
							}
							m_ext_list_ptr.reset(new k8s_ext_list_t(ext_list));
						}
						m_k8s_ext_detect_done = true;
						m_k8s_collector.reset();
						m_k8s_ext_handler.reset();
					}
					else
					{
						g_logger.log("K8s API extensions handler: not ready.",
						             sinsp_logger::SEV_TRACE);
						return nullptr;
					}
				}
			}
		}
		catch (std::exception& ex)
		{
			static time_t last_attempt;
			reset_k8s(last_attempt,
			          std::string("K8s API extensions handler error: ").append(ex.what()));
			throw;
		}
	}
	return m_ext_list_ptr;
}

void sinsp_analyzer::init_k8s_ssl(const uri& url)
{
	if (url.is_secure() && !m_k8s_ssl)
	{
		const std::string& cert = m_infrastructure_state->get_k8s_ssl_certificate();
		const std::string& key = m_infrastructure_state->get_k8s_ssl_key();
		const std::string& key_pwd = infrastructure_state::c_k8s_ssl_key_password->get_value();
		const std::string& ca_cert = m_infrastructure_state->get_k8s_ca_certificate();
		bool verify_cert = infrastructure_state::c_k8s_ssl_verify_certificate.get_value();
		const std::string& cert_type = infrastructure_state::c_k8s_ssl_certificate_type.get_value();
		m_k8s_ssl =
		    std::make_shared<sinsp_ssl>(cert, key, key_pwd, ca_cert, verify_cert, cert_type);
	}
	const std::string& bt_auth_token = m_infrastructure_state->get_k8s_bt_auth_token();
	if (!bt_auth_token.empty() && !m_k8s_bt)
	{
		m_k8s_bt = std::make_shared<sinsp_bearer_token>(bt_auth_token);
	}
}

k8s* sinsp_analyzer::get_k8s(const uri& k8s_api, const std::string& msg)
{
	try
	{
		if (k8s_api.is_secure())
		{
			init_k8s_ssl(k8s_api);
		}
		k8s_discover_ext(k8s_api.to_string());
		if (m_k8s_ext_detect_done)
		{
			m_k8s_ext_detect_done = false;
			g_logger.log(msg, sinsp_logger::SEV_INFO);
			return new k8s(k8s_api.to_string(),
			               false /*not captured*/,
			               m_k8s_ssl,
			               m_k8s_bt,
			               false,
			               m_configuration->get_k8s_event_filter(),
			               m_ext_list_ptr,
			               m_use_new_k8s);
		}
	}
	catch (std::exception& ex)
	{
		static time_t last_connect_attempt;
		time_t now;
		time(&now);
		if (difftime(now, last_connect_attempt) > m_k8s_retry_seconds)
		{
			last_connect_attempt = now;
			g_logger.log(std::string("K8s framework creation error: ").append(ex.what()),
			             sinsp_logger::SEV_ERROR);
		}
	}
	return nullptr;
}

uint32_t sinsp_analyzer::get_mesos_api_server_port(THREAD_TYPE* main_tinfo)
{
	if (main_tinfo)
	{
		if (main_tinfo->m_exe.find("mesos-master") != std::string::npos)
		{
			return MESOS_MASTER_PORT;
		}
		else if (main_tinfo->m_exe.find("mesos-slave") != std::string::npos)
		{
			return MESOS_SLAVE_PORT;
		}
		else if (main_tinfo->m_exe.find("mesos-agent") != std::string::npos)
		{
			return MESOS_SLAVE_PORT;
		}
	}
	return 0;
}

std::string& sinsp_analyzer::detect_mesos(std::string& mesos_api_server, uint32_t port)
{
	if (!m_mesos)
	{
		auto protocol =
		    m_configuration->get_dcos_enterprise_credentials().first.empty() ? "http" : "https";
		mesos_api_server = detect_local_server(protocol, port, &sinsp_analyzer::check_mesos_server);
		if (!mesos_api_server.empty())
		{
			m_configuration->set_mesos_state_uri(mesos_api_server);

			// If the port is not 5050, this uri is for a
			// slave/agent, in which case we only record
			// the uri to pass along to the app check.
			if (port == MESOS_MASTER_PORT)
			{
				g_logger.log("Mesos API server set to: " + uri(mesos_api_server).to_string(false),
				             sinsp_logger::SEV_INFO);
				m_configuration->set_mesos_follow_leader(true);
				if (m_configuration->get_marathon_uris().empty())
				{
					m_configuration->set_marathon_follow_leader(true);
				}
				g_logger.log("Mesos API server failover discovery enabled for: " + mesos_api_server,
				             sinsp_logger::SEV_INFO);
			}
		}
		else
		{
			// not to flood logs, log only once a minute
			static time_t last_log;
			time_t now;
			time(&now);
			if (m_mesos_present && (difftime(now, last_log) > m_detect_retry_seconds))
			{
				last_log = now;
				g_logger.log("Mesos API server not found.", sinsp_logger::SEV_WARNING);
			}
		}
	}
	return mesos_api_server;
}

THREAD_TYPE* sinsp_analyzer::get_main_thread_info(int64_t& tid)
{
	if (tid != -1)
	{
		sinsp_threadinfo* sinsp_thread = m_inspector->m_thread_manager->m_threadtable.get(tid);
		if (sinsp_thread != nullptr)
		{
			sinsp_threadinfo* main_thread = sinsp_thread->get_main_thread();
#ifdef USE_AGENT_THREAD
			thread_analyzer_info* analyzer_main_thread =
			    dynamic_cast<thread_analyzer_info*>(main_thread);
			ASSERT(analyzer_main_thread == main_thread);
			return analyzer_main_thread;
#else
			return main_thread;
#endif
		}
		else
		{
			tid = -1;
		}
	}
	return nullptr;
}

std::string sinsp_analyzer::detect_mesos(THREAD_TYPE* main_tinfo)
{
	string mesos_api_server = m_configuration->get_mesos_state_uri();
	if (!m_mesos)
	{
		if ((mesos_api_server.empty() || m_configuration->get_mesos_state_original_uri().empty()) &&
		    m_configuration->get_mesos_autodetect_enabled())
		{
			if (!main_tinfo)
			{
				main_tinfo = get_main_thread_info(m_mesos_master_tid);
				if (!main_tinfo)
				{
					main_tinfo = get_main_thread_info(m_mesos_slave_tid);
				}
			}
			if (main_tinfo)
			{
				uint32_t port = get_mesos_api_server_port(main_tinfo);
				if (port != 0)
				{
					detect_mesos(mesos_api_server, port);
				}
			}
		}
	}
	return mesos_api_server;
}
#endif  // CYGWING_AGENT

void sinsp_analyzer::update_percentile_data_serialization(
    const analyzer_emitter::progtable_by_container_t& progtable_by_container)
{
	// enable/disable percentile data serialization for configured containers
#ifndef CYGWING_AGENT
	const auto conf = get_configuration_read_only()->get_group_pctl_conf();
	if (conf)
	{
		m_containers_check_interval.run(
		    [this, &progtable_by_container, &conf]() {
			    g_logger.format(sinsp_logger::SEV_INFO,
			                    "Performing percentile data serialization check for containers");
			    const auto containers_info = m_inspector->m_container_manager.get_containers();
			    uint32_t n_matched = 0;
			    for (auto& it : m_containers)
			    {
				    auto cinfo_it = containers_info->find(it.first);
				    if (cinfo_it == containers_info->end())
				    {
					    continue;
				    }
				    auto is_match = n_matched < conf->max_containers() &&
				                    conf->match(cinfo_it->second.get(), *infra_state());
				    it.second.set_serialize_pctl_data(is_match);
				    if (is_match)
				    {
					    g_logger.format(sinsp_logger::SEV_DEBUG,
					                    "Percentile data serialization enabled for container: %s",
					                    cinfo_it->second->m_name.c_str());
					    ++n_matched;
				    }
			    }
		    },
		    m_prev_flush_time_ns);
	}
#endif  // CYGWING_AGENT
}

void sinsp_analyzer::gather_k8s_infrastructure_state(uint32_t flush_flags,
                                                     const vector<string>& emitted_containers)
{
#ifndef CYGWING_AGENT
	if (!m_use_new_k8s)
	{
		return;
	}

	if (!m_infrastructure_state->subscribed())
	{
		return;
	}

	if (flush_flags == analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		return;
	}

	std::string cluster_name = get_k8s_cluster_name();
	auto cluster_id = m_infrastructure_state->get_k8s_cluster_id();

	// if cluster_id is empty, better to don't send anything since
	// the backend relies on this field
	if (cluster_id.empty())
	{
		return;
	}

	++m_flushes_since_k8_local_flush;
	if (m_flushes_since_k8_local_flush >= m_k8s_local_update_frequency)
	{
		m_flushes_since_k8_local_flush = 0;
		// Try to find out our k8s node id & name
		m_infrastructure_state->find_our_k8s_node(&emitted_containers);

		if (c_new_k8s_local_export_format.get_value() == k8s_export_format::DEDICATED)
		{
			g_logger.log("sinsp_analyzer:: Emitting k8s metadata for local node (local_kubernetes)",
			             sinsp_logger::SEV_DEBUG);

			auto k8s_state = m_metrics->mutable_local_kubernetes();
			// Build the orchestrator state of the emitted containers (without metrics)
			// This is the k8 data for the local node
			k8s_state->set_cluster_id(cluster_id);
			k8s_state->set_cluster_name(cluster_name);
			m_infrastructure_state->state_of(emitted_containers, k8s_state, m_prev_flush_time_ns);
			check_dump_infrastructure_state(*k8s_state,
			                                "local",
			                                m_dump_local_infrastructure_state_on_next_flush);
		}
		else
		{
			g_logger.log("sinsp_analyzer:: Emitting k8s metadata for local node (congroups)",
			             sinsp_logger::SEV_DEBUG);

			auto k8s_state = m_metrics->mutable_orchestrator_state();
			// Build the orchestrator state of the emitted containers (without metrics)
			// This is the k8 data for the local node
			k8s_state->set_cluster_id(cluster_id);
			k8s_state->set_cluster_name(cluster_name);
			m_infrastructure_state->state_of(emitted_containers,
			                                 k8s_state->mutable_groups(),
			                                 m_prev_flush_time_ns);
			check_dump_infrastructure_state(*k8s_state,
			                                "local",
			                                m_dump_local_infrastructure_state_on_next_flush);
		}
	}

	// Check whether this node is a delegate node. If it is then it is
	// responsible for sending k8 metadata for the entire cluster.
	if (!check_k8s_delegation())
	{
		return;
	}

	++m_flushes_since_k8_cluster_flush;
	if (m_flushes_since_k8_cluster_flush >= m_k8s_cluster_update_frequency)
	{
		// if this agent is a delegated node, build & send the complete orchestrator state too (with
		// metrics this time)

		m_flushes_since_k8_cluster_flush = 0;
		if (c_new_k8s_global_export_format.get_value() == k8s_export_format::DEDICATED)
		{
			g_logger.log("sinsp_analyzer:: Emitting k8s metadata for cluster (global_kubernetes)",
			             sinsp_logger::SEV_DEBUG);
			auto k8s_state = m_metrics->mutable_global_kubernetes();

			k8s_state->set_cluster_id(cluster_id);
			k8s_state->set_cluster_name(cluster_name);
			m_infrastructure_state->get_state(k8s_state, m_prev_flush_time_ns);
			check_dump_infrastructure_state(*k8s_state,
			                                "global",
			                                m_dump_global_infrastructure_state_on_next_flush);
		}
		else
		{
			g_logger.log("sinsp_analyzer:: Emitting k8s metadata for cluster (congroups)",
			             sinsp_logger::SEV_DEBUG);
			auto k8s_state = m_metrics->mutable_global_orchestrator_state();

			k8s_state->set_cluster_id(cluster_id);
			k8s_state->set_cluster_name(cluster_name);
			m_infrastructure_state->get_state(k8s_state->mutable_groups(), m_prev_flush_time_ns);
			check_dump_infrastructure_state(*k8s_state,
			                                "global",
			                                m_dump_global_infrastructure_state_on_next_flush);
		}
	}
#endif
}

void sinsp_analyzer::clean_containers(
    const analyzer_emitter::progtable_by_container_t& progtable_by_container)
{
	m_containers_cleaner_interval.run(
	    [this, &progtable_by_container]() {
		    g_logger.format(sinsp_logger::SEV_INFO, "Flushing analyzer container table");
		    auto it = this->m_containers.begin();
		    while (it != this->m_containers.end())
		    {
			    if (progtable_by_container.find(it->first) == progtable_by_container.end())
			    {
				    it = this->m_containers.erase(it);
			    }
			    else
			    {
				    ++it;
			    }
		    }
	    },
	    m_prev_flush_time_ns);
}

void sinsp_analyzer::emit_processes_deprecated(
    std::set<uint64_t>& all_uids,
    analyzer_emitter::flush_flags flushflags,
    const analyzer_emitter::progtable_t& progtable,
    const analyzer_emitter::progtable_by_container_t& progtable_by_container,
    const std::vector<std::string>& emitted_containers,
    tracer_emitter& proc_trc,
    jmx_emitter& jmx_emitter_instance,
    environment_emitter& environment_emitter_instance,
    process_emitter& process_emitter_instance)
{
	bool progtable_needs_filtering = false;

	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "progtable size: %u", progtable.size());
	}

	//
	// Filter out the programs that didn't generate enough activity to go in the sample.
	// Note: we only do this when we're live, because in offline captures we don't have
	//       process CPU and memory.
	//
	if (!m_inspector->is_capture())
	{
		tracer_emitter filter_trc("filter_progtable", proc_trc);
		progtable_needs_filtering = progtable.size() > m_top_processes_in_sample;
		if (progtable_needs_filtering)
		{
			// Filter top active programs
			filter_top_programs_deprecated(progtable.begin(),
			                               progtable.end(),
			                               false,
			                               m_top_processes_in_sample);
			// Filter top client/server programs
			filter_top_programs_deprecated(progtable.begin(),
			                               progtable.end(),
			                               true,
			                               m_top_processes_in_sample);
			// Add at least one process per emitted_container
			for (const auto& container_id : emitted_containers)
			{
				auto progs_it = progtable_by_container.find(container_id);
				if (progs_it != progtable_by_container.end())
				{
					auto progs = progs_it->second;
					filter_top_programs_deprecated(progs.begin(),
					                               progs.end(),
					                               false,
					                               m_top_processes_per_container);
				}
			}
			// Add all processes with appcheck metrics
			if (process_manager::c_always_send_app_checks.get_value())
			{
				for (auto prog : progtable)
				{
					if (GET_AGENT_THREAD(prog)->get_exclude_from_sample() &&
					    m_app_checks_proxy->have_metrics_for_pid(prog->m_pid))
					{
						g_logger.format(sinsp_logger::SEV_DEBUG,
						                "Added pid %d with appcheck metrics to top processes",
						                prog->m_pid);
						GET_AGENT_THREAD(prog)->set_exclude_from_sample(false);
					}
				}
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// Second pass of the list of threads: aggregate threads into processes
	// or programs.
	///////////////////////////////////////////////////////////////////////////
	tracer_emitter at_trc("aggregate_threads", proc_trc);
	for (auto it = progtable.begin(); it != progtable.end(); ++it)
	{
		THREAD_TYPE* tinfo = *it;

		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
		sinsp_procinfo* procinfo = GET_AGENT_THREAD(tinfo)->m_procinfo;

		sinsp_counter_time tot;

		ASSERT(procinfo != NULL);

		procinfo->m_proc_metrics.get_total(&tot);

		//
		// Inclusion logic
		//
		// Keep:
		//  - top 30 clients/servers
		//  - top 30 programs that were active

		if (!GET_AGENT_THREAD(tinfo)->get_exclude_from_sample() || !progtable_needs_filtering)
		{
			draiosproto::program* prog = m_metrics->add_programs();

			process_emitter_instance.emit_process(
			    *tinfo,
			    *prog,
			    progtable_by_container,
			    *procinfo,
			    tot,
			    *m_metrics,
			    all_uids,
			    false /*legacy reporting doesn't support priorities*/);
		}

		//
		// Clear the thread metrics, so we're ready for the next sample
		//
		GET_AGENT_THREAD(tinfo)->clear_all_metrics();
	}
	at_trc.stop();
}

void sinsp_analyzer::emit_processes(sinsp_evt* evt,
                                    uint64_t sample_duration,
                                    bool is_eof,
                                    analyzer_emitter::flush_flags flushflags,
                                    const tracer_emitter& f_trc)
{
	tracer_emitter proc_trc("emit_processes", f_trc);
	tracer_emitter init_trc("init", proc_trc);
	int64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;
	m_server_programs.clear();
	analyzer_emitter::progtable_t progtable(m_top_processes_in_sample,
	                                        sinsp_threadinfo::hasher(),
	                                        sinsp_threadinfo::comparer());
	analyzer_emitter::progtable_by_container_t progtable_by_container;
#ifndef _WIN32
	vector<THREAD_TYPE*> java_process_requests;
	vector<app_process> app_checks_processes;
	bool can_disable_nodriver = true;
#ifndef CYGWING_AGENT
	vector<prom_process> prom_procs;
#endif
	init_trc.stop();

	// Get metrics from JMX until we found id 0 or timestamp-1
	// with id 0, means that sdjagent is not working or metrics are not ready
	// id = timestamp-1 are what we need now
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		if (m_jmx_proxy)
		{
			tracer_emitter jmx_trc("jmx_metrics", proc_trc);
			auto jmx_metrics = m_jmx_proxy->read_metrics(m_metric_limits);
			if (!jmx_metrics.empty())
			{
				// m_jmx_metrics is cleared by flush() because they are used
				// by falco baseliner, outside emit_processes
				m_jmx_metrics = move(jmx_metrics);
			}
		}
		if (m_app_checks_proxy)
		{
			auto flush_time_s = m_prev_flush_time_ns / ONE_SECOND_IN_NS;
			m_app_checks_proxy->refresh_metrics(flush_time_s, 0);
		}
	}
#endif

	tracer_emitter stats_trc("stats", proc_trc);
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "thread table size:%d",
		                m_inspector->m_thread_manager->get_thread_count());
	}

	if (m_ipv4_connections->get_n_drops() != 0)
	{
		if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "IPv4 table size:%d",
			                m_ipv4_connections->m_connections.size());
		}

		m_ipv4_connections->clear_n_drops();
	}
	stats_trc.stop();

	//
	// Snapshot global CPU state
	// (used as the reference value to calculate process CPU usages in the threadtable loop)
	//
#ifndef CYGWING_AGENT
	tracer_emitter jiffies_trc("jiffies", proc_trc);
	if (!m_inspector->is_capture() &&
	    (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT) && !m_skip_proc_parsing)
	{
		m_procfs_parser->set_global_cpu_jiffies();
	}
	jiffies_trc.stop();

#endif

	uint64_t process_count = 0;

	///////////////////////////////////////////////////////////////////////////
	// Emit process has 3 cycles on thread_table:
	//  1. Aggregate process into programs
	//  2. (only on programs) aggregate programs metrics to host and container ones
	//  3. (only on programs) Write programs on protobuf
	///////////////////////////////////////////////////////////////////////////

	///////////////////////////////////////////////////////////////////////////
	// First pass of the list of threads: emit the metrics (if defined)
	// and aggregate them into processes
	///////////////////////////////////////////////////////////////////////////
	tracer_emitter am_trc("aggregate_metrics", proc_trc);
	m_inspector->m_thread_manager->m_threadtable.loop([&](sinsp_threadinfo& sinsp_tinfo) {
#ifdef USE_AGENT_THREAD
		thread_analyzer_info& tinfo = dynamic_cast<thread_analyzer_info&>(sinsp_tinfo);
		ASSERT(tinfo == sinsp_tinfo);
		THREAD_TYPE* main_tinfo = tinfo.get_main_thread_info();
#else
		sinsp_threadinfo& tinfo = sinsp_tinfo;
		THREAD_TYPE* main_tinfo = tinfo.get_main_thread();
#endif
		analyzer_container_state* container = NULL;

		// xxx/nags : why not do this once for the main_thread?
		if (!tinfo.m_container_id.empty())
		{
			container = &m_containers[tinfo.m_container_id];
			// Filtering out containers if use_container_filter is set
			// Some day we might want to filter host processes as well
			if (container)
			{
#ifndef CYGWING_AGENT
				const auto cinfo =
				    m_inspector->m_container_manager.get_container(tinfo.m_container_id);
				bool optional;
				if (cinfo && !container->should_report_container(m_configuration,
				                                                 *cinfo,
				                                                 infra_state(),
				                                                 m_prev_flush_time_ns,
				                                                 optional))
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "Not reporting thread %ld in container %s",
					                tinfo.m_tid,
					                tinfo.m_container_id.c_str());
					// Just return from this lambda
					return true;
				}
#endif
			}

			const std::set<double>& pctls = m_configuration->get_percentiles();
			if (pctls.size())
			{
				container->set_percentiles(pctls);
			}
		}

		if (tinfo.is_main_thread())
		{
			++process_count;
		}

		// We need to reread cmdline only in live mode, with nodriver mode
		// proc is reread anyway
		if (m_inspector->is_live() && (tinfo.m_flags & PPM_CL_CLOSED) == 0 &&
		    m_prev_flush_time_ns - main_tinfo->m_clone_ts > ONE_SECOND_IN_NS &&
		    m_prev_flush_time_ns - GET_AGENT_THREAD(main_tinfo)->m_last_cmdline_sync_ns >
		        CMDLINE_UPDATE_INTERVAL_S * ONE_SECOND_IN_NS)
		{
			string proc_name = m_procfs_parser->read_process_name(main_tinfo->m_pid);
			if (!proc_name.empty())
			{
				main_tinfo->m_comm = proc_name;
			}
			vector<string> proc_args = m_procfs_parser->read_process_cmdline(main_tinfo->m_pid);
			if (!proc_args.empty())
			{
				main_tinfo->m_exe = proc_args.at(0);
				main_tinfo->m_args.clear();
				main_tinfo->m_args.insert(main_tinfo->m_args.begin(),
				                          ++proc_args.begin(),
				                          proc_args.end());
			}
			main_tinfo->compute_program_hash();
			GET_AGENT_THREAD(main_tinfo)->m_last_cmdline_sync_ns = m_prev_flush_time_ns;
		}

#ifndef CYGWING_AGENT
		if ((m_prev_flush_time_ns / ONE_SECOND_IN_NS) % 5 == 0 && tinfo.is_main_thread() &&
		    !m_inspector->is_capture())
		{
			// mesos autodetection flagging, happens only if mesos is not explicitly configured
			// we only record the relevant mesos process thread ID here; later, this flag is
			// detected by emit_mesos() and, if process is found to stil be alive, the appropriate
			// action is taken (configuring appchecks and connecting to API server)
			if (m_configuration->get_mesos_state_original_uri().empty() &&
			    m_configuration->get_mesos_autodetect_enabled())
			{
				uint32_t port = get_mesos_api_server_port(main_tinfo);
				if (port)
				{
					// always prefer master to slave when they are both found on the same host
					if (port == MESOS_MASTER_PORT)
					{
						m_mesos_master_tid = main_tinfo->m_tid;
						m_mesos_slave_tid = -1;
					}
					else if ((port == MESOS_SLAVE_PORT) && (m_mesos_master_tid == -1))
					{
						m_mesos_slave_tid = main_tinfo->m_tid;
					}
				}
			}
		}
#endif

		//
		// Attribute the last pending event to this second
		//
		if (m_prev_flush_time_ns != 0)
		{
			delta = m_prev_flush_time_ns - tinfo.m_lastevent_ts;

			if (delta > (int64_t)sample_duration)
			{
				delta =
				    (tinfo.m_lastevent_ts / sample_duration * sample_duration + sample_duration) -
				    tinfo.m_lastevent_ts;
			}

			tinfo.m_lastevent_ts = m_prev_flush_time_ns;

			if (PPME_IS_ENTER(tinfo.m_lastevent_type))
			{
				cat = &tinfo.m_lastevent_category;
			}
			else
			{
				tcat.m_category = EC_PROCESSING;
				tcat.m_subcategory = sinsp_evt::SC_NONE;
				cat = &tcat;
			}

			add_syscall_time(&GET_AGENT_THREAD(&tinfo)->m_metrics, cat, delta, 0, false);

			//
			// Flag the thread so we know that part of this event has already been attributed
			//
			GET_AGENT_THREAD(&tinfo)->m_th_analysis_flags |=
			    thread_analyzer_info::AF_PARTIAL_METRIC;
		}

		//
		// Some assertions to validate that everything looks like expected
		//
#ifdef _DEBUG
		sinsp_counter_time ttot;
		GET_AGENT_THREAD(&tinfo)->m_metrics.get_total(&ttot);
#endif

		//
		// Go through the FD list to flush the transactions that haven't been active for a while
		//
		uint64_t trtimeout;
		bool is_subsampling;

		if (flushflags == analyzer_emitter::DF_NONE)
		{
			trtimeout = TRANSACTION_TIMEOUT_NS;
			is_subsampling = false;
		}
		else
		{
			trtimeout = TRANSACTION_TIMEOUT_SUBSAMPLING_NS;
			is_subsampling = true;
		}

		GET_AGENT_THREAD(&tinfo)->flush_inactive_transactions(m_prev_flush_time_ns,
		                                                      trtimeout,
		                                                      is_subsampling);

		//
		// If this is a process, compute CPU load and memory usage
		//
		GET_AGENT_THREAD(&tinfo)->m_cpuload = 0;

		if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			if (tinfo.is_main_thread())
			{
				if (!m_inspector->is_capture())
				{
					//
					// It's pointless to try to get the CPU load if the process has been closed
					//
					if ((tinfo.m_flags & PPM_CL_CLOSED) == 0)
					{
						if (!m_skip_proc_parsing)
						{
							if (m_procfs_scan_thread)
							{
								GET_AGENT_THREAD(&tinfo)->m_cpuload =
								    m_procfs_parser->get_process_cpu_load(tinfo.m_pid);
							}
							else
							{
								GET_AGENT_THREAD(&tinfo)->m_cpuload =
								    m_procfs_parser->get_process_cpu_load_sync(
								        tinfo.m_pid,
								        &GET_AGENT_THREAD(&tinfo)->m_old_proc_jiffies);
							}
						}

						if (m_inspector->is_nodriver())
						{
#ifndef CYGWING_AGENT
							auto file_io_stats = m_procfs_parser->read_proc_file_stats(
							    tinfo.m_pid,
							    &GET_AGENT_THREAD(&tinfo)->m_file_io_stats);

							GET_AGENT_THREAD(&tinfo)->m_metrics.m_io_file.m_bytes_in =
							    file_io_stats.m_read_bytes;
							GET_AGENT_THREAD(&tinfo)->m_metrics.m_io_file.m_bytes_out =
							    file_io_stats.m_write_bytes;
							GET_AGENT_THREAD(&tinfo)->m_metrics.m_io_file.m_count_in =
							    file_io_stats.m_syscr;
							GET_AGENT_THREAD(&tinfo)->m_metrics.m_io_file.m_count_out =
							    file_io_stats.m_syscw;

							if (m_mode_switch_state == sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER)
							{
								if (m_stress_tool_matcher.match(tinfo.m_comm))
								{
									can_disable_nodriver = false;
								}
							}
#endif  // CYGWING_AGENT
						}
					}
				}
			}
		}

		if (tinfo.m_flags & PPM_CL_CLOSED &&
		    !(evt != NULL &&
		      (evt->get_type() == PPME_PROCEXIT_E || evt->get_type() == PPME_PROCEXIT_1_E) &&
		      evt->m_tinfo == &tinfo))
		{
			//
			// Yes, remove the thread from the table, but NOT if the event currently under
			// processing is an exit for this process. In that case we wait until next sample. Note:
			// we clear the metrics no matter what because m_thread_manager->remove_thread might
			//       not actually remove the thread if it has childs.
			//
			m_threads_to_remove.push_back(&tinfo);
		}

		//
		// Add this thread's counters to the process ones...
		//
		ASSERT(tinfo.m_program_hash != 0);

		auto emplaced = progtable.emplace(&tinfo);
		auto mtinfo = *emplaced.first;
		// Use first found thread of a program to collect all metrics
		if (emplaced.second)
		{
			if (container)
			{
				progtable_by_container[mtinfo->m_container_id].emplace_back(mtinfo);
			}
			GET_AGENT_THREAD(&tinfo)->set_main_program_thread(true);
		}
		else
		{
			GET_AGENT_THREAD(&tinfo)->set_main_program_thread(false);
		}

		ASSERT(mtinfo != NULL);

		GET_AGENT_THREAD(&tinfo)->m_main_thread_pid = mtinfo->m_pid;

		GET_AGENT_THREAD(mtinfo)->add_all_metrics(GET_AGENT_THREAD(&tinfo));

		if (!emplaced.second)
		{
			GET_AGENT_THREAD(&tinfo)->clear_all_metrics();
		}
#ifndef _WIN32
		if (tinfo.is_main_thread() && !(tinfo.m_flags & PPM_CL_CLOSED) &&
		    (m_next_flush_time_ns - tinfo.m_clone_ts) >
		        ASSUME_LONG_LIVING_PROCESS_UPTIME_S * ONE_SECOND_IN_NS &&
		    tinfo.m_vpid > 0)
		{
			const auto& procs = m_configuration->get_procfs_scan_procs();
			bool procfs_scan = procs.find(tinfo.m_comm) != procs.end();
			GET_AGENT_THREAD(&tinfo)->scan_listening_ports(
			    procfs_scan,
			    m_configuration->get_procfs_scan_interval());

			if (m_jmx_proxy && tinfo.get_comm() == "java")
			{
				if (!GET_AGENT_THREAD(&tinfo)->m_root_refreshed)
				{
					GET_AGENT_THREAD(&tinfo)->m_root_refreshed = true;
					tinfo.m_root = m_procfs_parser->read_proc_root(tinfo.m_pid);
				}
				java_process_requests.emplace_back(&tinfo);
			}

			// May happen that for processes like apache with mpm_prefork there are hundred of
			// apache processes with same comm, cmdline and ports, some of them are always alive,
			// some die and are recreated.
			// We send to app_checks only processes up at least for 10 seconds. But the programs
			// aggregation may choose the young one. So now we are trying to match a check for every
			// process in the program grouping and when we find a matching check, we mark it on the
			// main_thread of the group as we don't need more checks instances for each process.
			if (m_app_checks_proxy)
			{
				const auto& custom_checks =
				    GET_AGENT_THREAD(mtinfo)->get_proc_config().app_checks();
				vector<app_process> app_checks;

				match_checks_list(&tinfo, mtinfo, custom_checks, app_checks, "env");
				// Ignore the global list if we found custom checks
				if (app_checks.empty())
				{
					match_checks_list(&tinfo, mtinfo, m_app_checks, app_checks, "global list");
				}
				auto flush_time = m_prev_flush_time_ns / ONE_SECOND_IN_NS;

#ifndef CYGWING_AGENT
				// Prometheus checks are done through the app proxy as well.
				// Looking for prometheus matches after app_checks because
				// a rule may be specified for finding an app_checks match
				if (!m_app_checks_proxy->have_prometheus_metrics_for_pid(tinfo.m_pid, flush_time))
				{
					match_prom_checks(&tinfo, mtinfo, prom_procs, false);
				}
#endif  // CYGWING_AGENT

				for (auto& appcheck : app_checks)
				{
					if (m_app_checks_proxy->have_app_check_metrics_for_pid(tinfo.m_pid,
					                                                       flush_time,
					                                                       appcheck.name()))
					{
						// Found metrics for this pid and name that won't
						// expire this cycle so we use them instead of
						// running the check again
						g_logger.format(sinsp_logger::SEV_DEBUG,
						                "App metrics for %d,%s are still good",
						                tinfo.m_pid,
						                appcheck.name().c_str());
					}
					else
					{
						app_checks_processes.push_back(move(appcheck));
					}
				}
			}
		}
#endif
		return true;
	});
	am_trc.stop();

	if (m_inspector->is_nodriver() &&
	    m_mode_switch_state == sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER && can_disable_nodriver)
	{
		m_mode_switch_state = sinsp_analyzer::MSR_REQUEST_REGULAR;
	}

	tracer_emitter internal_metrics_trc("internal_metrics", proc_trc);
	if (m_internal_metrics)
	{
		// update internal metrics
		m_internal_metrics->set_process(process_count);
		m_internal_metrics->set_thread(m_inspector->m_thread_manager->m_threadtable.size());
		m_internal_metrics->set_thread_drops(m_inspector->m_thread_manager->m_n_drops);
		m_internal_metrics->set_container(m_containers.size());
		m_internal_metrics->set_appcheck(app_checks_processes.size());
		m_internal_metrics->set_javaproc(java_process_requests.size());
#ifndef CYGWING_AGENT
		m_internal_metrics->set_mesos_autodetect(m_configuration->get_mesos_autodetect_enabled());
#endif
		m_internal_metrics->update_subprocess_metrics(m_procfs_parser);
	}
	internal_metrics_trc.stop();

	tracer_emitter pt_trc("walk_progtable", proc_trc);
	for (auto it = progtable.begin(); it != progtable.end(); ++it)
	{
		THREAD_TYPE* tinfo = *it;
		analyzer_container_state* container = NULL;
		if (!tinfo->m_container_id.empty())
		{
			container = &m_containers[tinfo->m_container_id];
			const std::set<double>& pctls = m_configuration->get_percentiles();
			if (pctls.size())
			{
				container->set_percentiles(pctls);
			}
		}

		sinsp_procinfo* procinfo = GET_AGENT_THREAD(tinfo)->m_procinfo;

		//
		// ... Add to the host ones
		//
		m_host_transaction_counters.add(&procinfo->m_external_transaction_metrics);

		if (container)
		{
			container->m_transaction_counters.add(&procinfo->m_proc_transaction_metrics);
			if (m_top_files_per_container > 0)
			{
				container->m_files_stat.add(procinfo->m_files_stat);
			}
			if (m_top_file_devices_per_container > 0)
			{
				container->m_devs_stat.add(procinfo->m_devs_stat);
			}
		}

		if (procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
		{
			m_server_programs.insert(tinfo->m_tid);
			m_client_tr_time_by_servers +=
			    procinfo->m_external_transaction_metrics.get_counter()->m_time_ns_out;
		}

		sinsp_counter_time tot;

		ASSERT(procinfo != NULL);

		procinfo->m_proc_metrics.get_total(&tot);

		if (tot.m_count != 0)
		{
			sinsp_delays_info* prog_delays = &procinfo->m_transaction_delays;
			if (container)
			{
				m_delay_calculator->compute_program_delays(&m_host_client_transactions,
				                                           &m_host_server_transactions,
				                                           &container->m_client_transactions,
				                                           &container->m_server_transactions,
				                                           tinfo,
				                                           prog_delays);
			}
			else
			{
				m_delay_calculator->compute_program_delays(&m_host_client_transactions,
				                                           &m_host_server_transactions,
				                                           NULL,
				                                           NULL,
				                                           tinfo,
				                                           prog_delays);
			}

#ifdef _DEBUG
			procinfo->m_proc_metrics.calculate_totals();
			double processing = procinfo->m_proc_metrics.get_processing_percentage();
			double file = procinfo->m_proc_metrics.get_file_percentage();
			double net = procinfo->m_proc_metrics.get_net_percentage();
			double other = procinfo->m_proc_metrics.get_other_percentage();
			double totpct = processing + file + net + other;
			g_logger.log("Metrics [" + tinfo->m_comm + "] processing=" + to_string(processing) +
			                 ", file=" + to_string(file) + ", net=" + to_string(net) +
			                 ", other=" + to_string(other) + ", totpct=" + to_string(totpct),
			             sinsp_logger::SEV_DEBUG);
			ASSERT(totpct == 0 || (totpct > 0.99 && totpct < 1.01));
#endif  // _DEBUG

			//
			// Main metrics
			//
			// NOTE ABOUT THE FOLLOWING TWO LINES: computing processing time by looking at gaps
			// among system calls doesn't work if we are dropping all the non essential events,
			// which the aagent does by default, because a ton of time gets accountd as processing.
			// To avoid the issue, we patch the processing time with the actual CPU time for the
			// process, normalized accodring to the sampling ratio
			//
			procinfo->m_proc_metrics.m_processing.clear();
			procinfo->m_proc_metrics.m_processing.add(
			    1,
			    (uint64_t)(procinfo->m_cpuload * (1000000000 / 100) / m_acked_sampling_ratio));

			//
			// Health-related metrics
			//
			if (m_inspector->m_thread_manager->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD &&
			    procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
			{
				sinsp_score_info scores = m_score_calculator->get_process_capacity_score(
				    tinfo,
				    prog_delays,
				    (uint32_t)GET_AGENT_THREAD(tinfo)->m_procinfo->m_n_transaction_threads,
				    m_prev_flush_time_ns,
				    sample_duration);

				procinfo->m_capacity_score = scores.m_current_capacity;
				procinfo->m_stolen_capacity_score = scores.m_stolen_capacity;
			}
			else
			{
				procinfo->m_capacity_score = -1;
				procinfo->m_stolen_capacity_score = 0;
			}

			//
			// Update the host capcity score
			//
			if (procinfo->m_capacity_score != -1)
			{
				m_host_metrics.add_capacity_score(
				    procinfo->m_capacity_score,
				    procinfo->m_stolen_capacity_score,
				    procinfo->m_external_transaction_metrics.get_counter()->m_count_in);

				if (container)
				{
					container->m_metrics.add_capacity_score(
					    procinfo->m_capacity_score,
					    procinfo->m_stolen_capacity_score,
					    procinfo->m_external_transaction_metrics.get_counter()->m_count_in);
				}
			}

#if 1
			if (procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
			{
				uint64_t trtimein =
				    procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_in;
				uint64_t trtimeout =
				    procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_out;
				uint32_t trcountin = procinfo->m_proc_transaction_metrics.get_counter()->m_count_in;
				uint32_t trcountout =
				    procinfo->m_proc_transaction_metrics.get_counter()->m_count_out;

				if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(
					    sinsp_logger::SEV_DEBUG,
					    " %s (%" PRIu64 ")%" PRIu64 " h:%.2f(s:%.2f) cpu:%.2f %%f:%" PRIu32
					    " %%c:%" PRIu32,
					    tinfo->m_comm.c_str(),
					    tinfo->m_tid,
					    (uint64_t)GET_AGENT_THREAD(tinfo)->m_procinfo->m_program_pids.size(),
					    procinfo->m_capacity_score,
					    procinfo->m_stolen_capacity_score,
					    (float)procinfo->m_cpuload,
					    procinfo->m_fd_usage_pct,
					    procinfo->m_connection_queue_usage_pct);

					g_logger.format(
					    sinsp_logger::SEV_DEBUG,
					    "  trans)in:%" PRIu32 " out:%" PRIu32
					    " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
					    procinfo->m_proc_transaction_metrics.get_counter()->m_count_in *
					        m_acked_sampling_ratio,
					    procinfo->m_proc_transaction_metrics.get_counter()->m_count_out *
					        m_acked_sampling_ratio,
					    trcountin ? ((double)trtimein) / sample_duration : 0,
					    trcountout ? ((double)trtimeout) / sample_duration : 0,
					    (prog_delays)
					        ? ((double)prog_delays->m_merged_server_delay) / sample_duration
					        : 0,
					    (prog_delays)
					        ? ((double)prog_delays->m_merged_client_delay) / sample_duration
					        : 0,
					    (prog_delays)
					        ? ((double)prog_delays->m_local_processing_delay_ns) / sample_duration
					        : 0);

					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "  time)proc:%.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32
					                " out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
					                procinfo->m_proc_metrics.get_processing_percentage() * 100,
					                procinfo->m_proc_metrics.get_file_percentage() * 100,
					                procinfo->m_proc_metrics.m_tot_io_file.m_bytes_in,
					                procinfo->m_proc_metrics.m_tot_io_file.m_count_in,
					                procinfo->m_proc_metrics.m_tot_io_file.m_bytes_out,
					                procinfo->m_proc_metrics.m_tot_io_file.m_count_out,
					                procinfo->m_proc_metrics.get_net_percentage() * 100,
					                procinfo->m_proc_metrics.get_other_percentage() * 100);
				}
			}
#endif
		}

		//
		// Update the host metrics with the info coming from this process
		//
		if (procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
		{
			m_host_req_metrics.add(&procinfo->m_proc_metrics);

			if (container)
			{
				container->m_req_metrics.add(&procinfo->m_proc_metrics);
			}
		}

		//
		// Note how we only include server processes.
		// That's because these are transaction time metrics, and therefore we don't
		// want to use processes that don't serve transactions.
		//
		m_host_metrics.add(procinfo);

		if (container)
		{
			container->m_metrics.add(procinfo);
		}
	}
	pt_trc.stop();

	// pass connections to kafka tap
	tracer_emitter tap_trc("tap", proc_trc);
	if (m_tap)
	{
		m_tap->emit_connections(m_ipv4_connections, m_username_lookups ? &m_userdb : nullptr);
	}
	tap_trc.stop();

	////////////////////////////////////////////////////////////////////////////
	// EMIT CONNECTIONS
	////////////////////////////////////////////////////////////////////////////
	// This code has been moved here because it needs the processes already
	// grouped by programs (to use the correct pid for connections) but also needs to
	// run before emit_containers, because it aggregates network connections by server port
	// per each container
	// WARNING: the following methods emit but also clear the metrics
	if (m_configuration->get_aggregate_connections_in_proto())
	{
		//
		// Aggregate external connections and limit the number of entries in the connection table
		//
		tracer_emitter agg_conns_trc("emit_aggregated_connections", proc_trc);
		emit_aggregated_connections();
	}
	else
	{
		//
		// Emit all the connections
		//
		tracer_emitter full_conns_trc("emit_full_connections", proc_trc);
		emit_full_connections();
	}

	// Filter and emit containers, we do it now because when filtering processes we add
	// at least one process for each container
	tracer_emitter container_trc("emit_container", proc_trc);
	vector<string> emitted_containers;
	if (m_configuration->get_smart_container_reporting())
	{
		update_percentile_data_serialization(progtable_by_container);

		analyzer_container_emitter emitter(*this,
		                                   m_containers,
		                                   statsd_emitter::get_limit(),
		                                   progtable_by_container,
		                                   m_container_patterns,
		                                   flushflags,
		                                   m_containers_limit,
		                                   m_inspector->is_nodriver(),
		                                   emitted_containers);
		emitter.emit_containers();
		coalesce_unemitted_stats(emitted_containers);

		gather_k8s_infrastructure_state(flushflags, emitted_containers);

		clean_containers(progtable_by_container);
	}
	else
	{  // no smart container reporting
		emitted_containers = emit_containers_deprecated(progtable_by_container, flushflags);
	}
	container_trc.stop();

	// notify mounted_fs proxy of containers which have long-running procs
	tracer_emitter mountedfs_trc("mountedfs", proc_trc);
	if (!m_inspector->is_capture() && m_mounted_fs_proxy)
	{
		vector<THREAD_TYPE*> containers_for_mounted_fs;
		for (const auto& it : progtable_by_container)
		{
			const auto container_info = m_inspector->m_container_manager.get_container(it.first);
			if (container_info && !container_info->is_pod_sandbox())
			{
				auto long_running_proc =
				    find_if(it.second.begin(), it.second.end(), [this](THREAD_TYPE* tinfo) {
					    return !(tinfo->m_flags & PPM_CL_CLOSED) &&
					           (m_next_flush_time_ns - tinfo->get_main_thread()->m_clone_ts) >=
					               ASSUME_LONG_LIVING_PROCESS_UPTIME_S * ONE_SECOND_IN_NS;
				    });

				if (long_running_proc != it.second.end())
				{
					if (!GET_AGENT_THREAD(*long_running_proc)->m_root_refreshed)
					{
						GET_AGENT_THREAD(*long_running_proc)->m_root_refreshed = true;
						(*long_running_proc)->m_root =
						    m_procfs_parser->read_proc_root((*long_running_proc)->m_pid);
					}

					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "[mountedfs_reader] picked process %s (tid=%ld/%ld) for "
					                "container %s (tinfo->container_id=%s)",
					                (*long_running_proc)->get_comm().c_str(),
					                (*long_running_proc)->m_tid,
					                (*long_running_proc)->m_vtid,
					                it.first.c_str(),
					                (*long_running_proc)->m_container_id.c_str());

					containers_for_mounted_fs.push_back(*long_running_proc);
				}
			}
		}
		m_mounted_fs_proxy->send_container_list(containers_for_mounted_fs);
	}
	mountedfs_trc.stop();

	tracer_emitter actually_emit_trc("actually_emit", proc_trc);
	std::set<uint64_t> all_uids;
	jmx_emitter jmx_emitter_instance(m_jmx_metrics,
	                                 m_jmx_sampling,
	                                 metric_forwarding_configuration::c_jmx_max->get_value(),
	                                 m_jmx_metrics_by_containers);
	std::unique_ptr<app_check_emitter> app_check_emitter_instance = nullptr;
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT &&
	    m_app_checks_proxy != nullptr)
	{
		app_check_emitter_instance = make_unique<app_check_emitter>(
		    m_app_checks_proxy->get_all_metrics(),
		    metric_forwarding_configuration::c_app_checks_max->get_value(),
		    m_prom_conf,
		    m_app_checks_by_containers,
		    m_prometheus_by_containers,
		    m_prev_flush_time_ns);
	}

	environment_emitter environment_emitter_instance(m_prev_flush_time_ns,
	                                                 m_env_hash_config,
	                                                 *m_metrics);
	process_emitter process_emitter_instance(m_process_manager,
	                                         *m_inspector,
	                                         m_simpledriver_enabled,
	                                         m_inspector->is_nodriver(),
	                                         proc_trc,
	                                         m_top_files_per_prog,
	                                         m_device_map,
	                                         m_username_lookups,
	                                         m_track_environment,
	                                         m_top_file_devices_per_prog,
	                                         m_jmx_proxy.get(),
	                                         m_procfs_scan_thread,
	                                         *m_procfs_parser,
	                                         m_acked_sampling_ratio,
	                                         m_machine_info->num_cpus,
	                                         environment_emitter_instance,
	                                         jmx_emitter_instance,
	                                         app_check_emitter_instance.get());
	if (process_manager::c_process_flush_filter_enabled.get_value())
	{
		std::set<THREAD_TYPE*> emitted_processes;
		process_emitter_instance.emit_processes(flushflags,
		                                        progtable,
		                                        progtable_by_container,
		                                        emitted_containers,
		                                        *m_metrics,
		                                        all_uids,
		                                        emitted_processes);
	}
	else
	{
		emit_processes_deprecated(all_uids,
		                          flushflags,
		                          progtable,
		                          progtable_by_container,
		                          emitted_containers,
		                          proc_trc,
		                          jmx_emitter_instance,
		                          environment_emitter_instance,
		                          process_emitter_instance);
	}
	actually_emit_trc.stop();

	tracer_emitter user_trc("userdb_lookup", proc_trc);
	for (const auto uid : all_uids)
	{
		auto userdb = m_metrics->add_userdb();
		const auto& user = m_userdb.lookup(uid);
		userdb->set_id(uid);
		userdb->set_name(user);
	}
	user_trc.stop();

	tracer_emitter app_check_stats_trc("app_check_stats", proc_trc);
	// add jmx and app checks per container
	for (int i = 0; i < m_metrics->containers_size(); i++)
	{
		draiosproto::container* container = m_metrics->mutable_containers(i);
		string container_id = container->id();

		container->mutable_resource_counters()->set_jmx_sent(
		    std::get<0>(m_jmx_metrics_by_containers[container_id]));
		container->mutable_resource_counters()->set_jmx_total(
		    std::get<1>(m_jmx_metrics_by_containers[container_id]));

		container->mutable_resource_counters()->set_app_checks_sent(
		    std::get<0>(m_app_checks_by_containers[container_id]));
		container->mutable_resource_counters()->set_app_checks_total(
		    std::get<1>(m_app_checks_by_containers[container_id]));
		container->mutable_resource_counters()->set_prometheus_sent(
		    std::get<0>(m_prometheus_by_containers[container_id]));
		container->mutable_resource_counters()->set_prometheus_total(
		    std::get<1>(m_prometheus_by_containers[container_id]));
	}

	if (app_check_emitter_instance)
	{
		app_check_emitter_instance->log_result();
	}
	app_check_stats_trc.stop();

#ifndef _WIN32
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		tracer_emitter send_jmx_trc("send_jmx", proc_trc);
		if (m_jmx_proxy && is_jmx_flushtime() && !java_process_requests.empty())
		{
			m_jmx_proxy->send_get_metrics(java_process_requests);
		}
		send_jmx_trc.stop();
#ifndef CYGWING_AGENT
		if (m_app_checks_proxy)
		{
			tracer_emitter app_check_trc("app_checks", proc_trc);
			if (!prom_procs.empty())
			{
				tracer_emitter prom_filter_procs_trc("prom_filter_procs", app_check_trc);
				// Filter out duplicate prometheus scans
				prom_process::filter_procs(prom_procs,
				                           m_inspector->m_thread_manager->m_threadtable,
				                           *(m_app_checks_proxy->get_all_metrics().lock()),
				                           m_prev_flush_time_ns);
			}
			// Get our own thread info to match for prometheus host_filter
			// (for scraping remote endpoints)
			THREAD_TYPE* our_tinfo = get_thread_by_pid(getpid());
			if (!our_tinfo)
			{
				g_logger.format(sinsp_logger::SEV_WARNING,
				                "Couldn't find threadinfo for our pid %d",
				                getpid());
			}
			else
			{
				tracer_emitter prom_filter_procs_trc("remote_prom_checks", app_check_trc);
				// Check if we need to scrape remote prometheus endpoints.
				// Enforce interval by looking to see if we have any non-expired
				// prometheus metrics associated with our pid.
				// If we have multiple endpoints configured they will all be scraped
				// in the same cycle
				// XXX: This will have to be revisited if we're going to allow
				// different intervals for different endpoints or if we want to start
				// interleaving multiple endpoints.
				if (!m_app_checks_proxy->have_prometheus_metrics_for_pid(
				        our_tinfo->m_pid,
				        m_prev_flush_time_ns / ONE_SECOND_IN_NS))
				{
					match_prom_checks(our_tinfo,
#ifdef USE_AGENT_THREAD
					                  our_tinfo->get_main_thread_info(),
#else
					                  our_tinfo->get_main_thread(),
#endif
					                  prom_procs,
					                  true);
				}
			}

			if (!app_checks_processes.empty() || !prom_procs.empty())
			{
				tracer_emitter prom_filter_procs_trc("send_get_metrics_cmd", app_check_trc);
				m_app_checks_proxy->send_get_metrics_cmd(app_checks_processes,
				                                         prom_procs,
				                                         &m_prom_conf);
			}
		}
#endif
	}
#endif
}

void sinsp_analyzer::flush_processes()
{
	for (vector<THREAD_TYPE*>::const_iterator it = m_threads_to_remove.begin();
	     it != m_threads_to_remove.end();
	     ++it)
	{
		m_inspector->m_thread_manager->remove_thread((*it)->m_tid, false);
	}

	m_threads_to_remove.clear();
}

draiosproto::connection_state pb_connection_state(int analyzer_flags)
{
	if (analyzer_flags & sinsp_connection::AF_FAILED)
	{
		return draiosproto::connection_state::CONN_FAILED;
	}
	else if (analyzer_flags & sinsp_connection::AF_PENDING)
	{
		return draiosproto::connection_state::CONN_PENDING;
	}
	else
	{
		return draiosproto::connection_state::CONN_SUCCESS;
	}
}

draiosproto::error_code pb_error_code(int error_code)
{
	if (draiosproto::error_code_IsValid(error_code))
	{
		return static_cast<draiosproto::error_code>(error_code);
	}
	return draiosproto::ERR_NONE;
}

bool conn_cmp_bytes(pair<const process_tuple*, sinsp_connection*>& src,
                    pair<const process_tuple*, sinsp_connection*>& dst)
{
	uint64_t s =
	    src.second->m_metrics.m_client.m_bytes_in + src.second->m_metrics.m_client.m_bytes_out +
	    src.second->m_metrics.m_server.m_bytes_in + src.second->m_metrics.m_server.m_bytes_out;

	uint64_t d =
	    dst.second->m_metrics.m_client.m_bytes_in + dst.second->m_metrics.m_client.m_bytes_out +
	    dst.second->m_metrics.m_server.m_bytes_in + dst.second->m_metrics.m_server.m_bytes_out;

	return (s > d);
}

bool conn_cmp_n_aggregated_connections(pair<const process_tuple*, sinsp_connection*>& src,
                                       pair<const process_tuple*, sinsp_connection*>& dst)
{
	uint64_t s = src.second->m_timestamp;
	uint64_t d = dst.second->m_timestamp;

	return (s > d);
}

static inline bool should_report_connection(const process_tuple& tuple)
{
	if (tuple.m_fields.m_state == draiosproto::CONN_SUCCESS)
	{
		return tuple.m_fields.m_sip != 0 && tuple.m_fields.m_dip != 0;
	}
	else
	{
		return tuple.m_fields.m_sip != 0 || tuple.m_fields.m_dip != 0;
	}
}

//
// Strategy:
//  - sport is masked to zero, unless m_report_source_port is set
//  - if there are more than MAX_N_EXTERNAL_CLIENTS external client connections,
//    external client IPs are masked to zero
//
void sinsp_analyzer::emit_aggregated_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
	process_tuple tuple;
	bool aggregate_external_clients = false;
	set<uint32_t> unique_external_ips;

	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>
	    reduced_ipv4_connections, reduced_and_filtered_ipv4_connections, connection_to_emit;

	unordered_map<uint16_t, sinsp_connection_aggregator> connections_by_serverport;

	//
	// First partial pass to determine if external connections need to be coalesced
	//
	for (const auto& it : m_ipv4_connections->m_connections)
	{
		if (it.second.is_server_only())
		{
			uint32_t sip = it.first.m_fields.m_sip;

			if (!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(sip))
			{
				unique_external_ips.insert(sip);

				if (unique_external_ips.size() > m_max_n_external_clients)
				{
					aggregate_external_clients = true;
					break;
				}
			}
		}
	}

	//
	// Second pass to perform the aggregation
	//
	for (cit = m_ipv4_connections->m_connections.begin();
	     cit != m_ipv4_connections->m_connections.end();)
	{
		//
		// Find the main program pids
		//
		int64_t prog_spid = 0;
		int64_t prog_dpid = 0;
		string prog_scontainerid;
		string prog_dcontainerid;

		if (cit->second.m_spid != 0)
		{
			auto tinfo = get_thread_by_pid(cit->second.m_spid, false, true);
			if (tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				++cit;
				continue;
			}

			prog_spid = GET_AGENT_THREAD(tinfo)->m_main_thread_pid;
			prog_scontainerid = tinfo->m_container_id;
		}

		if (cit->second.m_dpid != 0)
		{
			auto tinfo = get_thread_by_pid(cit->second.m_dpid, false, true);
			if (tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				++cit;
				continue;
			}

			prog_dpid = GET_AGENT_THREAD(tinfo)->m_main_thread_pid;
			prog_dcontainerid = tinfo->m_container_id;
		}

		tuple.m_fields.m_spid = prog_spid;
		tuple.m_fields.m_dpid = prog_dpid;
		tuple.m_fields.m_sip = cit->first.m_fields.m_sip;
		tuple.m_fields.m_dip = cit->first.m_fields.m_dip;
		tuple.m_fields.m_sport = m_report_source_port ? cit->first.m_fields.m_sport : 0;
		tuple.m_fields.m_dport = cit->first.m_fields.m_dport;
		tuple.m_fields.m_l4proto = cit->first.m_fields.m_l4proto;
		tuple.m_fields.m_state = pb_connection_state(cit->second.m_analysis_flags);

		if (should_report_connection(tuple))
		{
			if (!cit->second.is_client_and_server())
			{
				if (cit->second.is_server_only())
				{
					//
					// If external client aggregation is enabled, this is a server connection, and
					// the client address is outside the subnet, mask it so it gets aggregated
					//
					if (aggregate_external_clients)
					{
						if (!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(
						        cit->first.m_fields.m_sip))
						{
							tuple.m_fields.m_sip = 0;
						}
					}

					//
					// Add this connection's bytes to the host network volume
					//
					m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in,
					                0,
					                cit->second.m_metrics.m_server.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out,
					                 0,
					                 cit->second.m_metrics.m_server.m_bytes_out);
				}
				else
				{
					//
					// Add this connection's bytes to the host network volume
					//
					ASSERT(cit->second.is_client_only())
					m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in,
					                0,
					                cit->second.m_metrics.m_client.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out,
					                 0,
					                 cit->second.m_metrics.m_client.m_bytes_out);
				}
			}

			//
			// Look for the entry in the reduced connection table.
			// Note: we don't export connections whose sip or dip is zero.
			//
			sinsp_connection& conn = reduced_ipv4_connections[tuple];
			if (conn.m_timestamp == 0)
			{
				//
				// New entry.
				// Structure copy the connection info.
				//
				conn = cit->second;
				conn.m_timestamp = 1;
				const std::set<double>& pctls = m_configuration->get_percentiles();
				if (pctls.size())
				{
					init_host_level_percentiles(conn.m_transaction_metrics, pctls);
				}
			}
			else
			{
				//
				// Existing entry.
				// Add this connection's metrics to the aggregated connection's ones.
				//
				conn.m_metrics.add(&cit->second.m_metrics);
				conn.m_transaction_metrics.add(&cit->second.m_transaction_metrics);
				conn.m_timestamp++;
			}

			// same thing by server port per host
			connections_by_serverport[tuple.m_fields.m_dport].add(&cit->second);

			// same thing by server port per container
			if (!prog_scontainerid.empty() && prog_scontainerid == prog_dcontainerid)
			{
				auto& conn_aggr = (*m_containers[prog_scontainerid]
				                        .m_connections_by_serverport)[tuple.m_fields.m_dport];
				conn_aggr.add(&cit->second);
			}
			else
			{
				if (!prog_scontainerid.empty())
				{
					auto& conn_aggr = (*m_containers[prog_scontainerid]
					                        .m_connections_by_serverport)[tuple.m_fields.m_dport];
					conn_aggr.add_client(&cit->second);
				}
				if (!prog_dcontainerid.empty())
				{
					auto& conn_aggr = (*m_containers[prog_dcontainerid]
					                        .m_connections_by_serverport)[tuple.m_fields.m_dport];
					conn_aggr.add_server(&cit->second);
				}
			}
		}

		//
		// Has this connection been closed druring this sample?
		//
		if (cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}

	sinsp_connection_aggregator::filter_and_emit(connections_by_serverport,
	                                             m_metrics->mutable_hostinfo(),
	                                             TOP_SERVER_PORTS_IN_SAMPLE,
	                                             m_acked_sampling_ratio);

	//
	// if the table is still too big, sort it and pick only the top connections
	//
	vector<pair<const process_tuple*, sinsp_connection*>> sortable_conns, sortable_incomplete_conns;
	pair<const process_tuple*, sinsp_connection*> sortable_conns_entry;

	if (reduced_ipv4_connections.size() > m_top_connections_in_sample)
	{
		//
		// Prepare the sortable list
		//
		for (auto& sit : reduced_ipv4_connections)
		{
			sortable_conns_entry.first = &(sit.first);
			sortable_conns_entry.second = &(sit.second);

			if (sit.first.m_fields.m_state == (int)draiosproto::connection_state::CONN_SUCCESS)
			{
				sortable_conns.push_back(sortable_conns_entry);
			}
			else
			{
				sortable_incomplete_conns.push_back(sortable_conns_entry);
			}
		}
		size_t num_conns = sortable_conns.size();
		size_t num_incomplete_conns = sortable_incomplete_conns.size();

		auto conns_to_report =
		    std::min(m_top_connections_in_sample, (uint32_t)sortable_conns.size());
		if (conns_to_report > 0)
		{
			//
			// Sort by number of sub-connections and pick the TOP_CONNECTIONS_IN_SAMPLE
			// connections
			//
			partial_sort(sortable_conns.begin(),
			             sortable_conns.begin() + conns_to_report,
			             sortable_conns.end(),
			             conn_cmp_n_aggregated_connections);

			for (uint32_t j = 0; j < conns_to_report; j++)
			{
				reduced_and_filtered_ipv4_connections[*(sortable_conns[j].first)] =
				    *(sortable_conns[j].second);
			}

			//
			// Sort by total bytes and pick the TOP_CONNECTIONS_IN_SAMPLE connections
			//
			partial_sort(sortable_conns.begin(),
			             sortable_conns.begin() + conns_to_report,
			             sortable_conns.end(),
			             conn_cmp_bytes);

			for (uint32_t j = 0; j < conns_to_report; j++)
			{
				reduced_and_filtered_ipv4_connections[*(sortable_conns[j].first)] =
				    *(sortable_conns[j].second);
			}
		}
		size_t reported_conns = reduced_and_filtered_ipv4_connections.size();

		conns_to_report =
		    std::min(m_top_connections_in_sample, (uint32_t)sortable_incomplete_conns.size());
		if (conns_to_report > 0)
		{
			//
			// Sort by number of sub-connections and pick the TOP_CONNECTIONS_IN_SAMPLE
			// incomplete connections
			//
			partial_sort(sortable_incomplete_conns.begin(),
			             sortable_incomplete_conns.begin() + conns_to_report,
			             sortable_incomplete_conns.end(),
			             conn_cmp_n_aggregated_connections);

			for (uint32_t j = 0; j < conns_to_report; j++)
			{
				reduced_and_filtered_ipv4_connections[*(sortable_incomplete_conns[j].first)] =
				    *(sortable_incomplete_conns[j].second);
			}
		}
		size_t reported_incomplete_conns =
		    reduced_and_filtered_ipv4_connections.size() - reported_conns;

		uint64_t now = sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS;
		if (m_connection_truncate_report_interval > 0 || m_connection_truncate_log_interval > 0)
		{
			bool truncated_conns = (num_conns != reported_conns);
			bool truncated_incomplete_conns = (num_incomplete_conns != reported_incomplete_conns);
			int trunc = truncated_conns | (truncated_incomplete_conns << 1);
			if (trunc)
			{
				string evt_name = "Too many TCP connections to report, truncating table";
				string evt_desc;

				switch (trunc)
				{
				case 1:
					evt_desc = "Reported " + to_string(reported_conns) + " out of " +
					           to_string(num_conns) + " connections";
					break;
				case 2:
					evt_desc = "Reported " + to_string(reported_incomplete_conns) + " out of " +
					           to_string(num_incomplete_conns) + " incomplete connections";
					break;
				case 3:
					evt_desc = "Reported " + to_string(reported_conns) + " out of " +
					           to_string(num_conns) + " successful connections and " +
					           to_string(reported_incomplete_conns) + " out of " +
					           to_string(num_incomplete_conns) + " incomplete connections";
					break;
				default:
					ASSERT(false);
				}

				if (m_connection_truncate_log_interval > 0 &&
				    m_connection_truncate_log_last + m_connection_truncate_log_interval < (int)now)
				{
					g_logger.log(evt_name + ". " + evt_desc, sinsp_logger::SEV_INFO);
#define IP4ADDR(ip) ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, ip >> 24
					for (auto it = sortable_conns.begin(); it != sortable_conns.end(); ++it)
					{
						const auto tuple = it->first;
						const auto aconn = it->second;
						if (reduced_and_filtered_ipv4_connections.find(*(it->first)) ==
						    reduced_and_filtered_ipv4_connections.end())
						{
							g_logger.format(
							    sinsp_logger::SEV_DEBUG,
							    "Dropping connection %s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
							    aconn->m_scomm.c_str(),
							    IP4ADDR(tuple->m_fields.m_sip),
							    tuple->m_fields.m_sport,
							    IP4ADDR(tuple->m_fields.m_dip),
							    tuple->m_fields.m_dport);
						}
					}

					for (auto it = sortable_incomplete_conns.begin();
					     it != sortable_incomplete_conns.end();
					     ++it)
					{
						const auto tuple = it->first;
						const auto aconn = it->second;
						if (reduced_and_filtered_ipv4_connections.find(*(it->first)) ==
						    reduced_and_filtered_ipv4_connections.end())
						{
							g_logger.format(sinsp_logger::SEV_DEBUG,
							                "Dropping incomplete connection %s %d.%d.%d.%d:%d -> "
							                "%d.%d.%d.%d:%d",
							                aconn->m_scomm.c_str(),
							                IP4ADDR(tuple->m_fields.m_sip),
							                tuple->m_fields.m_sport,
							                IP4ADDR(tuple->m_fields.m_dip),
							                tuple->m_fields.m_dport);
						}
					}
#undef IP4ADDR
					m_connection_truncate_log_last = (int)now;
				}

				if (m_connection_truncate_report_interval > 0 &&
				    m_connection_truncate_report_last + m_connection_truncate_report_interval <
				        (int)now)
				{
					event_scope scope;
					scope.add("host.mac", m_configuration->get_machine_id());

					auto evt = sinsp_user_event(now,
					                            std::move(evt_name),
					                            std::move(evt_desc),
					                            std::move(scope.get_ref()),
					                            {},
					                            user_event_logger::SEV_EVT_INFORMATION);

					user_event_logger::log(evt, user_event_logger::SEV_EVT_INFORMATION);
					m_connection_truncate_report_last = (int)now;
				}
			}
		}
		connection_to_emit = std::move(reduced_and_filtered_ipv4_connections);
	}
	else
	{
		connection_to_emit = std::move(reduced_ipv4_connections);
	}

	//
	// Emit the aggregated table into the sample
	//
	for (auto& acit : connection_to_emit)
	{
		//
		// Skip connection that had no activity during the sample
		//
		if (!m_simpledriver_enabled)
		{
			if (!acit.second.is_active())
			{
				continue;
			}
		}

		//
		// Add the connection to the protobuf
		//
		auto conn_state = pb_connection_state(acit.second.m_analysis_flags);
		if (conn_state == draiosproto::CONN_SUCCESS)
		{
			auto conn = m_metrics->add_ipv4_connections();
			emit_connection<decltype(conn)>(conn, conn_state, acit);
		}
		else
		{
			auto conn = m_metrics->add_ipv4_incomplete_connections();
			emit_connection<decltype(conn)>(conn, conn_state, acit);
		}
	}
}

template<typename T>
void sinsp_analyzer::emit_connection(T& conn,
                                     draiosproto::connection_state& conn_state,
                                     std::pair<const _process_tuple, sinsp_connection>& acit)
{
	conn->set_state(conn_state);
	conn->set_error_code(pb_error_code(acit.second.m_error_code));
	draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

	tuple->set_sip(htonl(acit.first.m_fields.m_sip));
	tuple->set_dip(htonl(acit.first.m_fields.m_dip));
	tuple->set_sport(acit.first.m_fields.m_sport);
	tuple->set_dport(acit.first.m_fields.m_dport);
	tuple->set_l4proto(acit.first.m_fields.m_l4proto);

	conn->set_spid(acit.first.m_fields.m_spid);
	conn->set_dpid(acit.first.m_fields.m_dpid);

	acit.second.m_metrics.to_protobuf(conn->mutable_counters(), m_acked_sampling_ratio);
	acit.second.m_transaction_metrics.to_protobuf(
	    conn->mutable_counters()->mutable_transaction_counters(),
	    conn->mutable_counters()->mutable_max_transaction_counters(),
	    m_acked_sampling_ratio);

	//
	// The timestamp field is used to count the number of sub-connections
	//
	conn->mutable_counters()->set_n_aggregated_connections((uint32_t)acit.second.m_timestamp);
}

template<typename T>
void sinsp_analyzer::emit_full_connection(T& conn,
                                          draiosproto::connection_state& conn_state,
                                          std::pair<const _ipv4tuple, sinsp_connection>& cit)
{
	conn->set_state(conn_state);
	conn->set_error_code(pb_error_code(cit.second.m_error_code));
	draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

	tuple->set_sip(htonl(cit.first.m_fields.m_sip));
	tuple->set_dip(htonl(cit.first.m_fields.m_dip));
	tuple->set_sport(cit.first.m_fields.m_sport);
	tuple->set_dport(cit.first.m_fields.m_dport);
	tuple->set_l4proto(cit.first.m_fields.m_l4proto);

	conn->set_spid(cit.second.m_spid);
	conn->set_dpid(cit.second.m_dpid);

	cit.second.m_metrics.to_protobuf(conn->mutable_counters(), m_acked_sampling_ratio);
	cit.second.m_transaction_metrics.to_protobuf(
	    conn->mutable_counters()->mutable_transaction_counters(),
	    conn->mutable_counters()->mutable_max_transaction_counters(),
	    m_acked_sampling_ratio);
}

void sinsp_analyzer::emit_full_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;

	for (cit = m_ipv4_connections->m_connections.begin();
	     cit != m_ipv4_connections->m_connections.end();)
	{
		//
		// We only include connections that had activity during the sample
		//
		if (cit->second.is_active() || m_simpledriver_enabled)
		{
			auto conn_state = pb_connection_state(cit->second.m_analysis_flags);
			if (conn_state == draiosproto::CONN_SUCCESS)
			{
				auto conn = m_metrics->add_ipv4_connections();
				emit_full_connection<decltype(conn)>(conn, conn_state, *cit);
			}
			else
			{
				auto conn = m_metrics->add_ipv4_incomplete_connections();
				emit_full_connection<decltype(conn)>(conn, conn_state, *cit);
			}
		}

		//
		// Add this connection's bytes to the host network volume
		//
		if (!cit->second.is_client_and_server())
		{
			if (cit->second.is_server_only())
			{
				m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in,
				                0,
				                cit->second.m_metrics.m_server.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out,
				                 0,
				                 cit->second.m_metrics.m_server.m_bytes_out);
			}
			else
			{
				ASSERT(cit->second.is_client_only())
				m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in,
				                0,
				                cit->second.m_metrics.m_client.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out,
				                 0,
				                 cit->second.m_metrics.m_client.m_bytes_out);
			}
		}

		//
		// Has this connection been closed druring this sample?
		//
		if (cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}
}

vector<long> sinsp_analyzer::get_n_tracepoint_diff()
{
	static run_on_interval log_interval(300 * ONE_SECOND_IN_NS);

	auto print_cpu_vec = [this](const vector<long>& v, stringstream& ss) {
		for (unsigned j = 0; j < v.size(); ++j)
		{
			ss << " cpu[" << j << "]=" << v[j];
		}
	};

	vector<long> n_evts_by_cpu;
	try
	{
		n_evts_by_cpu = m_inspector->get_n_tracepoint_hit();
	}
	catch (sinsp_exception e)
	{
		log_interval.run(
		    [&e]() {
			    g_logger.format(sinsp_logger::SEV_ERROR, "Event count query failed: %s", e.what());
		    },
		    sinsp_utils::get_current_time_ns());
	}
	catch (...)
	{
		log_interval.run(
		    []() {
			    g_logger.log("Event count query failed with an unknown error",
			                 sinsp_logger::SEV_ERROR);
		    },
		    sinsp_utils::get_current_time_ns());
	}

	if (n_evts_by_cpu.empty())
	{
		return n_evts_by_cpu;
	}
	else if (n_evts_by_cpu.size() != m_last_total_evts_by_cpu.size())
	{
		g_logger.log("Event count history mismatch, clearing history", sinsp_logger::SEV_ERROR);
		m_last_total_evts_by_cpu = move(n_evts_by_cpu);
		return vector<long>();
	}

	vector<long> evts_per_second_by_cpu(n_evts_by_cpu.size());
	for (unsigned j = 0; j < n_evts_by_cpu.size(); ++j)
	{
		evts_per_second_by_cpu[j] = n_evts_by_cpu[j] - m_last_total_evts_by_cpu[j];
	}
	m_last_total_evts_by_cpu = move(n_evts_by_cpu);

	if (g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		stringstream ss;
		ss << "Raw events per cpu: ";
		print_cpu_vec(evts_per_second_by_cpu, ss);
		g_logger.log(ss.str(), sinsp_logger::SEV_DEBUG);
	}
	return evts_per_second_by_cpu;
}

void sinsp_analyzer::adjust_sampling_ratio()
{
	// m_my_cpuload is amount of time used by the thread in centi-cores
	// flush_cpu_pct is the % of total wall time spent in flush vs not in flush.
	// so sampling_metric is really non-flush time in centi-cores
	uint64_t sampling_metric = m_my_cpuload * (1 - m_prev_flush_cpu_pct);
	g_logger.log("m_prev_flush_cpu_pct=" + std::to_string(m_prev_flush_cpu_pct) +
	                 ", m_my_cpuload=" + std::to_string(m_my_cpuload) + " (" +
	                 std::to_string(sampling_metric) + '/' +
	                 std::to_string(m_acked_sampling_ratio) + ')',
	             sinsp_logger::SEV_DEBUG);

	// While the check_disable_dropping function is generally opaque, there are two use cases which
	// we want to ensure it supports 1) dropping getting disabled in the middle of runtime, in which
	// case, we have to
	//    set the value back to 1
	// 2) configurations in which dropping ought not be there at all from the start due
	//    to the way that sinsp is configured and in which case we should avoid calls at all.
	//    This latter case should likely be dealt with via autodrop.enabled config, but it
	//    isn't right now
	if (m_check_disable_dropping())
	{
		if (m_requested_sampling_ratio != 1)
		{
			m_inspector->start_dropping_mode(1);
			m_requested_sampling_ratio = 1;
		}
		return;
	}

	// in certain cases we request a switch to nodriver mode.
	// This is handled in sinsp_worker, but should probably be handled here.
	if (m_inspector->is_live() && !security_config::is_enabled())
	{
		auto evts_per_second_by_cpu = get_n_tracepoint_diff();
		auto max_iter = max_element(evts_per_second_by_cpu.begin(), evts_per_second_by_cpu.end());
		decltype(evts_per_second_by_cpu)::value_type max_evts_per_second = 0;
		if (max_iter != evts_per_second_by_cpu.end())
		{
			max_evts_per_second = *max_iter;
		}
		m_total_evts_switcher.run_on_threshold(max_evts_per_second, [this]() {
			m_mode_switch_state = sinsp_analyzer::MSR_REQUEST_NODRIVER;
		});

		if (m_acked_sampling_ratio >= 128)
		{
			m_very_high_cpu_switcher.run_on_threshold(sampling_metric, [this]() {
				m_mode_switch_state = sinsp_analyzer::MSR_REQUEST_NODRIVER;
			});
		}
	}

	// first check for forcing the ratio, and ignore all else
	if (c_fixed_sampling_ratio->get_value() != 0)
	{
		m_inspector->start_dropping_mode(c_fixed_sampling_ratio->get_value());
		m_requested_sampling_ratio = c_fixed_sampling_ratio->get_value();
		return;
	}

	double upper_threshold = m_configuration->get_falco_baselining_enabled()
	                             ? (double)c_drop_upper_threshold_baseliner->get_value()
	                             : (double)c_drop_upper_threshold->get_value();
	if (c_adjust_threshold_for_cpu_count->get_value())
	{
		ASSERT(m_machine_info->num_cpus > 0);
		upper_threshold = std::min(upper_threshold + m_machine_info->num_cpus - 1, (double)100);
	}
	if (sampling_metric >= upper_threshold)
	{
		m_seconds_above_thresholds++;

		g_logger.format(sinsp_logger::SEV_INFO,
		                "sinsp above drop threshold %d secs: %" PRIu32 ":%" PRIu32,
		                (int)c_drop_upper_threshold->get_value(),
		                m_seconds_above_thresholds,
		                c_drop_seconds_before_action->get_value());
	}
	else
	{
		m_seconds_above_thresholds = 0;
	}

	if (m_seconds_above_thresholds >= c_drop_seconds_before_action->get_value())
	{
		m_seconds_above_thresholds = 0;

		if (m_acked_sampling_ratio < 128)
		{
			m_requested_sampling_ratio = std::min(m_acked_sampling_ratio * 2, (uint64_t)128);

			if (m_falco_baseliner->is_baseline_calculation_enabled())
			{
				g_logger.format(sinsp_logger::SEV_WARNING, "disabling falco baselining");
				m_falco_baseliner->disable_baseline_calculation();
				m_falco_baseliner->clear_tables();
			}

			m_inspector->start_dropping_mode(m_requested_sampling_ratio);
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
			                "sinsp Reached maximum sampling ratio and still too high");
		}
	}

	double lower_threshold = m_configuration->get_falco_baselining_enabled()
	                             ? (double)c_drop_lower_threshold_baseliner->get_value()
	                             : (double)c_drop_lower_threshold->get_value();
	if (c_adjust_threshold_for_cpu_count->get_value())
	{
		ASSERT(m_machine_info->num_cpus > 0);
		lower_threshold =
		    std::min(lower_threshold + (m_machine_info->num_cpus - 1) * 4 / (double)5, (double)90);
	}
	if (sampling_metric <= lower_threshold)
	{
		m_seconds_below_thresholds++;

		if (m_acked_sampling_ratio > 1)
		{
			g_logger.format(sinsp_logger::SEV_INFO,
			                "sinsp below drop threshold %d secs: %" PRIu32 ":%" PRIu32,
			                (int)c_drop_lower_threshold->get_value(),
			                m_seconds_below_thresholds,
			                c_drop_seconds_before_action->get_value());
		}
	}
	else
	{
		m_seconds_below_thresholds = 0;
	}

	if (m_seconds_below_thresholds >= c_drop_seconds_before_action->get_value())
	{
		m_seconds_below_thresholds = 0;

		if (m_acked_sampling_ratio > 1)
		{
			// before blindly dropping the ratio, perform a check that we believe
			// we have enough CPU to lower it
			double totcpuload = 0;
			ASSERT(m_machine_info->num_cpus == m_proc_stat.m_loads.size());
			for (unsigned j = 0; j < m_proc_stat.m_loads.size(); j++)
			{
				ASSERT(m_proc_stat.m_user.size() > j);
				totcpuload += m_proc_stat.m_user[j];
				ASSERT(m_proc_stat.m_nice.size() > j);
				totcpuload += m_proc_stat.m_nice[j];
				ASSERT(m_proc_stat.m_system.size() > j);
				totcpuload += m_proc_stat.m_system[j];
				ASSERT(m_proc_stat.m_irq.size() > j);
				totcpuload += m_proc_stat.m_irq[j];
				ASSERT(m_proc_stat.m_softirq.size() > j);
				totcpuload += m_proc_stat.m_softirq[j];
			}

			// note that available CPU here includes time which is being stolen
			double avail_cpu = (m_machine_info->num_cpus * 100.0) - totcpuload;
			ASSERT(avail_cpu + .00000001 >= 0);
			g_logger.log("avail_cpu=" + std::to_string(avail_cpu) +
			                 ", m_my_cpuload=" + std::to_string(m_my_cpuload),
			             sinsp_logger::SEV_DEBUG);

			// this check is a bit weird. In the worst case. In worst case, when we
			// decrease the sampling ratio, the non-flush time (effectively the threshold
			// metric) should double. That would make our new cpu time:
			//
			// m_my_cpuload + threshold metric
			//
			// And we would want to check that the increase was less than the available CPU.
			//
			// That check, however, would be likely overly aggressive, since halving the
			// ratio is unlikely to double the time, due to overhead from never_drop events
			// and other things.
			//
			// This check, though, doesn't seem to be doing that. It seems that
			// we are trying to limit our total CPU usage if the box is under pressure.
			//
			// If that is the case, however, we should be checking this value all the time,
			// and not just when we are attempting to decrease the value. It's likely
			// we need a more holistic solution to tailoring sampling ratio to CPU
			// usage instead of a one-off. SMAGENT-2208
			if (m_my_cpuload > avail_cpu)
			{
				return;
			}

			m_requested_sampling_ratio = std::max(m_acked_sampling_ratio / 2, (uint64_t)1);

			g_logger.format(sinsp_logger::SEV_INFO,
			                "sinsp -- Setting drop mode to %" PRIu32,
			                m_requested_sampling_ratio);
			m_inspector->start_dropping_mode(m_requested_sampling_ratio);
		}
	}
}

bool executed_command_cmp(const sinsp_executed_command& src, const sinsp_executed_command& dst)
{
	return (src.m_ts < dst.m_ts);
}

void sinsp_analyzer::emit_executed_commands(draiosproto::metrics* host_dest,
                                            draiosproto::container* container_dest,
                                            vector<sinsp_executed_command>* commands)
{
	if (commands->size() != 0)
	{
		sort(commands->begin(), commands->end(), executed_command_cmp);

		if (m_internal_metrics)
		{
			// The metrics are based on the number of command
			// lines identified, not returned.
			m_internal_metrics->set_n_command_lines(commands->size());

			// command line categories stored separately as
			// based on config, the commands themselves may not
			// actually be saved.
			m_internal_metrics->set_command_categories(m_command_categories);
		}

		//
		// if there are too many commands, try to aggregate by command line
		//
		uint32_t cmdcnt = 0;

		vector<sinsp_executed_command>::iterator it;

		for (it = commands->begin(); it != commands->end(); ++it)
		{
			if (!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if (cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> cmdlines;

			for (it = commands->begin(); it != commands->end(); ++it)
			{
				if (!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit =
					    cmdlines.find(it->m_cmdline);
					if (eit == cmdlines.end())
					{
						cmdlines[it->m_cmdline] = &(*it);
					}
					else
					{
						eit->second->m_count++;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		//
		// if there are STILL too many commands, try to aggregate by executable
		//
		cmdcnt = 0;

		for (it = commands->begin(); it != commands->end(); ++it)
		{
			if (!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if (cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> exes;

			for (it = commands->begin(); it != commands->end(); ++it)
			{
				if (!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit = exes.find(it->m_exe);
					if (eit == exes.end())
					{
						exes[it->m_exe] = &(*it);
						it->m_flags |= sinsp_executed_command::FL_EXEONLY;
					}
					else
					{
						eit->second->m_count += it->m_count;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		cmdcnt = 0;
		for (it = commands->begin(); it != commands->end(); ++it)
		{
			if (!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;

				if (cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
				{
					break;
				}

				draiosproto::command_details* cd;

				if (host_dest)
				{
					ASSERT(container_dest == NULL);
					cd = host_dest->add_commands();
				}
				else
				{
					ASSERT(host_dest == NULL);
					ASSERT(container_dest != NULL);
					cd = container_dest->add_commands();
				}

				cd->set_timestamp(it->m_ts);
				cd->set_count(it->m_count);
				cd->set_login_shell_id(it->m_shell_id);
				cd->set_login_shell_distance(it->m_login_shell_distance);
				cd->set_comm(it->m_comm);
				cd->set_pid(it->m_pid);
				cd->set_ppid(it->m_ppid);
				cd->set_uid(it->m_uid);
				cd->set_cwd(it->m_cwd);
				cd->set_tty(it->m_tty);
				cd->set_category(it->m_category);

				if (it->m_flags & sinsp_executed_command::FL_EXEONLY)
				{
					cd->set_cmdline(it->m_exe);
				}
				else
				{
					cd->set_cmdline(it->m_cmdline);
				}
			}
		}
	}
}

void sinsp_analyzer::secure_profiling_data_ready(
    const uint64_t ts,
    const secure::profiling::fingerprint* const secure_profiling_fingerprint)
{
	m_secure_profiling_handler.secure_profiling_data_ready(ts, secure_profiling_fingerprint);
}

void sinsp_analyzer::emit_baseline(sinsp_evt* evt, bool is_eof, const tracer_emitter& f_trc)
{
	//
	// if it's time to emit the falco baseline, do the serialization and then restart it
	//
	tracer_emitter falco_trc("falco_baseline", f_trc);
	if (m_falco_baseliner->is_baseline_calculation_enabled())
	{
		scap_stats st;
		m_inspector->get_capture_stats(&st);

		if (is_eof)
		{
			//
			// Make sure to push a baseline when reading from file and we reached EOF
			//
			m_falco_baseliner->emit_as_protobuf(0);
		}
		else if (evt != NULL && evt->get_ts() - m_last_falco_dump_ts >
		                            m_configuration->get_falco_baselining_report_interval_ns())
		{
			if (m_last_falco_dump_ts != 0)
			{
				m_falco_baseliner->emit_as_protobuf(evt->get_ts());
			}

			m_last_falco_dump_ts = evt->get_ts();
		}
	}
	else if (m_configuration->get_falco_baselining_enabled())
	{
		//
		// Once in a while, try to turn baseline calculation on again
		//
		if (m_acked_sampling_ratio == 1)
		{
			if (evt != NULL &&
			    evt->get_ts() - m_last_falco_dump_ts >
			    m_configuration->get_falco_baselining_autodisable_interval_ns())
			{
				//
				// It's safe to turn baselining on again.
				// Reset the tables and restart the baseline time counter.
				//
				scap_stats st;
				m_inspector->get_capture_stats(&st);

				m_falco_baseliner->clear_tables();
				m_falco_baseliner->enable_baseline_calculation();
				m_last_falco_dump_ts = evt->get_ts();
				m_falco_baseliner->load_tables(evt->get_ts());
				g_logger.format(
					"enabling falco baselining creation after a %lus pause",
					m_configuration->get_falco_baselining_autodisable_interval_ns() /
					1000000000);
			}
		}
		else
		{
			//
			// Sampling ratio is still high, reset the baseline counter
			//
			m_last_falco_dump_ts = evt->get_ts();
		}
	}
	if (m_internal_metrics)
	{
		m_internal_metrics->set_baseliner_enabled(
		    m_falco_baseliner->is_baseline_calculation_enabled());
	}

	falco_trc.stop();
}

#define HIGH_EVT_THRESHOLD 300 * 1000
#define HIGH_SINGLE_EVT_THRESHOLD 100 * 1000

void sinsp_analyzer::flush(sinsp_evt* evt,
                           uint64_t ts,
                           bool is_eof,
                           analyzer_emitter::flush_flags flushflags)
{
	tracer_emitter f_trc("analyzer_flush", flush_tracer_timeout());
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		calculate_analyzer_cpu_usage();
	}
	m_cputime_analyzer.begin_flush();
	uint32_t j;
	uint64_t flush_start_ns = sinsp_utils::get_current_time_ns();

	//
	// Skip the events if the analyzer has not been initialized yet
	//
	if (!m_initialized)
	{
		return;
	}

	if (c_dragent_cpu_profile.get_value())
	{
		if (!m_trace_started)
		{
			m_trace_started = true;
			std::string filename =
			    m_configuration->get_log_dir() + "/drcpu.prof." + to_string(m_trace_count);
			utils::profiler::start(filename);
			m_last_profile_flush_ns = flush_start_ns;
		}
		if ((flush_start_ns - m_last_profile_flush_ns) / 1000000000 >
		    c_dragent_cpu_profile_seconds.get_value())
		{
			utils::profiler::stop();
			m_trace_count++;
			m_trace_count %= c_dragent_cpu_profile_total_profiles.get_value();
			std::string filename =
			    m_configuration->get_log_dir() + "/drcpu.prof." + to_string(m_trace_count);
			utils::profiler::start(filename.c_str());
			m_last_profile_flush_ns = flush_start_ns;
		}
	}

	if (flushflags == analyzer_emitter::DF_FORCE_NOFLUSH)
	{
		return;
	}

	user_configured_limits::check_log_required<metric_limits>();

	for (j = 0;; j++)
	{
		if (flushflags == analyzer_emitter::DF_FORCE_FLUSH ||
		    flushflags == analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			//
			// Make sure we don't generate too many samples in case of subsampling
			//
			if (j > 0)
			{
				break;
			}
		}
		else
		{
			if (m_next_flush_time_ns > ts)
			{
				break;
			}
		}

		uint64_t sample_duration = get_sample_duration();

		if (m_next_flush_time_ns == 0)
		{
			//
			// This is the very first event, just initialize the times for future use
			//
			m_next_flush_time_ns = ts - ts % sample_duration + sample_duration;
			m_prev_flush_time_ns = m_next_flush_time_ns - sample_duration;
		}
		else
		{
			m_n_flushes++;

			//
			// Update the times
			//
			m_prev_flush_time_ns = ts - ts % sample_duration;
			m_next_flush_time_ns = m_prev_flush_time_ns + sample_duration;

			ASSERT(m_next_flush_time_ns / sample_duration * sample_duration ==
			       m_next_flush_time_ns);
			ASSERT(m_prev_flush_time_ns / sample_duration * sample_duration ==
			       m_prev_flush_time_ns);

			if (m_inspector->is_nodriver())
			{
				tracer_emitter pr_trc("refresh_proclist", f_trc);
				m_proclist_refresher_interval.run(
				    [this]() {
					    g_logger.log("Refreshing proclist", sinsp_logger::SEV_DEBUG);
					    this->m_inspector->refresh_proc_list();
				    },
				    m_prev_flush_time_ns);
			}

			//
			// Calculate CPU load
			//
			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				//
				// Make sure that there's been enough time since the previous call to justify
				// getting CPU info from proc
				//
				uint64_t wall_time = sinsp_utils::get_current_time_ns();

				if ((int64_t)(wall_time - m_prev_flush_wall_time) < 500000000 ||
				    m_inspector->is_capture())
				{
					if (!m_inspector->is_capture())
					{
						g_logger.format(sinsp_logger::SEV_ERROR,
						                "sample emission too fast (%" PRId64
						                "), skipping scanning proc",
						                (int64_t)(wall_time - m_prev_flush_wall_time));
					}

					m_skip_proc_parsing = true;
				}
				else
				{
					m_prev_flush_wall_time = wall_time;
					m_skip_proc_parsing = false;
					tracer_emitter ps_trc("get_proc_stat", f_trc);
					m_procfs_parser->get_proc_stat(&m_proc_stat);
				}
			}

			//
			// Flush the scheduler analyzer
			//
#ifndef CYGWING_AGENT
			if (m_inspector->m_thread_manager->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD)
			{
				m_sched_analyzer2->flush(evt, m_prev_flush_time_ns, is_eof, flushflags);
			}
#endif

			//
			// Reset the protobuffer
			//
			m_metrics = make_unique<draiosproto::metrics>();

			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT &&
			    !m_inspector->is_capture())
			{
#ifndef CYGWING_AGENT
				// Only run every 10 seconds or 5 minutes
				if (m_configuration->get_cointerface_enabled() &&
				    m_configuration->get_swarm_enabled())
				{
					tracer_emitter ss_trc("get_swarm_state", f_trc);
					m_swarmstate_interval.run(
					    [this]() {
						    g_logger.format(sinsp_logger::SEV_DEBUG, "Sending Swarm State Command");
						    //  callback to be executed during coclient::process_queue()
						    coclient::response_cb_t callback =
						        [this](bool successful, google::protobuf::Message* response_msg) {
							        m_metrics->mutable_swarm()->Clear();
							        if (successful)
							        {
								        sdc_internal::swarm_state_result* res =
								            (sdc_internal::swarm_state_result*)response_msg;
								        g_logger.format(sinsp_logger::SEV_DEBUG,
								                        "Received Swarm State: size=%d",
								                        res->state().ByteSize());
								        m_docker_swarm_state->CopyFrom(res->state());
								        if (!res->successful())
								        {
									        g_logger.format(
									            sinsp_logger::SEV_DEBUG,
									            "Swarm state poll returned error: %s, changing "
									            "interval to %lds\n",
									            res->errstr().c_str(),
									            SWARM_POLL_FAIL_INTERVAL / ONE_SECOND_IN_NS);
									        m_swarmstate_interval.interval(
									            SWARM_POLL_FAIL_INTERVAL);
								        }
								        else if (m_swarmstate_interval.interval() >
								                 SWARM_POLL_INTERVAL)
								        {
									        g_logger.format(sinsp_logger::SEV_DEBUG,
									                        "Swarm state poll recovered, changing "
									                        "interval back to %lds\n",
									                        SWARM_POLL_INTERVAL / ONE_SECOND_IN_NS);
									        m_swarmstate_interval.interval(SWARM_POLL_INTERVAL);
								        }
							        }
							        else
							        {
								        g_logger.format(
								            sinsp_logger::SEV_DEBUG,
								            "Swarm state poll failed, setting interval to %lds\n",
								            SWARM_POLL_FAIL_INTERVAL / ONE_SECOND_IN_NS);
								        m_swarmstate_interval.interval(SWARM_POLL_FAIL_INTERVAL);
							        }
						        };
						    m_coclient.get_swarm_state(callback);
					    },
					    sinsp_utils::get_current_time_ns());
					// Read available responses
					m_coclient.process_queue();
					ss_trc.stop();
					tracer_emitter copy_trc("copy_swarm_state", f_trc);
					// Copy from cached swarm state
					m_metrics->mutable_swarm()->CopyFrom(*m_docker_swarm_state);
				}
#endif

				tracer_emitter gs_trc("get_statsd", f_trc);
				m_statsd_emitter->fetch_metrics(m_prev_flush_time_ns);

				if (m_mounted_fs_proxy)
				{
					// Get last filesystem stats, list of containers is sent on emit_processes
					auto new_fs_map = m_mounted_fs_proxy->receive_mounted_fs_list();
					if (!new_fs_map.m_mounted_fs.empty())
					{
						m_mounted_fs_map = move(new_fs_map.m_mounted_fs);
						m_device_map = move(new_fs_map.m_device_map);
					}
				}
			}

			////////////////////////////////////////////////////////////////////////////
			// EMIT PROCESSES
			////////////////////////////////////////////////////////////////////////////
			// XXX We're trying to avoid passing around tracer_emitter
			// refs, but do it here since emit_processes() calls a lot
			// of other important functions and we want to maintain
			// the parent/child relationship of the span IDs
			//
			// The tracer_emitter foremit_processes is created
			// inside the func to take advantage of scoping
			emit_processes(evt, sample_duration, is_eof, flushflags, f_trc);

			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
				                "IPv4 table size:%d",
				                m_ipv4_connections->m_connections.size());

				if (m_ipv4_connections->get_n_drops() != 0)
				{
					g_logger.format(sinsp_logger::SEV_ERROR,
					                "IPv4 table drops:%d",
					                m_ipv4_connections->get_n_drops());

					m_ipv4_connections->clear_n_drops();
				}
			}

			tracer_emitter fp_trc("flush_processes", f_trc);
			flush_processes();
			fp_trc.stop();

			////////////////////////////////////////////////////////////////////////////
			// EMIT THE LIST OF INTERFACES
			////////////////////////////////////////////////////////////////////////////
			vector<sinsp_ipv4_ifinfo>* v4iflist =
			    m_inspector->m_network_interfaces->get_ipv4_list();
			for (uint32_t k = 0; k < v4iflist->size(); k++)
			{
				draiosproto::ipv4_network_interface* ni = m_metrics->add_ipv4_network_interfaces();

				ni->set_name(v4iflist->at(k).m_name);
				ni->set_addr(htonl(v4iflist->at(k).m_addr));
				ni->set_netmask(htonl(v4iflist->at(k).m_netmask));
			}

			////////////////////////////////////////////////////////////////////////////
			// emit host stuff
			////////////////////////////////////////////////////////////////////////////
			m_metrics->set_machine_id(m_configuration->get_machine_id());
			m_metrics->set_customer_id(m_configuration->get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);
			m_metrics->set_sampling_ratio(m_acked_sampling_ratio);

			m_metrics->mutable_hostinfo()->set_hostname(sinsp_gethostname());
			m_metrics->mutable_hostinfo()->set_num_cpus(m_machine_info->num_cpus);
			m_metrics->mutable_hostinfo()->set_physical_memory_size_bytes(
			    m_inspector->m_machine_info->memory_size_bytes);

			//
			// Map customizations coming from the analyzer.
			//
			m_metrics->set_host_custom_name(m_configuration->get_host_custom_name());
#ifndef CYGWING_AGENT
			m_metrics->set_host_tags(std::move(get_host_tags_with_cluster()));
#endif
			m_metrics->set_is_host_hidden(m_configuration->get_host_hidden());
			m_metrics->set_hidden_processes(m_configuration->get_hidden_processes());
			m_metrics->set_version(m_configuration->get_version());
			if (!m_configuration->get_instance_id().empty())
			{
				m_metrics->set_instance_id(m_configuration->get_instance_id());
			}

			ASSERT(m_proc_stat.m_loads.size() == 0 ||
			       m_proc_stat.m_loads.size() == m_machine_info->num_cpus);
			ASSERT(m_proc_stat.m_loads.size() == m_proc_stat.m_steal.size());

			for (uint32_t k = 0; k < m_proc_stat.m_loads.size(); k++)
			{
				if ((g_logger.get_severity() >= sinsp_logger::SEV_DEBUG) &&
				    (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT))
				{
					g_logger.log("CPU[" + to_string(k) +
					                 "]: us=" + to_string(m_proc_stat.m_user[k]) +
					                 ", sy=" + to_string(m_proc_stat.m_system[k]) +
					                 ", ni=" + to_string(m_proc_stat.m_nice[k]) +
					                 ", id=" + to_string(m_proc_stat.m_idle[k]) +
					                 ", wa=" + to_string(m_proc_stat.m_iowait[k]) +
					                 ", hi=" + to_string(m_proc_stat.m_irq[k]) +
					                 ", si=" + to_string(m_proc_stat.m_softirq[k]) +
					                 ", st=" + to_string((long double)m_proc_stat.m_steal[k]) +
					                 ", ld=" + to_string((long double)m_proc_stat.m_loads[k]),
					             sinsp_logger::SEV_DEBUG);
				}

#ifndef CYGWING_AGENT
				m_metrics->mutable_hostinfo()->add_cpu_loads(
				    (uint32_t)(m_proc_stat.m_loads[k] * 100));
				m_metrics->mutable_hostinfo()->add_cpu_steal(
				    (uint32_t)(m_proc_stat.m_steal[k] * 100));
				m_metrics->mutable_hostinfo()->add_cpu_idle(
				    (uint32_t)(m_proc_stat.m_idle[k] * 100));
				m_metrics->mutable_hostinfo()->add_user_cpu(
				    (uint32_t)(m_proc_stat.m_user[k] * 100));
				m_metrics->mutable_hostinfo()->add_nice_cpu(
				    (uint32_t)(m_proc_stat.m_nice[k] * 100));
				m_metrics->mutable_hostinfo()->add_system_cpu(
				    (uint32_t)(m_proc_stat.m_system[k] * 100));
				m_metrics->mutable_hostinfo()->add_iowait_cpu(
				    (uint32_t)(m_proc_stat.m_iowait[k] * 100));
#else
				m_metrics->mutable_hostinfo()->add_cpu_loads((uint32_t)(m_proc_stat.m_loads[k]));
				m_metrics->mutable_hostinfo()->add_cpu_idle((uint32_t)(m_proc_stat.m_idle[k]));
				m_metrics->mutable_hostinfo()->add_user_cpu((uint32_t)(m_proc_stat.m_user[k]));
				m_metrics->mutable_hostinfo()->add_system_cpu((uint32_t)(m_proc_stat.m_system[k]));
#endif
			}

			m_metrics->mutable_hostinfo()->set_uptime(m_proc_stat.m_uptime);

			// Log host syscall count
			auto top_calls = m_host_metrics.m_syscall_count.top_calls(5);
			auto sev = sinsp_logger::SEV_DEBUG;
			if (flushflags == analyzer_emitter::DF_FORCE_FLUSH ||
			    flushflags == analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT ||
			    m_host_metrics.m_syscall_count.total_calls() > HIGH_EVT_THRESHOLD ||
			    (top_calls.crbegin() != top_calls.crend() &&
			     top_calls.crbegin()->first > HIGH_SINGLE_EVT_THRESHOLD))
			{
				sev = sinsp_logger::SEV_INFO;
			}
			std::ostringstream call_log;
			call_log << "Top calls";
			if (flushflags == analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				call_log << " while sampling";
			}
			call_log << " (" << m_host_metrics.m_syscall_count.total_calls() << " total)";
			for (auto iter = top_calls.crbegin(); iter != top_calls.crend(); iter++)
			{
				call_log << ", " << sinsp_utils::event_name_by_id(iter->second) << "("
				         << iter->second << "):" << iter->first;
			}
			g_logger.log(call_log.str(), sev);

			if (!m_inspector->is_capture())
			{
				double loadavg[3] = {0};
				if (getloadavg(loadavg, 3) != -1)
				{
					m_metrics->mutable_hostinfo()->set_system_load_1(loadavg[0] * 100);
					m_metrics->mutable_hostinfo()->set_system_load_5(loadavg[1] * 100);
					m_metrics->mutable_hostinfo()->set_system_load_15(loadavg[2] * 100);
				}
				else
				{
					g_logger.log("Could not obtain load averages", sinsp_logger::SEV_WARNING);
				}

				m_procfs_parser->get_global_mem_usage_kb(&m_host_metrics.m_res_memory_used_kb,
				                                         &m_host_metrics.m_res_memory_free_kb,
				                                         &m_host_metrics.m_res_memory_avail_kb,
				                                         &m_host_metrics.m_swap_memory_used_kb,
				                                         &m_host_metrics.m_swap_memory_total_kb,
				                                         &m_host_metrics.m_swap_memory_avail_kb);
			}

			if (m_protocols_enabled)
			{
				sinsp_protostate_marker host_marker;
				host_marker.add(m_host_metrics.m_protostate);
				host_marker.mark_top(HOST_PROTOS_LIMIT);
				m_host_metrics.m_protostate->to_protobuf(m_metrics->mutable_protos(),
				                                         m_acked_sampling_ratio,
				                                         HOST_PROTOS_LIMIT);
			}

			//
			// host info
			//
#ifndef CYGWING_AGENT
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_capacity_score(
			    (uint32_t)(m_host_metrics.get_capacity_score() * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_stolen_capacity_score(
			    (uint32_t)(m_host_metrics.get_stolen_score() * 100));
			m_metrics->mutable_hostinfo()
			    ->mutable_resource_counters()
			    ->set_connection_queue_usage_pct(m_host_metrics.m_connection_queue_usage_pct);
#endif
			m_metrics->mutable_hostinfo()
			    ->mutable_resource_counters()
			    ->set_resident_memory_usage_kb((uint32_t)m_host_metrics.m_res_memory_used_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_usage_kb(
			    (uint32_t)m_host_metrics.m_swap_memory_used_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_total_kb(
			    (uint32_t)m_host_metrics.m_swap_memory_total_kb);
			m_metrics->mutable_hostinfo()
			    ->mutable_resource_counters()
			    ->set_swap_memory_available_kb(m_host_metrics.m_swap_memory_avail_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_major_pagefaults(
			    m_host_metrics.m_pfmajor);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_minor_pagefaults(
			    m_host_metrics.m_pfminor);
			m_host_metrics.m_syscall_errors.to_protobuf(
			    m_metrics->mutable_hostinfo()->mutable_syscall_errors(),
			    m_acked_sampling_ratio);
			if (!m_inspector->is_nodriver())
			{
				// These metrics are not correct in nodriver mode
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_count(
				    m_host_metrics.m_fd_count);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_usage_pct(
				    m_host_metrics.m_fd_usage_pct);
			}
			m_metrics->mutable_hostinfo()->set_memory_bytes_available_kb(
			    m_host_metrics.m_res_memory_avail_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_count_processes(
			    m_host_metrics.get_process_count());
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_proc_start_count(
			    m_host_metrics.get_process_start_count());
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_threads_count(
			    m_host_metrics.m_threads_count);

			if (m_mounted_fs_proxy)
			{
				auto fs_list = m_mounted_fs_map.find("host");
				if (fs_list != m_mounted_fs_map.end())
				{
					for (auto it = fs_list->second.begin(); it != fs_list->second.end(); ++it)
					{
						draiosproto::mounted_fs* fs = m_metrics->add_mounts();
						it->to_protobuf(fs);
					}
				}
			}
			else if (!m_inspector->is_capture())  // When not live, fs stats break regression tests
			                                      // causing false positives
			{
				auto fs_list = m_mounted_fs_reader->get_mounted_fs_list();
				for (auto it = fs_list.begin(); it != fs_list.end(); ++it)
				{
					draiosproto::mounted_fs* fs = m_metrics->add_mounts();
					it->to_protobuf(fs);
				}
			}

			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_syscall_count(
			    m_host_metrics.m_syscall_count.total_calls());

#ifndef CYGWING_AGENT
			//
			// Executed commands
			//
			if (m_configuration->get_commandlines_capture_enabled())
			{
				emit_executed_commands(m_metrics.get(), NULL, &(m_executed_commands[""]));
			}

			//
			// Kubernetes
			//
			tracer_emitter k8s_trc("emit_k8s", f_trc);
			if (!m_configuration->get_go_k8s_user_events())
			{
				emit_k8s();
			}

			std::string k8s_url = m_infrastructure_state->get_k8s_url();
			if (m_configuration->get_go_k8s_user_events() && !k8s_url.empty() &&
			    !m_k8s_user_event_handler)
			{
				init_k8s_user_event_handler();
				m_k8s_user_event_handler->subscribe(
				    infrastructure_state::c_k8s_timeout_s.get_value(),
				    m_configuration->get_k8s_event_filter());
				glogf("k8s event message handler is now subscribed to the k8s APi server");
			}

			if (m_k8s_user_event_handler)
			{
				if (m_get_events != m_is_k8s_delegated)
				{
					// Only delegated agents should be sending K8s events.
					// If the delegation status changes tell cointerface to
					// start or stop sending events.
					m_get_events = m_is_k8s_delegated;
					if (m_get_events)
					{
						glogf("k8s_user_event: tell cointerface to start sending events");
						m_k8s_user_event_handler->start_event_stream();
					}
					else
					{
						glogf("k8s_user_event: tell cointerface to stop sending events");
						m_k8s_user_event_handler->stop_event_stream();
					}
				}

				m_k8s_user_event_handler->refresh(sinsp_utils::get_current_time_ns());
			}

			k8s_trc.stop();

			//
			// Mesos
			//
			tracer_emitter mesos_trc("emit_mesos", f_trc);
			emit_mesos();
			mesos_trc.stop();

			//
			// Docker
			//
			m_has_docker = Poco::File(docker::get_socket_file()).exists();
			static bool first_time = true;
			if (!m_has_docker)
			{
				if (first_time)
				{
					g_logger.log("Docker service not running, events will not be available.",
					             sinsp_logger::SEV_INFO);
				}
				first_time = false;
			}
			else if (m_configuration->get_docker_event_filter())
			{
				tracer_emitter docker_trc("emit_docker", f_trc);
				emit_docker_events();
			}

			//
			// containerd
			//
			if (m_configuration->get_container_filter())
			{
				tracer_emitter containerd_trc("emit_containerd", f_trc);
				emit_containerd_events();
			}

			tracer_emitter misc_trc("misc_emit", f_trc);
			m_fd_listener->m_files_stat.emit(m_metrics.get(), m_top_files_per_host);
			m_fd_listener->m_devs_stat.emit(m_metrics.get(),
			                                m_device_map,
			                                m_top_file_devices_per_host);

			m_fd_listener->m_files_stat.clear();
			m_fd_listener->m_devs_stat.clear();
#endif  // CYGWING_AGENT

			m_statsd_emitter->emit(m_metrics->mutable_hostinfo(),
			                       m_metrics->mutable_protos()->mutable_statsd());

#ifndef _WIN32

			// jmx metrics for the host
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_jmx_sent(0);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_jmx_total(0);
			if (m_jmx_metrics_by_containers.find("") != m_jmx_metrics_by_containers.end())
			{
				auto jmx_sent = std::get<0>(m_jmx_metrics_by_containers[""]);
				auto jmx_total = std::get<1>(m_jmx_metrics_by_containers[""]);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_jmx_sent(jmx_sent);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_jmx_total(
				    jmx_total);
			}
			// clear the cache for the next round of sampling
			m_jmx_metrics_by_containers.clear();

			// app checks for the host
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_app_checks_sent(0);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_app_checks_total(0);
			if (m_app_checks_by_containers.find("") != m_app_checks_by_containers.end())
			{
				auto checks_sent = std::get<0>(m_app_checks_by_containers[""]);
				auto checks_total = std::get<1>(m_app_checks_by_containers[""]);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_app_checks_sent(
				    checks_sent);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_app_checks_total(
				    checks_total);
			}
			// clear the cache for the next round of sampling
			m_app_checks_by_containers.clear();
			// prometheus for the host
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_sent(0);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_total(0);
			if (m_prometheus_by_containers.find("") != m_prometheus_by_containers.end())
			{
				auto checks_sent = std::get<0>(m_prometheus_by_containers[""]);
				auto checks_total = std::get<1>(m_prometheus_by_containers[""]);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_sent(
				    checks_sent);
				m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_total(
				    checks_total);
			}
			// clear the cache for the next round of sampling
			m_prometheus_by_containers.clear();
#endif

			//
			// Metrics coming from chisels
			//
			emit_chisel_metrics();

			//
			// User-configured events
			//
			emit_user_events();

			//
			// Percentile configuration
			//
			emit_percentiles_config();

#ifndef CYGWING_AGENT
			misc_trc.stop();

			//
			// Transactions
			//
			m_delay_calculator->compute_host_container_delays(&m_host_transaction_counters,
			                                                  &m_host_client_transactions,
			                                                  &m_host_server_transactions,
			                                                  &m_host_transaction_delays);

			m_host_transaction_counters.to_protobuf(
			    m_metrics->mutable_hostinfo()->mutable_transaction_counters(),
			    m_metrics->mutable_hostinfo()->mutable_max_transaction_counters(),
			    m_acked_sampling_ratio);

			if (m_host_transaction_delays.m_local_processing_delay_ns != -1)
			{
				m_metrics->mutable_hostinfo()->set_transaction_processing_delay(
				    m_host_transaction_delays.m_local_processing_delay_ns * m_acked_sampling_ratio);
				m_metrics->mutable_hostinfo()->set_next_tiers_delay(
				    m_host_transaction_delays.m_merged_client_delay * m_acked_sampling_ratio);
			}
#endif  // CYGWING_AGENT

			//
			// Time splits
			//
			m_host_metrics.m_metrics.to_protobuf(m_metrics->mutable_hostinfo()->mutable_tcounters(),
			                                     m_acked_sampling_ratio);
#ifdef CYGWING_AGENT
			//
			// On Windows, there's no I/O information by process, so we patch the I/O disk with
			// data coming from WMI.
			//
			wh_machine_disk_bandwidth_info mdbres =
			    wh_wmi_get_machine_disk_bandwidth(m_inspector->get_wmi_handle());
			if (mdbres.m_result != 0)
			{
				auto host_io_disk =
				    m_metrics->mutable_hostinfo()->mutable_tcounters()->mutable_io_file();
				host_io_disk->set_bytes_in(mdbres.m_bytes_in);
				host_io_disk->set_bytes_out(mdbres.m_bytes_out);
				host_io_disk->set_count_in(mdbres.m_count_in);
				host_io_disk->set_count_out(mdbres.m_count_out);
			}
#endif

#ifndef CYGWING_AGENT
			m_host_req_metrics.to_reqprotobuf(m_metrics->mutable_hostinfo()->mutable_reqcounters(),
			                                  m_acked_sampling_ratio);
#endif  // CYGWING_AGENT
			auto external_io_net = m_metrics->mutable_hostinfo()->mutable_external_io_net();
			m_io_net.to_protobuf(external_io_net, 1, m_acked_sampling_ratio);

			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				// We decided to patch host network metrics using data from /proc, because using
				// only sysdig metrics we miss kernel threads activity In this case, sampling_ratio
				// is not evaluated
				auto interfaces_stats = m_procfs_parser->read_network_interfaces_stats();
				if (interfaces_stats.first > 0 || interfaces_stats.second > 0)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "Patching host external networking, from (%u, %u) to (%u, %u)",
					                m_io_net.m_bytes_in,
					                m_io_net.m_bytes_out,
					                interfaces_stats.first,
					                interfaces_stats.second);
					// protobuf uint32 is converted to int in java. It means that numbers higher
					// than int max are translated into negative ones. This is a problem
					// specifically when agent loses samples and here we send current value - prev
					// read value. It can be very high so at this point let's patch it to avoid the
					// overflow
					static const auto max_int32 =
					    static_cast<uint32_t>(std::numeric_limits<int32_t>::max());
					external_io_net->set_bytes_in(std::min(interfaces_stats.first, max_int32));
					external_io_net->set_bytes_out(std::min(interfaces_stats.second, max_int32));
				}
			}
			m_metrics->mutable_hostinfo()->mutable_external_io_net()->set_time_ns_out(0);

			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "sinsp cpu: %lf", m_my_cpuload);

				g_logger.format(sinsp_logger::SEV_DEBUG,
				                "host times: %.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32
				                " out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
				                m_host_metrics.m_metrics.get_processing_percentage() * 100,
				                m_host_metrics.m_metrics.get_file_percentage() * 100,
				                m_host_metrics.m_metrics.m_tot_io_file.m_bytes_in,
				                m_host_metrics.m_metrics.m_tot_io_file.m_count_in,
				                m_host_metrics.m_metrics.m_tot_io_file.m_bytes_out,
				                m_host_metrics.m_metrics.m_tot_io_file.m_count_out,
				                m_host_metrics.m_metrics.get_net_percentage() * 100,
				                m_host_metrics.m_metrics.get_other_percentage() * 100);
			}

			if (m_host_transaction_counters.get_counter()->m_count_in +
			        m_host_transaction_counters.get_counter()->m_count_out !=
			    0)
			{
				if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
					                " host h:%.2f(s:%.2f)",
					                m_host_metrics.get_capacity_score(),
					                m_host_metrics.get_stolen_score());

					g_logger.format(
					    sinsp_logger::SEV_DEBUG,
					    "  trans)in:%" PRIu32 " out:%" PRIu32
					    " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
					    m_host_transaction_counters.get_counter()->m_count_in *
					        m_acked_sampling_ratio,
					    m_host_transaction_counters.get_counter()->m_count_out *
					        m_acked_sampling_ratio,
					    (float)m_host_transaction_counters.get_counter()->m_time_ns_in /
					        sample_duration,
					    (float)m_client_tr_time_by_servers / sample_duration,
					    (m_host_transaction_delays.m_local_processing_delay_ns != -1)
					        ? ((double)m_host_transaction_delays.m_merged_server_delay) /
					              sample_duration
					        : -1,
					    (m_host_transaction_delays.m_local_processing_delay_ns != -1)
					        ? ((double)m_host_transaction_delays.m_merged_client_delay) /
					              sample_duration
					        : -1,
					    (m_host_transaction_delays.m_local_processing_delay_ns != -1)
					        ? ((double)m_host_transaction_delays.m_local_processing_delay_ns) /
					              sample_duration
					        : -1);

					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "host transaction times: proc:%.2lf%% file:%.2lf%% net:%.2lf%% "
					                "other:%.2lf%%",
					                m_host_req_metrics.get_processing_percentage() * 100,
					                m_host_req_metrics.get_file_percentage() * 100,
					                m_host_req_metrics.get_net_percentage() * 100,
					                m_host_req_metrics.get_other_percentage() * 100);
				}
			}

			// Secure Audit - Emit and Flush
			if (m_secure_audit && m_sent_metrics &&
			    flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				uint64_t start_emit_time = sinsp_utils::get_current_time_ns();

				m_secure_audit->emit_commands_audit(&m_executed_commands);

				uint64_t emit_time_ms =
				    (sinsp_utils::get_current_time_ns() - start_emit_time) / 1000000;
				m_internal_metrics->set_secure_audit_emit_ms(emit_time_ms);

				m_secure_audit->flush(ts);
			}

			// Secure Profiling - Emit and Flush
			if (m_configuration->get_falco_baselining_enabled())
			{
				emit_baseline(evt, is_eof, f_trc);
			}

			//
			// Internal metrics
			// Should go after all the other emitters are done
			//
			if (m_internal_metrics)
			{
				scap_stats st = {};
				m_inspector->get_capture_stats(&st);

				m_internal_metrics->emit(m_metrics->mutable_protos()->mutable_statsd(),
				                         st,
				                         m_prev_flush_cpu_pct,
				                         m_acked_sampling_ratio,
				                         m_prev_flushes_duration_ns,
				                         m_inspector->m_n_proc_lookups,
				                         m_inspector->m_n_main_thread_lookups,
				                         m_inspector->max_buf_used(),
				                         static_cast<uint64_t>(m_my_cpuload + 0.500001));
			}

			////////////////////////////////////////////////////////
			// Serialize everything
			////////////////////////////////////////////////////////
			if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				// Complete the flush
				flush_done_handler(evt);
			}

			//
			// Reset the aggregated host metrics
			//
			m_host_metrics.clear();
			m_host_req_metrics.clear();
		}
	}

	////////////////////////////////////////////////////////////////////////
	// CLEANUPS
	////////////////////////////////////////////////////////////////////////

	//
	// Clear the transaction state
	//
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "# Client Transactions:%d",
		                m_trans_table->m_n_client_transactions * m_acked_sampling_ratio);
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "# Server Transactions:%d",
		                m_trans_table->m_n_server_transactions * m_acked_sampling_ratio);
	}

	m_trans_table->m_n_client_transactions = 0;
	m_trans_table->m_n_server_transactions = 0;

	m_host_transaction_counters.clear();
	m_client_tr_time_by_servers = 0;

	for (j = 0; j < m_host_server_transactions.size(); ++j)
	{
		m_host_server_transactions[j].clear();
	}

	for (j = 0; j < m_host_client_transactions.size(); ++j)
	{
		m_host_client_transactions[j].clear();
	}

	if (m_inspector->m_n_main_thread_lookups)
	{
		g_logger.format(sinsp_logger::SEV_INFO,
		                "Looked up %d main thread(s) in /proc",
		                m_inspector->m_n_main_thread_lookups);
	}
	if (m_inspector->m_n_proc_lookups)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "Looked up %d thread(s) in /proc (total time %lu ns)",
		                m_inspector->m_n_proc_lookups,
		                m_inspector->m_n_proc_lookups_duration_ns);
	}
	//
	// Reset the proc lookup counter
	//
	m_inspector->m_n_proc_lookups = 0;
	m_inspector->m_n_proc_lookups_duration_ns = 0;
	m_inspector->m_n_main_thread_lookups = 0;

	//
	// Clear the network I/O counter
	//
	m_io_net.clear();

	// Since we don't subsample EXECVE_X, it's safe to keep the executed
	// commands list. It will be sent in the next flush
	if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		//
		// Clear the executed command list
		//
		m_executed_commands.clear();
	}

	if (is_jmx_flushtime())
	{
		m_jmx_metrics.clear();
	}
	//
	// if there were tid collisions report them in the log and then clear the list
	//
	if (m_inspector->m_tid_collisions.size() != 0)
	{
		string tcb;

		for (j = 0; j < MIN(m_inspector->m_tid_collisions.size(), 16); j++)
		{
			tcb += to_string(m_inspector->m_tid_collisions[j]);
			tcb += " ";
		}

		g_logger.format(sinsp_logger::SEV_INFO,
		                "%d TID collisions (%s)",
		                (int)m_inspector->m_tid_collisions.size(),
		                tcb.c_str());

		if (m_inspector->m_tid_collisions.size() >= MAX_TID_COLLISIONS_IN_SAMPLE)
		{
			m_die = true;
		}

		m_inspector->m_tid_collisions.clear();
	}

	//
	// Run the periodic connection and thread table cleanup
	// This is run on every sample for NODRIVER mode
	// by forcing interval to 0
	//
	remove_expired_connections(ts);
	m_inspector->remove_inactive_threads();
	m_inspector->m_container_manager.remove_inactive_containers();

	if (evt)
	{
		if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			const uint64_t nevts_in_last_sample = evt->get_num() - m_prev_sample_evtnum;
			g_logger.format(sinsp_logger::SEV_DEBUG, "----- %" PRIu64 "", nevts_in_last_sample);
		}

		m_prev_sample_evtnum = evt->get_num();

		//
		// This thread might be removed, either by a procexit or by thread table
		// cleanup process
		// In either case, evt->m_tinfo would become invalid.
		// To avoid that, we refresh evt->m_tinfo.
		//
		evt->m_tinfo = NULL;  // This is important to avoid using a stale cached value!
		evt->m_tinfo = evt->get_thread_info();
	}

	m_prev_flushes_duration_ns = sinsp_utils::get_current_time_ns() - flush_start_ns;
	m_cputime_analyzer.end_flush();
	m_prev_flush_cpu_pct = m_cputime_analyzer.calc_flush_percent();

	if (c_autodrop_enabled->get_value() &&
	    flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		adjust_sampling_ratio();
	}

	if (m_falco_baseliner->is_baseline_calculation_enabled())
	{
		// If, between two emit interval, we notice a lot of
		// dropped events due to the buffer being full with
		// respect to the total number of events processed, we
		// disable the baseliner.
		scap_stats st;
		m_inspector->get_capture_stats(&st);
		if (m_falco_baseliner->is_drops_buffer_rate_critical(
		        m_configuration->get_falco_baselining_max_drops_buffer_rate_percentage()))
		{
			g_logger.format(sinsp_logger::SEV_WARNING,
			                "disabling falco baselining because of critical drops buffer rate.");
			m_falco_baseliner->disable_baseline_calculation();
			m_falco_baseliner->clear_tables();
		}
	}

	// audit tap data must be sent to the backend _after_ the main metrics object
	// as we're authenticated by the first metrics object we send
	if (m_tap && m_sent_metrics)
	{
		if (m_env_hash_config.m_send_audit_tap)
		{
			m_tap->emit_pending_envs(m_inspector);
		}
		auto tap_events = m_tap->get_events();
		if (tap_events)
		{
			m_audit_tap_handler.audit_tap_data_ready(ts, tap_events);
		}
		m_tap->clear();
	}

	if (f_trc.stop() > m_flush_log_time)
	{
		rearm_tracer_logging();
	}
}

void sinsp_analyzer::flush_done_handler(const sinsp_evt* evt)
{
	static uint64_t prev_sample_time = 0;

	// Calculate some internal timestamps and stats
	const uint64_t evt_num = evt ? evt->get_num() : flush_data_message::NO_EVENT_NUMBER;
	const uint64_t original_sample_len = c_flush_interval->get_value();
	const uint64_t ts = m_prev_flush_time_ns - (m_prev_flush_time_ns % original_sample_len);
	uint64_t nevts = 0;
	uint64_t num_drop_events = 0;

	// Get the number of dropped events and include that in the log message
	scap_stats st = {};
	m_inspector->get_capture_stats(&st);
	num_drop_events = st.n_drops - m_prev_sample_num_drop_events;
	m_prev_sample_num_drop_events = st.n_drops;

	// Handle bookkeeping
	if (evt_num != flush_data_message::NO_EVENT_NUMBER)
	{
		nevts = evt_num - m_prev_sample_evtnum;
		m_prev_sample_evtnum = evt_num;

		// Subsampling can cause repeated samples, which we skip here
		if (prev_sample_time != 0)
		{
			if (ts == prev_sample_time)
			{
				return;
			}
		}

		prev_sample_time = ts;
	}

	// The following message is used in some test automation. Change with caution.
	g_logger.format(sinsp_logger::SEV_INFO,
	                "ts=%" PRIu64 ", ne=%" PRIu64 ", de=%" PRIu64
	                ", c=%.2lf"
	                ", fp=%.2lf"
	                ", sr=%" PRIu32 ", st=%" PRIu64 ", fl=%" PRIu64,
	                ts / 1000000000,
	                nevts,
	                num_drop_events,
	                m_my_cpuload,
	                m_prev_flush_cpu_pct,
	                m_acked_sampling_ratio,
	                st.n_tids_suppressed,
	                m_prev_flushes_duration_ns / 1000000);

	// Send the metrics to the serializer
	m_flush_queue->put(std::make_shared<flush_data_message>(ts,
	                                                        &m_sent_metrics,
	                                                        std::move(m_metrics),
	                                                        nevts,
	                                                        num_drop_events,
	                                                        m_my_cpuload,
	                                                        m_acked_sampling_ratio,
	                                                        st.n_tids_suppressed));
}

//
// Parses a previous select/poll/epoll and account its time based on the successive I/O operation
//
void sinsp_analyzer::add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat)
{
	thread_analyzer_info* tainfo = GET_AGENT_THREAD(evt->m_tinfo);
	int64_t wd = tainfo->m_last_wait_duration_ns;

	ASSERT(tainfo != NULL);

	if (wd != 0)
	{
		uint64_t we = tainfo->m_last_wait_end_time_ns;

		if (we >= m_prev_flush_time_ns)
		{
			uint64_t ws;
			uint64_t delta;

			if (wd > 0)
			{
				ws = we - wd;
			}
			else
			{
				ws = we + wd;
			}

			delta = we - MAX(ws, m_prev_flush_time_ns);

			sinsp_counters* metrics = &tainfo->m_metrics;

			//
			// This can happen in case of event drops
			//
			if (delta > metrics->m_wait_other.m_time_ns)
			{
				tainfo->m_last_wait_duration_ns = 0;
				tainfo->m_last_wait_end_time_ns = 0;
				return;
			}

			if (cat->m_category == EC_FILE)
			{
				metrics->m_wait_file.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if (cat->m_category == EC_NET)
			{
				metrics->m_wait_net.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if (cat->m_category == EC_IPC)
			{
				metrics->m_wait_ipc.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else
			{
				switch (cat->m_subcategory)
				{
				case sinsp_evt::SC_NET:
					if (cat->m_category == EC_IO_READ)
					{
						break;
					}
					else if (cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_net.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_net.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_FILE:
					if (cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_file.add_in(1, delta);
					}
					else if (cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_file.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_file.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_IPC:
					if (cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_ipc.add_in(1, delta);
					}
					else if (cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_ipc.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_ipc.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				default:
					break;
				}
			}
		}

		tainfo->m_last_wait_duration_ns = 0;
		tainfo->m_last_wait_end_time_ns = 0;
	}
}

//
// Analyzer event processing entry point
//
void sinsp_analyzer::process_event(sinsp_evt* evt, libsinsp::event_return rc)
{
	uint64_t ts;
	uint64_t delta;
	sinsp_evt::category cat;
	uint16_t etype;
	thread_analyzer_info* tainfo;

	analyzer_emitter::flush_flags flushflags = analyzer_emitter::DF_NONE;

	switch (rc)
	{
	case libsinsp::EVENT_RETURN_TIMEOUT:
		flushflags = analyzer_emitter::DF_TIMEOUT;
		break;
	case libsinsp::EVENT_RETURN_EOF:
		flushflags = analyzer_emitter::DF_EOF;
		break;
	case libsinsp::EVENT_RETURN_NONE:
#ifndef _DEBUG
	default:
#endif
		flushflags = analyzer_emitter::DF_NONE;
	}
	//
	// If there is no event, assume that this is an EOF and use the
	// next sample event as target time
	//
	if (evt != NULL)
	{
		ts = evt->get_ts();
		etype = evt->get_type();
		m_host_metrics.m_syscall_count.add(etype);

		if (m_parser->process_event(evt) == false)
		{
			return;
		}

		//
		// If there are chisels to run, run them now, before going into the analyzer logic
		//
		if (m_run_chisels)
		{
			for (auto it = m_chisels.begin(); it != m_chisels.end(); ++it)
			{
				if ((*it)->run(evt) == false)
				{
					continue;
				}
			}
		}
	}
	else
	{
		if (m_acked_sampling_ratio != 1)
		{
			return;
		}

		if (flushflags == analyzer_emitter::DF_EOF)
		{
			ts = m_next_flush_time_ns;
			flush(evt, ts, true, flushflags);

			if (m_run_chisels)
			{
				chisels_on_capture_end();
			}

			return;
		}

		if (flushflags != analyzer_emitter::DF_TIMEOUT)
		{
			ASSERT(false);
			return;
		}

		if (!m_inspector->is_live() || m_inspector->m_lastevent_ts == 0)
		{
			return;
		}

		// the only way we get here, and thus DON'T return on a null event is
		// 1) sampling ratio == 1
		// 2) flushflags == DF_TIMEOUT
		// 3) inspector is live and lastevent TS != 0
		ts = sinsp_utils::get_current_time_ns() - 500000000;
		etype = 0;  // this avoids a compiler warning
	}

	// When we are sampling, we expect to get a "drop mode" switch event twice per
	// flush interval...once to start sampling, and once to stop it. As a heuristic,
	// if we got 1.5x of a sampling interval without getting a drop event, we're going
	// to assume something was missed and YOLO set it. It is unknown at this time
	// if this is expected behavior or not.
	if (m_acked_sampling_ratio != 1 &&
	    ts - m_last_dropmode_switch_time > c_flush_interval->get_value() * 3 / 2)
	{
		g_logger.log("Did not receive drop event to confirm sampling_ratio " +
		                 to_string(m_acked_sampling_ratio) + ", forcing update",
		             sinsp_logger::SEV_WARNING);
		ack_sampling_ratio(m_acked_sampling_ratio);
		m_last_dropmode_switch_time = ts;
	}

	//
	// Check if it's time to flush
	//
	// It's not clear, but it seems the belief is that when sampling ratio != 1,
	// then flush is triggered by the EOF flag, but when not sampling, we don't get
	// the EOF event.
	//
	if (ts >= m_next_flush_time_ns && m_acked_sampling_ratio == 1)
	{
		flush(evt, ts, false /*not eof*/, flushflags);
	}

	//
	// This happens if the flush was generated by a timeout
	//
	if (evt == NULL)
	{
		return;
	}

	m_falco_baseliner->process_event(evt);

#ifndef CYGWING_AGENT
	if (m_infrastructure_state &&
	    (security_config::is_enabled() || m_infrastructure_state->subscribed()))
	{
		//
		// Refresh the infrastructure state with pending orchestrators or hosts events
		//
		m_infrastructure_state->refresh(ts);
	}
#endif

	//
	// This is where normal event parsing starts.
	// The following code is executed for every event
	//
	if (evt->m_tinfo == NULL || etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
	{
		//
		// No thread associated to this event, nothing to do
		//
		return;
	}

	tainfo = GET_AGENT_THREAD(evt->m_tinfo);

	if (tainfo == NULL)
	{
		//
		// No analyzer state associated to this thread.
		// This should never happen. if it does, skip the event.
		//
		ASSERT(false);
		return;
	}

	//
	// Get the event category and type
	//
	evt->get_category(&cat);

	//
	// for our purposes, accept() is wait, not networking
	//
	if (etype == PPME_SOCKET_ACCEPT_E || etype == PPME_SOCKET_ACCEPT_X ||
	    etype == PPME_SOCKET_ACCEPT_5_E || etype == PPME_SOCKET_ACCEPT_5_X)
	{
		cat.m_category = EC_WAIT;
	}

	//
	// Check if this is an event that goes across sample boundaries
	//
	if ((tainfo->m_th_analysis_flags & thread_analyzer_info::AF_PARTIAL_METRIC) != 0)
	{
		//
		// Part of this event has already been attributed to the previous sample,
		// we just include the remaining part
		//
		tainfo->m_th_analysis_flags &= ~(thread_analyzer_info::AF_PARTIAL_METRIC);

		delta = ts - m_prev_flush_time_ns;
	}
	else
	{
		//
		// Normal event that falls completely inside this sample
		//
		delta = ts - evt->m_tinfo->m_lastevent_ts;
	}

	//
	// Add this event time to the right category in the metrics array
	//
	if (PPME_IS_ENTER(etype))
	{
		//
		// remember the category in the thread info. We'll use
		// it if we need to flush the sample.
		//
		evt->m_tinfo->m_lastevent_category = cat;

		//
		// Switch the category to processing
		//
		cat.m_category = EC_PROCESSING;
	}
	else
	{
		if (!evt->m_tinfo->is_lastevent_data_valid())
		{
			//
			// There was some kind of drop and the enter event is not matching
			//
			cat.m_category = EC_UNKNOWN;
		}

		//
		// if a sample flush happens after this event, the time will have to
		// be attributed to processing.
		//
		evt->m_tinfo->m_lastevent_category.m_category = EC_PROCESSING;

		//
		// if this is an fd-based syscall that comes after a wait, update the wait time
		//
		ppm_event_flags eflags = evt->get_info_flags();
		if (eflags & EF_USES_FD)
		{
			add_wait_time(evt, &cat);
		}
	}

	//
	// Increase the counter
	//
	bool do_inc_counter = (cat.m_category != EC_PROCESSING);

	add_syscall_time(&tainfo->m_metrics, &cat, delta, evt->get_iosize(), do_inc_counter);

	//
	// If this is an error syscall, add the error to the host, process, and
	// container (if applicable).
	//
	if (evt->is_syscall_error())
	{
		// If m_fdinfo is nullptr, then there is no connection object
		// on which to increment network error counters.
		if (evt->m_fdinfo && evt->is_network_error())
		{
			sinsp_connection* const conn =
			    get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());

			if (conn != nullptr)
			{
				conn->m_metrics.increment_error_count();
			}
		}

		m_host_metrics.m_syscall_errors.add(evt);

		ASSERT(GET_AGENT_THREAD(evt->m_tinfo));

		GET_AGENT_THREAD(evt->m_tinfo)->m_syscall_errors.add(evt);

		if (!evt->m_tinfo->m_container_id.empty())
		{
			m_containers[evt->m_tinfo->m_container_id].m_metrics.m_syscall_errors.add(evt);
		}
	}
}

void sinsp_analyzer::add_syscall_time(sinsp_counters* metrics,
                                      sinsp_evt::category* cat,
                                      uint64_t delta,
                                      uint32_t bytes,
                                      bool inc_count)
{
	uint32_t cnt_delta = (inc_count) ? 1 : 0;

	switch (cat->m_category)
	{
	case EC_UNKNOWN:
		metrics->m_unknown.add(cnt_delta, delta);
		break;
	case EC_OTHER:
		metrics->m_other.add(cnt_delta, delta);
		break;
	case EC_FILE:
		metrics->m_file.add(cnt_delta, delta);
		break;
	case EC_NET:
		metrics->m_net.add(cnt_delta, delta);
		break;
	case EC_IPC:
		metrics->m_ipc.add(cnt_delta, delta);
		break;
	case EC_MEMORY:
		metrics->m_memory.add(cnt_delta, delta);
		break;
	case EC_PROCESS:
		metrics->m_process.add(cnt_delta, delta);
		break;
	case EC_SLEEP:
		metrics->m_sleep.add(cnt_delta, delta);
		break;
	case EC_SYSTEM:
		metrics->m_system.add(cnt_delta, delta);
		break;
	case EC_SIGNAL:
		metrics->m_signal.add(cnt_delta, delta);
		break;
	case EC_USER:
		metrics->m_user.add(cnt_delta, delta);
		break;
	case EC_TIME:
		metrics->m_time.add(cnt_delta, delta);
		break;
	case EC_PROCESSING:
		metrics->m_processing.add(cnt_delta, delta);
		break;
	case EC_IO_READ:
	{
		switch (cat->m_subcategory)
		{
		case sinsp_evt::SC_FILE:
			metrics->m_io_file.add_in(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NET:
			metrics->m_io_net.add_in(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_IPC:
			metrics->m_ipc.add(cnt_delta, delta);
			break;
		case sinsp_evt::SC_UNKNOWN:
		case sinsp_evt::SC_OTHER:
			metrics->m_io_other.add_in(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NONE:
			metrics->m_io_other.add_in(cnt_delta, delta, bytes);
			break;
		default:
			ASSERT(false);
			metrics->m_io_other.add_in(cnt_delta, delta, bytes);
			break;
		}
	}
	break;
	case EC_IO_WRITE:
	{
		switch (cat->m_subcategory)
		{
		case sinsp_evt::SC_FILE:
			metrics->m_io_file.add_out(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NET:
			metrics->m_io_net.add_out(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_IPC:
			metrics->m_ipc.add(cnt_delta, delta);
			break;
		case sinsp_evt::SC_UNKNOWN:
		case sinsp_evt::SC_OTHER:
			metrics->m_io_other.add_out(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NONE:
			metrics->m_io_other.add_out(cnt_delta, delta, bytes);
			break;
		default:
			ASSERT(false);
			metrics->m_io_other.add_out(cnt_delta, delta, bytes);
			break;
		}
	}
	break;
	case EC_IO_OTHER:
	{
		switch (cat->m_subcategory)
		{
		case sinsp_evt::SC_FILE:
			metrics->m_io_file.add_other(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NET:
			metrics->m_io_net.add_other(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_IPC:
			metrics->m_ipc.add(cnt_delta, delta);
			break;
		case sinsp_evt::SC_UNKNOWN:
		case sinsp_evt::SC_OTHER:
			metrics->m_io_other.add_other(cnt_delta, delta, bytes);
			break;
		case sinsp_evt::SC_NONE:
			metrics->m_io_other.add_other(cnt_delta, delta, bytes);
			break;
		default:
			ASSERT(false);
			metrics->m_io_other.add_other(cnt_delta, delta, bytes);
			break;
		}
	}
	break;
	case EC_WAIT:
		metrics->m_wait_other.add(cnt_delta, delta);
		break;
	case EC_SCHEDULER:
	case EC_INTERNAL:
		break;
	default:
		ASSERT(false);
	}
}

#ifndef CYGWING_AGENT
void sinsp_analyzer::get_k8s_data()
{
	if (m_k8s)
	{
		m_k8s->watch();
		if (m_metrics && !m_use_new_k8s)
		{
			k8s_proto(*m_metrics).get_proto(m_k8s->get_state());
			if (g_logger.get_severity() >= sinsp_logger::SEV_TRACE && m_metrics->has_kubernetes())
			{
				g_logger.log("K8s proto data:", sinsp_logger::SEV_TRACE);
				g_logger.log(m_metrics->kubernetes().DebugString(), sinsp_logger::SEV_TRACE);
			}
		}
		else if (!m_metrics)
		{
			g_logger.log("Proto metrics are NULL.", sinsp_logger::SEV_ERROR);
		}
	}
}

void sinsp_analyzer::reset_k8s(time_t& last_attempt, const std::string& err)
{
	log_timed_error(last_attempt, err);
	m_k8s_api_detected = false;
	m_k8s_ext_detect_done = false;
	m_k8s_delegator.reset();
	m_k8s_collector.reset();
	m_k8s_api_handler.reset();
	m_k8s_ext_handler.reset();
	m_ext_list_ptr.reset();
	m_k8s.reset();
}

void sinsp_analyzer::collect_k8s(const std::string& k8s_api)
{
	if (!k8s_api.empty())
	{
		uri k8s_uri(k8s_api);
		try
		{
			std::ostringstream log;
			if (!m_k8s)
			{
				log << "Connecting to K8S API server at: [" << k8s_uri.to_string(false) << ']';
				m_k8s.reset(get_k8s(k8s_uri, log.str()));
			}

			if (m_k8s)
			{
				if (m_k8s->get_machine_id().empty() && !m_configuration->get_machine_id().empty())
				{
					m_k8s->set_machine_id(m_configuration->get_machine_id());
				}
				get_k8s_data();
			}
		}
		catch (std::exception& ex)
		{
			static time_t last_attempt;
			reset_k8s(last_attempt, std::string("Error collecting K8s data:").append(ex.what()));
		}
	}
}

void sinsp_analyzer::emit_k8s()
{
	std::string k8s_api = m_infrastructure_state->get_k8s_url();
	if (k8s_api.empty())
	{
		return;
	}

	// the connection to k8s api server is entirely managed
	// in this function - if it is dropped, the attempts to re-establish it will keep on going
	// forever, once per cycle, until either connection is re-established or agent shut down

	try
	{
		if (!check_k8s_delegation())
		{
			return;
		}
		if (!k8s_api.empty())
		{
			if (!m_k8s_api_detected)
			{
				if (!m_k8s_api_handler)
				{
					if (!m_k8s_collector)
					{
						m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
					}
					if (uri(k8s_api).is_secure())
					{
						init_k8s_ssl(k8s_api);
					}
					m_k8s_api_handler.reset(new k8s_api_handler(m_k8s_collector,
					                                            k8s_api,
					                                            "/api",
					                                            ".versions",
					                                            "1.1",
					                                            m_k8s_ssl,
					                                            m_k8s_bt,
					                                            false));
				}
				else
				{
					m_k8s_api_handler->collect_data();
					if (m_k8s_api_handler->connection_error())
					{
						throw sinsp_exception("K8s API handler connection error.");
					}
					else if (m_k8s_api_handler->ready())
					{
						g_logger.log("K8s API handler data received.", sinsp_logger::SEV_TRACE);
						if (m_k8s_api_handler->error())
						{
							g_logger.log(
							    "K8s API handler data error occurred while detecting API versions.",
							    sinsp_logger::SEV_ERROR);
						}
						else
						{
							m_k8s_api_detected =
							    m_k8s_api_handler->has("v1");  // TODO: make version configurable
						}
						m_k8s_collector.reset();
						m_k8s_api_handler.reset();
					}
					else
					{
						g_logger.log("K8s API handler: not ready.", sinsp_logger::SEV_TRACE);
					}
				}
			}
			if (m_k8s_api_detected)
			{
				collect_k8s(k8s_api);
			}
		}
	}
	catch (std::exception& ex)
	{
		static time_t last_attempt;
		reset_k8s(last_attempt, std::string("Error emitting K8s data:").append(ex.what()));
	}
}

// Get the cluster name from infrastructure state
std::string sinsp_analyzer::get_k8s_cluster_name()
{
	return m_infrastructure_state->get_k8s_cluster_name();
}

// if user has not configured an agent "cluster:" tag,
// then append that tag here - by default, the value
// will be "default" unless:
// 1.) User specifies a k8s_cluster_name
// 2.) At some point in the future, we ping the GKE or
//     other kube cluster and ask forits name
std::string sinsp_analyzer::get_host_tags_with_cluster()
{
	std::string tags = m_configuration->get_host_tags();
	if (!(m_use_new_k8s && m_infrastructure_state->subscribed()))
	{
		return tags;
	}

	const string tag_str("cluster:");

	// No user-defined agent cluster tag so it's safe to append
	if (m_infrastructure_state->get_cluster_name_from_agent_tags().empty())
	{
		if (!tags.empty())
		{
			tags.append(1, ',');
		}
		tags.append(tag_str);
		tags.append(get_k8s_cluster_name());
	}

	return tags;
}

void sinsp_analyzer::get_mesos_data()
{
	ASSERT(m_mesos);
	ASSERT(m_mesos->is_alive());

	time_t now;
	time(&now);
	if (m_mesos && m_last_mesos_refresh)
	{
		m_mesos->collect_data();
	}

	// Possibly regenerate the auth token
	m_mesos->refresh_token();

	if (m_mesos && difftime(now, m_last_mesos_refresh) > MESOS_STATE_REFRESH_INTERVAL_S)
	{
		m_mesos->send_data_request();
		m_last_mesos_refresh = now;
	}
	if (m_mesos && m_mesos->get_state().has_data())
	{
		ASSERT(m_metrics);
		mesos_proto(*m_metrics, m_mesos->get_state(), m_configuration->get_marathon_skip_labels())
		    .get_proto();

		if (g_logger.get_severity() >= sinsp_logger::SEV_TRACE && m_metrics->has_mesos())
		{
			g_logger.log(m_metrics->mesos().DebugString(), sinsp_logger::SEV_TRACE);
		}
	}
	else
	{
		throw sinsp_exception("Mesos state empty (will retry later).");
	}
}

void sinsp_analyzer::reset_mesos(const std::string& errmsg)
{
	if (!errmsg.empty())
	{
		g_logger.log(errmsg, sinsp_logger::SEV_ERROR);
	}
	m_mesos_last_failure_ns = m_prev_flush_time_ns;
	m_mesos.reset();
	m_configuration->set_mesos_state_uri(m_configuration->get_mesos_state_original_uri());
	if (m_internal_metrics)
	{
		m_internal_metrics->set_mesos_detected(false);
	}
}

void sinsp_analyzer::emit_mesos()
{
	// mesos uri config settings can be set:
	//
	//    - explicitly in configuration file; when present, this setting has priority
	//      over anything else in regards to presence/location of the api server
	//
	//    - implicitly, by mesos autodetect flag (which defaults to true);
	//      when mesos_state_uri is empty, autodetect is true and api server is detected on the
	//      local machine, uris will be automatically set to:
	//
	//      mesos state:     "http://{IP_ADDR}:5050/state.json"
	//                       with {IP_ADDR} being interface where Mesos is found listening
	//      marathon groups: will be discovered automatically from mesos master state
	//                       (eg. "http://localhost:8080/v2/groups")
	//      marathon uri:    will be discovered automatically from mesos master state
	//                       (eg. "http://localhost:8080/v2/apps?embed=apps.tasks")
	//
	// so, at runtime, mesos_state_uri being empty or not determines whether mesos data
	// will be collected and emitted; the connection to mesos api server is entirely managed
	// in this function - if it is dropped, the attempts to re-establish it will keep on going
	// forever, once per cycle, until either connection is re-established or agent shut down

	string mesos_uri = m_configuration->get_mesos_state_uri();

	try
	{
		if (!mesos_uri.empty())
		{
			// Note that if the mesos uri is for a slave/agent, we don't do anything.
			uri m_uri(mesos_uri);

			if (m_uri.get_port() != 5050)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
				                "Mesos uri %s is for slave, not performing further queries",
				                mesos_uri.c_str());
				return;
			}

			g_logger.log("Emitting Mesos ...", sinsp_logger::SEV_DEBUG);
			if (!m_mesos)
			{
				g_logger.log(
				    "Connecting to Mesos API server at [" + m_uri.to_string(false) + "] ...",
				    sinsp_logger::SEV_INFO);
				get_mesos(mesos_uri);
			}
			else if (m_mesos && !m_mesos->is_alive())
			{
				g_logger.log(
				    "Existing Mesos connection error detected (not alive). Trying to reconnect ...",
				    sinsp_logger::SEV_ERROR);
				get_mesos(mesos_uri);
			}

			if (m_mesos)
			{
				if (m_mesos->is_alive())
				{
					get_mesos_data();
				}
				if (!m_mesos->is_alive())
				{
					g_logger.log(
					    "Existing Mesos connection error detected (not alive). Trying to reconnect "
					    "...",
					    sinsp_logger::SEV_ERROR);
					get_mesos(mesos_uri);
					if (m_mesos && m_mesos->is_alive())
					{
						g_logger.log("Mesos connection re-established.", sinsp_logger::SEV_INFO);
						get_mesos_data();
					}
					else
					{
						reset_mesos("Mesos connection attempt failed. Will retry in next cycle.");
					}
				}
			}
			else
			{
				reset_mesos("Mesos connection not established.");
			}
		}
		else if (m_configuration->get_mesos_autodetect_enabled() &&
		         (m_prev_flush_time_ns - m_mesos_last_failure_ns) >
		             MESOS_RETRY_ON_ERRORS_TIMEOUT_NS)
		{
			detect_mesos();
		}
		if (m_mesos && m_mesos->is_alive() && m_internal_metrics)
		{
			m_internal_metrics->set_mesos_detected(true);
		}
	}
	catch (std::exception& e)
	{
		reset_mesos(std::string("Error fetching Mesos state: ").append(e.what()));
	}
}

void sinsp_analyzer::log_timed_error(time_t& last_attempt, const std::string& err)
{
	time_t now;
	time(&now);
	if (difftime(now, last_attempt) > m_k8s_retry_seconds)
	{
		last_attempt = now;
		g_logger.log(err, sinsp_logger::SEV_ERROR);
	}
}

bool sinsp_analyzer::check_k8s_delegation()
{
	m_is_k8s_delegated = check_k8s_delegation_impl();
	return m_is_k8s_delegated;
}

bool sinsp_analyzer::check_k8s_delegation_impl()
{
	const std::string& k8s_uri = m_infrastructure_state->get_k8s_url();
	int delegated_nodes = m_configuration->get_k8s_delegated_nodes();

	if (m_use_new_k8s)
	{
		ASSERT(m_infrastructure_state);
		if (!m_infrastructure_state || !m_infrastructure_state->subscribed())
		{
			return false;
		}

		if (!m_new_k8s_delegator)
		{
			g_logger.log("Creating new K8s delegator object ...", sinsp_logger::SEV_INFO);
			m_new_k8s_delegator.reset(new new_k8s_delegator());
			if (!m_new_k8s_delegator)
			{
				g_logger.log("Can't create new K8s delegator object.", sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		return m_new_k8s_delegator->is_delegated(m_infrastructure_state,
		                                         delegated_nodes,
		                                         m_prev_flush_time_ns);
	}

	if (!k8s_uri.empty())
	{
		if (delegated_nodes > 0)
		{
			try
			{
				static time_t last_attempt;
				if (m_k8s_delegator)
				{
					m_k8s_delegator->collect_data();
					return m_k8s_delegator->is_delegated();
				}
				else
				{
					bool log = false;
					time_t now;
					time(&now);
					if (difftime(now, last_attempt) > m_k8s_retry_seconds)
					{
						log = true;
						last_attempt = now;
					}
					if (log)
					{
						g_logger.log("Creating K8s delegator object ...", sinsp_logger::SEV_INFO);
					}
					if (uri(k8s_uri).is_secure())
					{
						init_k8s_ssl(k8s_uri);
					}
					m_k8s_delegator.reset(new k8s_delegator(m_inspector,
					                                        k8s_uri,
					                                        delegated_nodes,
					                                        "1.1",  // http version
					                                        m_k8s_ssl,
					                                        m_k8s_bt));
					if (m_k8s_delegator)
					{
						if (m_k8s_delegator->connection_error())
						{
							throw sinsp_exception("K8s delegator connection error.");
						}
						if (log)
						{
							g_logger.log("Created K8s delegator object, collecting data...",
							             sinsp_logger::SEV_INFO);
						}
						m_k8s_delegator->collect_data();
						return m_k8s_delegator->is_delegated();
					}
					else
					{
						if (log)
						{
							g_logger.log("Can't create K8s delegator object.",
							             sinsp_logger::SEV_ERROR);
						}
						m_k8s_delegator.reset();
					}
				}
			}
			catch (std::exception& ex)
			{
				static time_t last_attempt;
				reset_k8s(last_attempt, std::string("K8s delegator error: ") + ex.what());
			}
		}
		else
		{
			// This check should be in k8s_delegator, but that
			// requires starting the delegator. This keeps the
			// legacy k8s behavior of not starting the delegator
			// to avoid any possible legacy k8s perf issues.
			static run_on_interval deleg_log(K8S_DELEGATION_INTERVAL);
			deleg_log.run(
			    [delegated_nodes]() {
				    bool enabled = (delegated_nodes < 0);
				    g_logger.log(std::string("K8s delegator: delegation ") +
				                     (enabled ? "forced" : "disabled") + " by config override",
				                 sinsp_logger::SEV_INFO);
				    return enabled;
			    },
			    sinsp_utils::get_current_time_ns());
		}
	}
	return false;
}

void sinsp_analyzer::emit_docker_events()
{
	try
	{
		if (m_docker)
		{
			m_docker->collect_data();
		}
		else
		{
			g_logger.log("Creating Docker object ...", sinsp_logger::SEV_INFO);
			m_docker.reset(
			    new docker(m_configuration->get_add_event_scopes() ? infra_state() : nullptr));
			if (m_docker)
			{
				m_docker->set_event_filter(m_configuration->get_docker_event_filter());
				m_docker->set_machine_id(m_configuration->get_machine_id());
				g_logger.log("Created Docker object, collecting data...", sinsp_logger::SEV_INFO);
				m_docker->collect_data();
				return;
			}
			else
			{
				g_logger.log("Can't create Docker events object.", sinsp_logger::SEV_ERROR);
				m_docker.reset();
			}
		}
	}
	catch (std::exception& ex)
	{
		if (docker::should_log_errors())
		{
			g_logger.log(std::string("Docker events error: ") + ex.what(), sinsp_logger::SEV_ERROR);
		}
		m_docker.reset();
	}
}

void sinsp_analyzer::emit_containerd_events()
{
	if (m_containerd_events == nullptr)
	{
		const auto& cri_socket = libsinsp::cri::s_cri_unix_socket_path;
		auto cri_runtime_type = libsinsp::cri::s_cri_runtime_type;

		if (cri_socket.empty())
		{
			return;
		}

		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "CRI socket: %s, runtime type: %d",
		                cri_socket.c_str(),
		                cri_runtime_type);

		if (cri_runtime_type != sinsp_container_type::CT_CONTAINERD)
		{
			return;
		}
		g_logger.format(sinsp_logger::SEV_INFO,
		                "Connecting to containerd socket at %s for events",
		                cri_socket.c_str());
		m_containerd_events = make_unique<containerd_events>(
		    std::string("unix://") + scap_get_host_root() + cri_socket,
		    m_configuration->get_machine_id(),
		    m_configuration->get_containerd_event_filter());
	}

	if (!m_containerd_events->is_open())
	{
		m_containerd_events->subscribe();
	}
	if (m_containerd_events)
	{
		m_containerd_events->tick();
	}
}
#endif  // CYGWING_AGENT

void sinsp_analyzer::send_containers_to_statsite_fowarder(
    sinsp_analyzer& analyzer,
    const std::vector<std::string>& containers,
    const analyzer_emitter::progtable_by_container_t& progtable_by_container)
{
	if (!analyzer.m_statsite_forwader_queue)
	{
		return;
	}

	const auto agent_container_id =
	    (analyzer.get_agent_thread() != nullptr) ? analyzer.get_agent_thread()->m_container_id : "";
	Json::Value root(Json::objectValue);

	root["containers"] = Json::arrayValue;

	for (const auto& id : containers)
	{
		if (id == agent_container_id)
		{
			continue;
		}

		const auto& container_processes = progtable_by_container.at(id);
		Json::Value c(Json::objectValue);

		// We need some representativate process from the network
		// namespace of the target container.  Here, we pick the
		// first process; there's nothing particularly special about
		// that process.
		c["id"] = id;
		c["pid"] = static_cast<Json::Int64>(container_processes[0]->m_pid);

		root["containers"].append(c);
	}

	Json::FastWriter json_writer;
	analyzer.m_statsite_forwader_queue->send(json_writer.write(root));
}

// deprecated because smart container filtering has it's own comparator
template<typename Extractor>
class containers_cmp_deprecated
{
public:
	containers_cmp_deprecated(const unordered_map<string, analyzer_container_state>* containers,
	                          Extractor&& extractor)
	    : m_containers(containers),
	      m_extractor(extractor)
	{
	}

	bool operator()(const string& lhs, const string& rhs)
	{
		const auto it_analyzer_lhs = m_containers->find(lhs);
		const auto it_analyzer_rhs = m_containers->find(rhs);
		decltype(m_extractor(it_analyzer_lhs->second)) cmp_lhs = 0;
		if (it_analyzer_lhs != m_containers->end())
		{
			cmp_lhs = m_extractor(it_analyzer_lhs->second);
		}
		decltype(m_extractor(it_analyzer_rhs->second)) cmp_rhs = 0;
		if (it_analyzer_rhs != m_containers->end())
		{
			cmp_rhs = m_extractor(it_analyzer_rhs->second);
		}
		return cmp_lhs > cmp_rhs;
	}

private:
	const unordered_map<string, analyzer_container_state>* m_containers;
	Extractor m_extractor;
};

template<class S>
void sinsp_analyzer::check_dump_infrastructure_state(const S& state,
                                                     const std::string& descriptor,
                                                     bool& should_dump)
{
	if (!should_dump)
	{
		return;
	}

	should_dump = false;

	g_logger.format(sinsp_logger::SEV_INFO,
	                "Dumping %s infrastructure state... STARTED",
	                descriptor.c_str());

	time_t rawtime;
	struct tm* timeinfo;
	char time_buffer[80];

	// Build the file name
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(time_buffer, sizeof(time_buffer), "%Y-%d-%m_%H-%M-%S", timeinfo);

	std::ostringstream oss;
	oss << m_configuration->get_log_dir() + "/";
	oss << time_buffer;
	oss << "_";
	oss << descriptor;
	oss << "_orchestrator_state_t.json";
	const std::string fileName = oss.str();

	// Dump the file
	std::ofstream out(fileName);

	std::string jsonString;
	google::protobuf::util::MessageToJsonString(state, &jsonString);
	out << jsonString;

	out.close();

	g_logger.format(sinsp_logger::SEV_INFO,
	                "Dumping %s infrastructure state... COMPLETE",
	                descriptor.c_str());
}

vector<string> sinsp_analyzer::emit_containers_deprecated(
    const analyzer_emitter::progtable_by_container_t& progtable_by_container,
    analyzer_emitter::flush_flags flushflags)
{
	// Containers are ordered by cpu, mem, file_io and net_io, these lambda extract
	// that value from analyzer_container_state
	auto cpu_extractor = [](const analyzer_container_state& analyzer_state) {
		return analyzer_state.m_metrics.m_cpuload;
	};

	auto mem_extractor = [](const analyzer_container_state& analyzer_state) {
		return analyzer_state.m_metrics.m_res_memory_used_kb;
	};

	auto file_io_extractor = [](const analyzer_container_state& analyzer_state) {
		return analyzer_state.m_req_metrics.m_io_file.get_tot_bytes();
	};

	auto net_io_extractor = [](const analyzer_container_state& analyzer_state) {
		return analyzer_state.m_req_metrics.m_io_net.get_tot_bytes();
	};

	update_percentile_data_serialization(progtable_by_container);

	vector<string> emitted_containers;
	vector<string> containers_ids;
	containers_ids.reserve(m_containers.size());
	sinsp_protostate_marker containers_protostate_marker;

	uint64_t total_cpu_shares = 0;
	for (const auto& item : progtable_by_container)
	{
		const auto& container_id = item.first;
		const auto container_info = m_inspector->m_container_manager.get_container(container_id);
		if (container_info)
		{
			if (!container_info->is_pod_sandbox())
			{
				if ((m_container_patterns.empty() ||
				     std::find_if(m_container_patterns.begin(),
				                  m_container_patterns.end(),
				                  [&container_info](const string& pattern) {
					                  return container_info->m_name.find(pattern) != string::npos ||
					                         container_info->m_image.find(pattern) != string::npos;
				                  }) != m_container_patterns.end()))
				{
					auto analyzer_it = m_containers.find(container_id);
#ifndef CYGWING_AGENT
					bool optional;
					if (analyzer_it != m_containers.end() &&
					    analyzer_it->second.should_report_container(m_configuration,
					                                                *container_info,
					                                                infra_state(),
					                                                m_prev_flush_time_ns,
					                                                optional))
#else
					if (analyzer_it != m_containers.end())
#endif
					{
						containers_ids.push_back(container_id);
						containers_protostate_marker.add(
						    analyzer_it->second.m_metrics.m_protostate);
					}
				}

				// This count it's easy to be affected by a lot of noise, for example:
				// 1. k8s_POD pods
				// 2. custom containers run from cmdline with no --cpu-shares flag,
				//    in this case the kernel defaults to 1024
				// 3. system containers like kubernetes proxy
				//
				// we decided to skip 1. to avoid noise (they have usually shares=2,
				// does not affect so much the calc but they may be a lot)
				// Right now we decided to keep 2. But may be changed in the future
				// because usually if--cpu-shares flag is not set, it is meant for troubleshooting
				// containers with few cpu usage or system containers
				// with a default of 1024 given by the kernel, they pollute a lot the calculation
				total_cpu_shares += container_info->m_cpu_shares;
			}
		}
	}

	send_containers_to_statsite_fowarder(*this, containers_ids, progtable_by_container);

	g_logger.format(sinsp_logger::SEV_DEBUG, "total_cpu_shares=%lu", total_cpu_shares);
	containers_protostate_marker.mark_top(CONTAINERS_PROTOS_TOP_LIMIT);
	// Emit containers on protobuf, our logic is:
	// Pick top N from top_by_cpu
	// Pick top N from top_by_mem which are not already taken by top_cpu
	// Pick top N from top_by_file_io which are not already taken by top_cpu and top_mem
	// Etc ...

	const auto containers_limit_by_type = m_containers_limit / 4;
	const auto containers_limit_by_type_remainder = m_containers_limit % 4;
	unsigned statsd_limit = statsd_emitter::get_limit();
	auto check_and_emit_containers = [&containers_ids,
	                                  this,
	                                  &statsd_limit,
	                                  &emitted_containers,
	                                  &total_cpu_shares,
	                                  &progtable_by_container,
	                                  flushflags](const uint32_t containers_limit) {
		for (uint32_t j = 0; j < containers_limit && !containers_ids.empty(); ++j)
		{
			const auto& containerid = containers_ids.front();
			// We need any pid of a process running within this container
			// to get net stats via /proc
			// Since we're using it also to read cgroups, try to pick vpid=1
			// first.
			const auto& container_progs = progtable_by_container.at(containerid);
			auto container_init = find_if(container_progs.begin(),
			                              container_progs.end(),
			                              [](THREAD_TYPE* tinfo) { return tinfo->m_vtid == 1; });

			THREAD_TYPE* tinfo;
			if (container_init != container_progs.end())
			{
				tinfo = *container_init;
			}
			else
			{
				tinfo = progtable_by_container.at(containerid).front();
				g_logger.format(sinsp_logger::SEV_DEBUG,
				                "Failed to find container init for %s, "
				                "using process %s (vtid=%ld)",
				                containerid.c_str(),
				                tinfo->m_comm.c_str(),
				                tinfo->m_vtid);
			}
			std::list<uint32_t> groups;
			this->emit_container(containerid,
			                     &statsd_limit,
			                     total_cpu_shares,
			                     tinfo,
			                     flushflags,
			                     groups);
			emitted_containers.emplace_back(containerid);
			containers_ids.erase(containers_ids.begin());
		}
	};

	if (containers_ids.size() > containers_limit_by_type + containers_limit_by_type_remainder)
	{
		partial_sort(
		    containers_ids.begin(),
		    containers_ids.begin() + containers_limit_by_type + containers_limit_by_type_remainder,
		    containers_ids.end(),
		    containers_cmp_deprecated<decltype(mem_extractor)>(&m_containers, move(mem_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type + containers_limit_by_type_remainder);

	if (containers_ids.size() > containers_limit_by_type)
	{
		partial_sort(
		    containers_ids.begin(),
		    containers_ids.begin() + containers_limit_by_type,
		    containers_ids.end(),
		    containers_cmp_deprecated<decltype(file_io_extractor)>(&m_containers,
		                                                           move(file_io_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type);

	// This will not work on nodriver, net stats are read just before emitting.
	// We could read them earlier but containers using `--net host` will
	// have net_stats==host_stats, which falses the algorithm
	// so ignore it for now.
	auto top_cpu_containers = containers_limit_by_type;
	if (!m_inspector->is_nodriver())
	{
		if (containers_ids.size() > containers_limit_by_type)
		{
			partial_sort(
			    containers_ids.begin(),
			    containers_ids.begin() + containers_limit_by_type,
			    containers_ids.end(),
			    containers_cmp_deprecated<decltype(net_io_extractor)>(&m_containers,
			                                                          move(net_io_extractor)));
		}
		check_and_emit_containers(containers_limit_by_type);
	}
	else
	{
		// assign top net slots to top cpu
		top_cpu_containers += containers_limit_by_type;
	}

	if (containers_ids.size() > top_cpu_containers)
	{
		partial_sort(
		    containers_ids.begin(),
		    containers_ids.begin() + top_cpu_containers,
		    containers_ids.end(),
		    containers_cmp_deprecated<decltype(cpu_extractor)>(&m_containers, move(cpu_extractor)));
	}
	check_and_emit_containers(top_cpu_containers);

	/*
	 * Required for fake k8s API server, so that we report the fake containers
	 * in local orchestrator state and they're visible in the UI
	 *
	 * Has absolutely no use in real world setups
	 */
	if (c_test_only_send_infra_state_containers->get_value())
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Sending infra_state containers");
		for (const auto& id : m_infrastructure_state->test_only_get_container_ids())
		{
			draiosproto::container* container = m_metrics->add_containers();
			g_logger.format(sinsp_logger::SEV_DEBUG,
			                "Sending infra_state container %s",
			                id.c_str());
			container->set_id(id);
			container->set_type(draiosproto::CUSTOM);
			emitted_containers.emplace_back(id);
		}
	}

	gather_k8s_infrastructure_state(flushflags, emitted_containers);

	/*
	    g_logger.log("Found " + std::to_string(m_metrics->containers().size()) + " containers.",
	   sinsp_logger::SEV_DEBUG); for(const auto& c : m_metrics->containers())
	    {
	        g_logger.log(c.DebugString(), sinsp_logger::SEV_TRACE);
	    }
	*/
	clean_containers(progtable_by_container);

	return emitted_containers;
}

void sinsp_analyzer::emit_container(const string& container_id,
                                    unsigned* statsd_limit,
                                    uint64_t total_cpu_shares,
                                    THREAD_TYPE* tinfo,
                                    analyzer_emitter::flush_flags flushflags,
                                    const std::list<uint32_t>& groups)
{
	const auto container_info = m_inspector->m_container_manager.get_container(container_id);
	if (!container_info)
	{
		return;
	}
	unordered_map<string, analyzer_container_state>::iterator it_analyzer =
	    m_containers.find(container_info->m_id);
	if (it_analyzer == m_containers.end())
	{
		return;
	}

	draiosproto::container* container = m_metrics->add_containers();

	container->set_id(container_info->m_id);

	for (auto& i : groups)
	{
		container->add_container_reporting_group_id(i);
	}

	switch (container_info->m_type)
	{
	case CT_DOCKER:
		container->set_type(draiosproto::DOCKER);
		break;
	case CT_LXC:
		container->set_type(draiosproto::LXC);
		break;
	case CT_LIBVIRT_LXC:
		container->set_type(draiosproto::LIBVIRT_LXC);
		break;
	case CT_MESOS:
		container->set_type(draiosproto::MESOS);
		// Sanity check the mesos task id. if it's trivially small, log a warning.
		if (container_info->m_mesos_task_id.length() < 3)
		{
			g_logger.format(sinsp_logger::SEV_WARNING,
			                "Suspicious mesos task id for container id '%s': '%s'",
			                container_id.c_str(),
			                container_info->m_mesos_task_id.c_str());
		}
		break;
	case CT_RKT:
		container->set_type(draiosproto::RKT);
		break;
	case CT_CUSTOM:
		container->set_type(draiosproto::CUSTOM);
		break;
	case CT_CRI:
		container->set_type(draiosproto::CRI);
		break;
	case CT_CONTAINERD:
		container->set_type(draiosproto::CONTAINERD);
		break;
	case CT_CRIO:
		container->set_type(draiosproto::CRIO);
		break;
	case CT_BPM:
		container->set_type(draiosproto::CUSTOM);
		break;
	default:
		ASSERT(false);
	}

	if (container_info->is_successful())
	{
		if (!container_info->m_name.empty())
		{
			container->set_name(container_info->m_name);
		}

		if (!container_info->m_image.empty())
		{
			container->set_image(container_info->m_image);
		}

		if (!container_info->m_imageid.empty())
		{
			container->set_image_id(container_info->m_imageid.substr(0, 12));
		}

		if (!container_info->m_imagerepo.empty())
		{
			container->set_image_repo(container_info->m_imagerepo);
		}

		if (!container_info->m_imagetag.empty())
		{
			container->set_image_tag(container_info->m_imagetag);
		}

		if (!container_info->m_imagedigest.empty())
		{
			container->set_image_digest(container_info->m_imagedigest);
		}
	}

#ifndef CYGWING_AGENT
	if (!container_info->m_mesos_task_id.empty())
	{
		container->set_mesos_task_id(container_info->m_mesos_task_id);
	}
#endif

	auto uid = make_pair((string) "container", container_id);
#ifndef CYGWING_AGENT
	m_infrastructure_state->get_orch_labels(uid,
	                                        container->mutable_orchestrators_fallback_labels());
#endif

	for (vector<sinsp_container_info::container_port_mapping>::const_iterator it_ports =
	         container_info->m_port_mappings.begin();
	     it_ports != container_info->m_port_mappings.end();
	     ++it_ports)
	{
		draiosproto::container_port_mapping* mapping = container->add_port_mappings();

		mapping->set_host_ip(it_ports->m_host_ip);
		mapping->set_host_port(it_ports->m_host_port);
		mapping->set_container_ip(container_info->m_container_ip);
		mapping->set_container_port(it_ports->m_container_port);
	}

	for (map<string, string>::const_iterator it_labels = container_info->m_labels.begin();
	     it_labels != container_info->m_labels.end();
	     ++it_labels)
	{
		std::string filter;
		const string& label_key = it_labels->first;
		const string& label_val = it_labels->second;

		// Filter labels forbidden by config file
		if (m_label_limits && !m_label_limits->allow(label_key, filter))
		{
			continue;
		}

		// Limit length of label values based on config. Long labels are skipped
		// instead of truncating to avoid producing overlapping labels.
		if (label_val.length() > m_containers_labels_max_len)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
			                "%s: Skipped label '%s' of "
			                "container %s[%s]: longer than max configured, %u > %u",
			                __func__,
			                label_key.c_str(),
			                container_info->m_name.c_str(),
			                container_id.c_str(),
			                label_val.length(),
			                m_containers_labels_max_len);
			continue;
		}

		draiosproto::container_label* label = container->add_labels();
		label->set_key(label_key);
		label->set_value(label_val);
	}

#ifndef CYGWING_AGENT
	container->mutable_resource_counters()->set_capacity_score(
	    it_analyzer->second.m_metrics.get_capacity_score() * 100);
	container->mutable_resource_counters()->set_stolen_capacity_score(
	    it_analyzer->second.m_metrics.get_stolen_score() * 100);
	container->mutable_resource_counters()->set_connection_queue_usage_pct(
	    it_analyzer->second.m_metrics.m_connection_queue_usage_pct);
#endif
	uint32_t res_memory_kb = it_analyzer->second.m_metrics.m_res_memory_used_kb;

#ifndef CYGWING_AGENT
	auto memory_cgroup_it =
	    find_if(tinfo->m_cgroups.cbegin(),
	            tinfo->m_cgroups.cend(),
	            [](const pair<string, string>& cgroup) { return cgroup.first == "memory"; });
	// Exclude memory_cgroup=/, it's very unlikely for containers and will lead
	// to wrong metrics reported, rely on our processes memory sum in that case
	// it happens when there are race conditions during the creating phase of a container
	// and lasts very little
	if (memory_cgroup_it != tinfo->m_cgroups.cend() && memory_cgroup_it->second != "/")
	{
		const auto cgroup_memory =
		    m_procfs_parser->read_cgroup_used_memory(memory_cgroup_it->second);
		if (cgroup_memory > 0)
		{
			res_memory_kb = cgroup_memory / 1024;
		}
	}
#endif
	container->mutable_resource_counters()->set_resident_memory_usage_kb(res_memory_kb);
	container->mutable_resource_counters()->set_swap_memory_usage_kb(
	    it_analyzer->second.m_metrics.m_swap_memory_used_kb);
	container->mutable_resource_counters()->set_minor_pagefaults(
	    it_analyzer->second.m_metrics.m_pfminor);
#ifndef CYGWING_AGENT
	container->mutable_resource_counters()->set_major_pagefaults(
	    it_analyzer->second.m_metrics.m_pfmajor);
	it_analyzer->second.m_metrics.m_syscall_errors.to_protobuf(container->mutable_syscall_errors(),
	                                                           m_acked_sampling_ratio);
	if (!m_inspector->is_nodriver())
	{
		// These metrics are not correct in nodriver mode
		container->mutable_resource_counters()->set_fd_count(
		    it_analyzer->second.m_metrics.m_fd_count);
		container->mutable_resource_counters()->set_fd_usage_pct(
		    it_analyzer->second.m_metrics.m_fd_usage_pct);
	}
#endif

	double container_cpu_pct = it_analyzer->second.m_metrics.m_cpuload;
#ifndef CYGWING_AGENT
	auto cpuacct_cgroup_it =
	    find_if(tinfo->m_cgroups.cbegin(),
	            tinfo->m_cgroups.cend(),
	            [](const pair<string, string>& cgroup) { return cgroup.first == "cpuacct"; });
	if (cpuacct_cgroup_it != tinfo->m_cgroups.cend() && cpuacct_cgroup_it->second != "/")
	{
		/*
		 * Only read cpuacct cgroup values when we really are going to emit them,
		 * otherwise the read value gets lost and we underreport the CPU usage
		 */
		if (flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			const auto cgroup_cpuacct =
			    m_procfs_parser->read_cgroup_used_cpu(cpuacct_cgroup_it->second,
			                                          it_analyzer->second.m_last_cpuacct_cgroup,
			                                          &it_analyzer->second.m_last_cpu_time);
			if (cgroup_cpuacct > 0)
			{
				// g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s cpuacct_pct=%.2f,
				// cpu_pct=%.2f", container_id.c_str(), cgroup_cpuacct * 100,
				// it_analyzer->second.m_metrics.m_cpuload * 100);
				container_cpu_pct = cgroup_cpuacct;
			}
		}
	}
#endif  // CYGWING_AGENT
	container->mutable_resource_counters()->set_cpu_pct(container_cpu_pct * 100);

	container->mutable_resource_counters()->set_count_processes(
	    it_analyzer->second.m_metrics.get_process_count());
#ifndef CYGWING_AGENT
	container->mutable_resource_counters()->set_proc_start_count(
	    it_analyzer->second.m_metrics.get_process_start_count());
#endif

	if (container_info->m_cpu_shares > 0)
	{
		container->mutable_resource_counters()->set_cpu_shares(container_info->m_cpu_shares);

		const double share_ratio = static_cast<double>(container_info->m_cpu_shares) /
		                           static_cast<double>(total_cpu_shares);
		const double cpu_pct_host = container_cpu_pct / m_inspector->m_num_cpus;

		// Say we are using 20% of the host and the cpu_shares allow
		// us up to 50% of the host. Then our usage is .2/.5 = .4
		const double cpu_shares_usage_pct = cpu_pct_host / share_ratio;

		// g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s cpu_shares=%u used_pct=%.2f",
		// container_id.c_str(), container_info->m_cpu_shares, cpu_shares_usage_pct);
		container->mutable_resource_counters()->set_cpu_shares_usage_pct(
		    cpu_shares_usage_pct * 100);  // * 100 because we convert double to .2 fixed decimal
	}

	if (container_info->m_cpu_quota > 0 && container_info->m_cpu_period > 0)
	{
		// These two numbers directly determine how many cores can be used.
		// X/X would be one core; 3X/X would be 3 cores, X/2X would be
		// half a core.
		const double quota_cores = static_cast<double>(container_info->m_cpu_quota) /
		                           static_cast<double>(container_info->m_cpu_period);

		// Quota limit is returned in hundredths of a percent. This is so
		// that the value returned is consistent with cpu_pct.
		const int quota_limit_multiplier = 100 * 100;
		container->mutable_resource_counters()->set_cpu_cores_quota_limit(quota_cores *
		                                                                  quota_limit_multiplier);

		const double cpu_quota_used_pct = container_cpu_pct / quota_cores;
		// g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s cpu_quota=%ld cpu_period=%ld
		// used_pct=%.2f", container_id.c_str(), container_info->m_cpu_quota,
		// container_info->m_cpu_period, cpu_quota_used_pct);
		container->mutable_resource_counters()->set_cpu_quota_used_pct(cpu_quota_used_pct * 100);
	}

	if (container_info->m_cpuset_cpu_count > 0)
	{
		// Cpuset limit is returned in hundreths of a percent. This is
		// so that the value returned is consistent with cpu_pct.
		const int cpuset_limit_multiplier = 100 * 100;
		container->mutable_resource_counters()->set_cpu_cores_cpuset_limit(
		    container_info->m_cpuset_cpu_count * cpuset_limit_multiplier);
		// container_cpu_pct is already pct * num_cpus, so just divide by
		// cpuset cpus to get the value that we want between 1 and 100
		const double cpuset_used_pct =
		    container_cpu_pct / static_cast<double>(container_info->m_cpuset_cpu_count);
		container->mutable_resource_counters()->set_cpu_cpuset_usage_pct(cpuset_used_pct * 100);
	}

	if (container_info->m_size_rw_bytes != -1)
	{
		container->mutable_resource_counters()->set_rw_bytes(container_info->m_size_rw_bytes);
	}

	if (container_info->m_memory_limit > 0)
	{
		container->mutable_resource_counters()->set_memory_limit_kb(container_info->m_memory_limit /
		                                                            1024);
		// g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s memory=%u/%u",
		// container_id.c_str(), res_memory_kb, container_info->m_memory_limit/1024);
	}

	if (container_info->m_swap_limit > 0)
	{
		container->mutable_resource_counters()->set_swap_limit_kb(container_info->m_swap_limit /
		                                                          1024);
	}

	auto tcounters = container->mutable_tcounters();
	it_analyzer->second.m_metrics.m_metrics.to_protobuf(tcounters, m_acked_sampling_ratio);
	if (m_inspector->is_nodriver())
	{
#ifndef CYGWING_AGENT
		// We need to patch network metrics reading from /proc
		// since we don't have sysdig events in this case
		auto io_net = tcounters->mutable_io_net();
		auto net_bytes =
		    m_procfs_parser->read_proc_network_stats(tinfo->m_pid,
		                                             &it_analyzer->second.m_last_bytes_in,
		                                             &it_analyzer->second.m_last_bytes_out);
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "Patching container=%s pid=%ld networking from (%u, %u) to (%u, %u)",
		                container_id.c_str(),
		                tinfo->m_pid,
		                io_net->bytes_in(),
		                io_net->bytes_out(),
		                net_bytes.first,
		                net_bytes.second);
		io_net->set_bytes_in(net_bytes.first);
		io_net->set_bytes_out(net_bytes.second);

#else
		// In Windows we patch both network and file I/O
		// metrics.
		wh_docker_io_bytes dbytes =
		    wh_docker_get_io_bytes(m_inspector->get_wmi_handle(), container_id.c_str());
		if (dbytes.m_result != 0)
		{
			auto io_net = tcounters->mutable_io_net();
			io_net->set_bytes_in(dbytes.m_net_bytes_in);
			io_net->set_bytes_out(dbytes.m_net_bytes_out);

			auto io_file = tcounters->mutable_io_file();
			io_file->set_bytes_in(dbytes.m_file_bytes_in);
			io_file->set_bytes_out(dbytes.m_file_bytes_out);
		}
#endif
	}

#ifndef CYGWING_AGENT
	if (m_protocols_enabled)
	{
		it_analyzer->second.m_metrics.m_protostate->to_protobuf(container->mutable_protos(),
		                                                        m_acked_sampling_ratio,
		                                                        CONTAINERS_PROTOS_TOP_LIMIT);
	}

	it_analyzer->second.m_req_metrics.to_reqprotobuf(container->mutable_reqcounters(),
	                                                 m_acked_sampling_ratio);

	it_analyzer->second.m_transaction_counters.to_protobuf(
	    container->mutable_transaction_counters(),
	    container->mutable_max_transaction_counters(),
	    m_acked_sampling_ratio);

	m_delay_calculator->compute_host_container_delays(&it_analyzer->second.m_transaction_counters,
	                                                  &it_analyzer->second.m_client_transactions,
	                                                  &it_analyzer->second.m_server_transactions,
	                                                  &it_analyzer->second.m_transaction_delays);

	if (it_analyzer->second.m_transaction_delays.m_local_processing_delay_ns != -1)
	{
		container->set_transaction_processing_delay(
		    it_analyzer->second.m_transaction_delays.m_local_processing_delay_ns *
		    m_acked_sampling_ratio);
		container->set_next_tiers_delay(
		    it_analyzer->second.m_transaction_delays.m_merged_client_delay *
		    m_acked_sampling_ratio);
	}
#endif  // CYGWING_AGENT

	*statsd_limit = m_statsd_emitter->emit(container_info->m_id,
	                                       container_info->m_name,
	                                       container,
	                                       *statsd_limit);

	auto fs_list = m_mounted_fs_map.find(container_info->m_id);
	if (fs_list != m_mounted_fs_map.end())
	{
		for (const auto& fs : fs_list->second)
		{
			auto proto_fs = container->add_mounts();
			fs.to_protobuf(proto_fs);
		}
	}

#ifndef CYGWING_AGENT
	auto thread_count = it_analyzer->second.m_metrics.m_threads_count;
	container->mutable_resource_counters()->set_threads_count(thread_count);

	//
	// Emit the executed commands for this container
	//
	if (m_configuration->get_commandlines_capture_enabled())
	{
		auto ecit = m_executed_commands.find(container_id);

		if (ecit != m_executed_commands.end())
		{
			emit_executed_commands(NULL, container, &(ecit->second));
		}
	}
#endif

	it_analyzer->second.m_files_stat.emit(container, m_top_files_per_container);
	it_analyzer->second.m_devs_stat.emit(container, m_device_map, m_top_file_devices_per_container);

	sinsp_connection_aggregator::filter_and_emit(*it_analyzer->second.m_connections_by_serverport,
	                                             container,
	                                             TOP_SERVER_PORTS_IN_SAMPLE_PER_CONTAINER,
	                                             m_acked_sampling_ratio);

	sinsp_counter_time totals;
	it_analyzer->second.m_metrics.m_metrics.get_total(&totals);
	container->mutable_resource_counters()->set_syscall_count(totals.m_count);

	it_analyzer->second.clear();
}

void sinsp_analyzer::coalesce_unemitted_stats(const vector<std::string>& emitted_containers)
{
	std::set<std::string> unemitted_containers;

	for (const auto& container : m_containers)
	{
		unemitted_containers.insert(container.first);
	}

	for (const auto& container : emitted_containers)
	{
		unemitted_containers.erase(container);
	}

	draiosproto::unreported_stats* container_buffer = m_metrics->mutable_unreported_counters();

	auto rc = container_buffer->mutable_resource_counters();

	const auto containers_info = m_inspector->m_container_manager.get_containers();

	// the metrics need a couple of denominators that are maintained across calls.
	// this is a bit ugly...
	uint64_t opaque_denominator_a = 0;
	uint64_t opaque_denominator_b = 0;
	uint64_t opaque_denominator_c = 0;
	uint64_t opaque_denominator_d = 0;
	uint32_t count = 0;
	for (const auto& container_name : unemitted_containers)
	{
		count++;
		const auto& container_it = containers_info->find(container_name);
		if (container_it == containers_info->end())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
			                "container %s not found for coalescing (probably deleted). skipping.",
			                container_name.c_str());
			continue;
		}
		const auto& sinsp_container_data = container_it->second;
		auto& analyzer_container_data = m_containers.find(sinsp_container_data->m_id)->second;

#ifndef CYGWING_AGENT
		rc->set_connection_queue_usage_pct(
		    std::max(rc->connection_queue_usage_pct(),
		             analyzer_container_data.m_metrics.m_connection_queue_usage_pct));
		if (!m_inspector->is_nodriver())
		{
			rc->set_fd_usage_pct(rc->fd_usage_pct() +
			                     analyzer_container_data.m_metrics.m_fd_usage_pct);
		}

#endif
		rc->set_cpu_pct(rc->cpu_pct() + analyzer_container_data.m_metrics.m_cpuload * 100);
		rc->set_resident_memory_usage_kb(rc->resident_memory_usage_kb() +
		                                 analyzer_container_data.m_metrics.m_res_memory_used_kb);
		rc->set_swap_memory_usage_kb(rc->swap_memory_usage_kb() +
		                             analyzer_container_data.m_metrics.m_swap_memory_used_kb);
		rc->set_major_pagefaults(rc->major_pagefaults() +
		                         analyzer_container_data.m_metrics.m_pfmajor);
		rc->set_minor_pagefaults(rc->minor_pagefaults() +
		                         analyzer_container_data.m_metrics.m_pfminor);
		rc->set_fd_count(rc->fd_count() + analyzer_container_data.m_metrics.m_fd_count);
		rc->set_cpu_shares(rc->cpu_shares() + sinsp_container_data->m_cpu_shares);
		rc->set_memory_limit_kb(rc->memory_limit_kb() +
		                        sinsp_container_data->m_memory_limit / 1024);
		rc->set_swap_limit_kb(rc->swap_limit_kb() + sinsp_container_data->m_swap_limit / 1024);
		rc->set_count_processes(rc->count_processes() +
		                        analyzer_container_data.m_metrics.get_process_count());
		rc->set_proc_start_count(rc->proc_start_count() +
		                         analyzer_container_data.m_metrics.get_process_start_count());
		rc->set_threads_count(rc->threads_count() +
		                      analyzer_container_data.m_metrics.m_threads_count);

		analyzer_container_data.m_metrics.m_metrics.coalesce_protobuf(
		    container_buffer->mutable_tcounters(),
		    m_acked_sampling_ratio,
		    opaque_denominator_a,
		    opaque_denominator_b);

#ifndef CYGWING_AGENT
		if (m_protocols_enabled)
		{
			analyzer_container_data.m_metrics.m_protostate->coalesce_protobuf(
			    container_buffer->mutable_protos(),
			    m_acked_sampling_ratio);
		}

		analyzer_container_data.m_req_metrics.coalesce_reqprotobuf(
		    container_buffer->mutable_reqcounters(),
		    m_acked_sampling_ratio,
		    opaque_denominator_c,
		    opaque_denominator_d);

		analyzer_container_data.m_metrics.m_syscall_errors.coalesce_protobuf(
		    container_buffer->mutable_syscall_errors(),
		    m_acked_sampling_ratio);

		analyzer_container_data.m_transaction_counters.coalesce_protobuf(
		    container_buffer->mutable_transaction_counters(),
		    container_buffer->mutable_max_transaction_counters(),
		    m_acked_sampling_ratio);
#endif

		sinsp_counter_time totals;
		analyzer_container_data.m_metrics.m_metrics.get_total(&totals);
		container_buffer->mutable_resource_counters()->set_syscall_count(
		    container_buffer->resource_counters().syscall_count() + totals.m_count);

		container_buffer->add_names(container_name);

		analyzer_container_data.clear();
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
	                "Total Containers Found: %d, Emitted: %d, Unemitted: %d, Coalesced: %d",
	                m_containers.size(),
	                emitted_containers.size(),
	                unemitted_containers.size(),
	                count);
}

void sinsp_analyzer::emit_chisel_metrics()
{
	uint32_t j = 0;

	m_chisel_metrics.clear();

	for (const auto& chisel : m_chisels)
	{
		chisel->do_end_of_sample();
	}

	for (const auto& metric : m_chisel_metrics)
	{
		auto statsd_proto = m_metrics->mutable_protos()->mutable_statsd()->add_statsd_metrics();
		metric.to_protobuf(statsd_proto);
		++j;

		if (j >= CHISEL_METRIC_LIMIT)
		{
			g_logger.log("statsd metrics limit reached, skipping remaining ones",
			             sinsp_logger::SEV_WARNING);
			break;
		}
	}

	if (j > 0)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Added %d chisel metrics", j);
	}
}

void sinsp_analyzer::emit_user_events()
{
	if (m_user_event_queue && m_user_event_queue->count())
	{
		sinsp_user_event evt;
		while (m_user_event_queue->get(evt))
		{
			auto user_event = m_metrics->add_events();
			user_event->set_timestamp_sec(evt.epoch_time_s());
			user_event->set_severity(evt.severity());
			const string& n = evt.name();
			if (!n.empty())
			{
				user_event->set_title(n);
			}
			const string& desc = evt.description();
			if (!desc.empty())
			{
				user_event->set_description(desc);
			}
			const string& sc = evt.scope();
			if (!sc.empty())
			{
				user_event->set_scope(sc);
			}
			for (const auto& p : evt.tags())
			{
				auto tags = user_event->add_tags();
				tags->set_key(p.first);
				tags->set_value(p.second);
			}
		}
#ifndef CYGWING_AGENT
		if (m_k8s)
		{
			m_k8s->clear_events();
		}
		if (m_docker)
		{
			m_docker->reset_event_counter();
		}

#endif
		if (g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			std::ostringstream ostr;
			ostr << "User event Proto:" << std::endl;
			for (const auto& e : m_metrics->events())
			{
				ostr << e.DebugString() << std::endl;
			}
			g_logger.log(ostr.str(), sinsp_logger::SEV_TRACE);
		}
	}
}

#ifndef CYGWING_AGENT
void sinsp_analyzer::match_prom_checks(THREAD_TYPE* tinfo,
                                       THREAD_TYPE* mtinfo,
                                       vector<prom_process>& prom_procs,
                                       bool use_host_filter)
{
	if (!m_prom_conf.enabled() || GET_AGENT_THREAD(mtinfo)->found_prom_check())
		return;

	const auto container = m_inspector->m_container_manager.get_container(tinfo->m_container_id);

	m_prom_conf.match_and_fill(tinfo,
	                           mtinfo,
	                           container.get(),
	                           *infra_state(),
	                           prom_procs,
	                           use_host_filter);
}
#endif

void sinsp_analyzer::match_checks_list(THREAD_TYPE* tinfo,
                                       THREAD_TYPE* mtinfo,
                                       const vector<app_check>& checks,
                                       vector<app_process>& app_checks_processes,
                                       const char* location)
{
	for (const auto& check : checks)
	{
		if (GET_AGENT_THREAD(mtinfo)->found_app_check(check))
			continue;
		if (check.match(tinfo))
		{
			string mm = "master.mesos";
			shared_ptr<app_process_conf_vals> conf_vals;
			set<uint16_t> listening_ports = GET_AGENT_THREAD(tinfo)->listening_ports();

			g_logger.format(sinsp_logger::SEV_DEBUG,
			                "Found check %s for process %d:%d from %s",
			                check.name().c_str(),
			                tinfo->m_pid,
			                tinfo->m_vpid,
			                location);

			// for mesos-master and mesos-slave app
			// checks, override the built-in conf vals
			// with the mesos-specific ones.
#ifndef CYGWING_AGENT
			if (check.module() == "mesos_master" || check.module() == "mesos_slave")
			{
				string auth_hostname = "localhost";

				// for dcos enterprise, the auth service only runs on the master. So for the slave,
				// set the auth hostname to the special name master.mesos, which always
				// resolves to the master
				if (check.module() == "mesos_slave")
				{
					auth_hostname = mm;
				}

				if (!m_mesos_conf_vals)
				{
					if (m_configuration->get_mesos_state_uri().empty())
					{
						g_logger.log(
						    "Not performing mesos master/slave app check as no mesos uri exists "
						    "yet",
						    sinsp_logger::SEV_DEBUG);
						continue;
					}
					else
					{
						// We now have enough information to generate mesos-specific
						// app check configuration, so create the object.
						m_mesos_conf_vals.reset(
						    new mesos_conf_vals(m_configuration->get_dcos_enterprise_credentials(),
						                        m_configuration->get_mesos_credentials(),
						                        m_configuration->get_mesos_state_uri(),
						                        auth_hostname));
					}
				}

				conf_vals = m_mesos_conf_vals;
			}
			else if (check.module() == "marathon")
			{
				if (!m_marathon_conf_vals)
				{
					// We now have enough information to generate marathon-specific
					// app check configuration, so create the object.

					// The marathon uri can either be the first configured
					// marathon uri or the first autodetected marathon uri. if both
					// are empty, we don't perform the app check at all.
					string marathon_uri;
					if (!m_configuration->get_marathon_uris().empty())
					{
						marathon_uri = m_configuration->get_marathon_uris().front();
					}
					else if (m_mesos && !m_mesos->marathon_uris().empty())
					{
						marathon_uri = m_mesos->marathon_uris().front();
					}

					if (marathon_uri.empty())
					{
						g_logger.log(
						    "Not performing marathon app check as no marathon uri exists yet",
						    sinsp_logger::SEV_DEBUG);
						continue;
					}
					else
					{
						m_marathon_conf_vals.reset(new marathon_conf_vals(
						    m_configuration->get_dcos_enterprise_credentials(),
						    m_configuration->get_marathon_credentials(),
						    marathon_uri,
						    mm));
					}
				}

				conf_vals = m_marathon_conf_vals;
			}
#endif  // CYGWING_AGENT

			app_checks_processes.emplace_back(check, tinfo);
			GET_AGENT_THREAD(mtinfo)->set_found_app_check(check);

			if (conf_vals)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
				                "Adding mesos/marathon specific info to app check %s",
				                check.name().c_str());
				app_checks_processes.back().set_conf_vals(conf_vals);
			}

			// Keep looking for all other app-checks that might match
		}
	}
}

#define REPORT(args...)                                            \
	do                                                             \
	{                                                              \
		len = snprintf(reportbuf + pos, reportbuflen - pos, args); \
		if (len == -1)                                             \
		{                                                          \
			return -1;                                             \
		}                                                          \
		pos += len;                                                \
	} while (0)

#define LOOP_REPORT(args...)                                       \
	do                                                             \
	{                                                              \
		len = snprintf(reportbuf + pos, reportbuflen - pos, args); \
		if (len == -1)                                             \
		{                                                          \
			pos = -1;                                              \
			return false;                                          \
		}                                                          \
		pos += len;                                                \
	} while (0)

int32_t sinsp_analyzer::generate_memory_report(OUT char* reportbuf,
                                               uint32_t reportbuflen,
                                               bool do_complete_report)
{
	int len;
	uint32_t pos = 0;
	uint32_t nfds = 0;
	uint32_t nfds_file = 0;
	uint32_t nfds_ipv4 = 0;
	uint32_t nfds_ipv6 = 0;
	uint32_t nfds_dir = 0;
	uint32_t nfds_ipv4s = 0;
	uint32_t nfds_ipv6s = 0;
	uint32_t nfds_fifo = 0;
	uint32_t nfds_unix = 0;
	uint32_t nfds_event = 0;
	uint32_t nfds_unknown = 0;
	uint32_t nfds_unsupported = 0;
	uint32_t nfds_signal = 0;
	uint32_t nfds_evtpoll = 0;
	uint32_t nfds_inotify = 0;
	uint32_t nfds_timerfd = 0;
	uint32_t ntransactions = 0;
	uint32_t ntransactions_http = 0;
	uint32_t ntransactions_mysql = 0;
	uint32_t ntransactions_postgres = 0;
	uint32_t ntransactions_mongodb = 0;
	uint32_t nqueuedtransactions_client = 0;
	uint32_t nqueuedtransactions_server = 0;
	uint32_t nqueuedtransactions_client_capacity = 0;
	uint32_t nqueuedtransactions_server_capacity = 0;

	REPORT("threads: %d\n", (int)m_inspector->m_thread_manager->m_threadtable.size());
	REPORT("connections: %d\n", (int)m_ipv4_connections->size());

	m_inspector->m_thread_manager->m_threadtable.loop([&](sinsp_threadinfo& sinsp_tinfo) {
#ifdef USE_AGENT_THREAD
		thread_analyzer_info& tinfo = dynamic_cast<thread_analyzer_info&>(sinsp_tinfo);
		ASSERT(tinfo == sinsp_tinfo);
#else
		sinsp_threadinfo& tinfo = sinsp_tinfo;
#endif

		if (!tinfo.is_main_thread())
		{
			return true;
		}
		main_thread_analyzer_info* main_info = GET_AGENT_THREAD(&tinfo)->main_thread_ainfo();

		for (uint32_t j = 0; j < main_info->m_server_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_server += main_info->m_server_transactions_per_cpu[j].size();
			nqueuedtransactions_server_capacity +=
			    main_info->m_server_transactions_per_cpu[j].capacity();
		}

		for (uint32_t j = 0; j < main_info->m_client_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_client += main_info->m_client_transactions_per_cpu[j].size();
			nqueuedtransactions_client_capacity +=
			    main_info->m_client_transactions_per_cpu[j].capacity();
		}

		if (do_complete_report)
		{
			LOOP_REPORT("    tid: %d comm: %s nfds:%d\n",
			            (int)tinfo.m_tid,
			            tinfo.m_comm.c_str(),
			            (int)tinfo.m_fdtable.size());
		}

		for (auto fdit = tinfo.m_fdtable.m_table.begin(); fdit != tinfo.m_fdtable.m_table.end();
		     ++fdit)
		{
			nfds++;

			switch (fdit->second.m_type)
			{
			case SCAP_FD_FILE:
			case SCAP_FD_FILE_V2:
				nfds_file++;
				break;
			case SCAP_FD_IPV4_SOCK:
				nfds_ipv4++;
				break;
			case SCAP_FD_IPV6_SOCK:
				nfds_ipv6++;
				break;
			case SCAP_FD_DIRECTORY:
				nfds_dir++;
				break;
			case SCAP_FD_IPV4_SERVSOCK:
				nfds_ipv4s++;
				break;
			case SCAP_FD_IPV6_SERVSOCK:
				nfds_ipv6s++;
				break;
			case SCAP_FD_FIFO:
				nfds_fifo++;
				break;
			case SCAP_FD_UNIX_SOCK:
				nfds_unix++;
				break;
			case SCAP_FD_EVENT:
				nfds_event++;
				break;
			case SCAP_FD_UNKNOWN:
				nfds_unknown++;
				break;
			case SCAP_FD_UNSUPPORTED:
				nfds_unsupported++;
				break;
			case SCAP_FD_SIGNALFD:
				nfds_signal++;
				break;
			case SCAP_FD_EVENTPOLL:
				nfds_evtpoll++;
				break;
			case SCAP_FD_INOTIFY:
				nfds_inotify++;
				break;
			case SCAP_FD_TIMERFD:
				nfds_timerfd++;
				break;
			default:
				nfds_unknown++;
			}

			if (fdit->second.is_transaction())
			{
				ntransactions++;

				if (fdit->second.m_usrstate != NULL)
				{
					if (fdit->second.m_usrstate->m_protoparser != NULL)
					{
						switch (fdit->second.m_usrstate->m_protoparser->get_type())
						{
						case sinsp_protocol_parser::PROTO_HTTP:
							ntransactions_http++;
							break;
						case sinsp_protocol_parser::PROTO_MYSQL:
							ntransactions_mysql++;
							break;
						case sinsp_protocol_parser::PROTO_POSTGRES:
							ntransactions_postgres++;
							break;
						case sinsp_protocol_parser::PROTO_MONGODB:
							ntransactions_mongodb++;
							break;
						case sinsp_protocol_parser::PROTO_TLS:
							break;
						default:
							ASSERT(false);
							break;
						}
					}
				}
			}
		}
		return true;
	});

	// check error from the loop above
	if (pos < 0)
	{
		return pos;
	}

	REPORT("FDs: %d\n", (int)nfds);
	REPORT("  ipv4: %d\n", (int)nfds_ipv4);
	REPORT("  ipv6: %d\n", (int)nfds_ipv6);
	REPORT("  dir: %d\n", (int)nfds_dir);
	REPORT("  ipv4s: %d\n", (int)nfds_ipv4s);
	REPORT("  ipv6s: %d\n", (int)nfds_ipv6s);
	REPORT("  fifo: %d\n", (int)nfds_fifo);
	REPORT("  unix: %d\n", (int)nfds_unix);
	REPORT("  event: %d\n", (int)nfds_event);
	REPORT("  file: %d\n", (int)nfds_file);
	REPORT("  unknown: %d\n", (int)nfds_unknown);
	REPORT("  unsupported: %d\n", (int)nfds_unsupported);
	REPORT("  signal: %d\n", (int)nfds_signal);
	REPORT("  evtpoll: %d\n", (int)nfds_evtpoll);
	REPORT("  inotify: %d\n", (int)nfds_inotify);
	REPORT("  timerfd: %d\n", (int)nfds_timerfd);

	REPORT("transactions: %d\n", (int)ntransactions);
	REPORT("  http: %d\n", (int)ntransactions_http);
	REPORT("  mysql: %d\n", (int)ntransactions_mysql);
	REPORT("  postgres: %d\n", (int)ntransactions_postgres);
	REPORT("  mongodb: %d\n", (int)ntransactions_mongodb);
	REPORT("  queued client: %d\n", (int)nqueuedtransactions_client);
	REPORT("  queued server: %d\n", (int)nqueuedtransactions_server);
	REPORT("  queue client capacity: %d\n", (int)nqueuedtransactions_client_capacity);
	REPORT("  queue server capacity: %d\n", (int)nqueuedtransactions_server_capacity);

	// fprintf(stdout, "%s", reportbuf);
	return pos;
}

#ifndef _WIN32
void sinsp_analyzer::set_statsd_iofds(const std::pair<FILE*, FILE*>& iofds, const bool forwarder)
{
	m_statsite_proxy =
	    std::make_shared<statsite_proxy>(iofds, m_configuration->get_statsite_check_format());

	g_logger.format(sinsp_logger::SEV_INFO,
	                "Creating statsd_emitter, security_enabled:  %s",
	                (security_config::is_enabled() ? "true" : "false"));

	m_statsd_emitter = statsd_emitter_factory::create(m_statsite_proxy, m_metric_limits);

	if (forwarder)
	{
		m_statsite_forwader_queue =
		    make_unique<posix_queue>("/sdc_statsite_forwarder_in", posix_queue::SEND, 1);
	}
}
#endif  // _WIN32

void sinsp_analyzer::set_fs_usage_from_external_proc(bool value)
{
	if (value)
	{
		m_mounted_fs_proxy = make_unique<mounted_fs_proxy>();
	}
	else
	{
		m_mounted_fs_proxy.reset();
	}
}

void sinsp_analyzer::set_emit_tracers(bool enabled)
{
	tracer_emitter::set_enabled(enabled);
}

void sinsp_analyzer::rearm_tracer_logging()
{
	auto now = sinsp_utils::get_current_time_ns();
	if (now > m_flush_log_time_restart)
	{
		m_flush_log_time_end = now + m_flush_log_time_duration;
		m_flush_log_time_restart = now + m_flush_log_time_cooldown;
	}
}

uint64_t sinsp_analyzer::flush_tracer_timeout()
{
	auto now = sinsp_utils::get_current_time_ns();

	if (now < m_flush_log_time_end)
	{
		return 0;
	}
	else if (now < m_flush_log_time_restart)
	{
		return tracer_emitter::no_timeout;
	}
	else
	{
		return m_flush_log_time;
	}
}

void sinsp_analyzer::enable_audit_tap(bool emit_local_connections)
{
	m_tap = std::make_shared<audit_tap>(&m_env_hash_config,
	                                    m_configuration->get_machine_id(),
	                                    emit_local_connections);
	m_threadtable_listener->set_audit_tap(m_tap);
}

void sinsp_analyzer::enable_secure_audit()
{
	m_secure_audit = std::make_shared<secure_audit>();
	m_secure_audit->set_data_handler(this);
	m_secure_audit->set_internal_metrics(this);
}

void sinsp_analyzer::enable_secure_profiling()
{
	m_falco_baseliner->set_data_handler(this);
}

void sinsp_analyzer::dump_infrastructure_state_on_next_flush()
{
	g_logger.log("Will dump infrastructure state on next flush", sinsp_logger::SEV_INFO);
	m_dump_local_infrastructure_state_on_next_flush = true;
	m_dump_global_infrastructure_state_on_next_flush = true;
}

void sinsp_analyzer::incr_command_lines_category(draiosproto::command_category cat, uint64_t delta)
{
	if (m_command_categories.find(cat) == m_command_categories.end())
	{
		m_command_categories.insert(std::pair<draiosproto::command_category, uint64_t>(cat, delta));
	}
	else
	{
		m_command_categories[cat] = m_command_categories[cat] + delta;
	}
}

bool sinsp_analyzer::should_terminate() const
{
	return m_die;
}

size_t sinsp_analyzer::num_server_programs() const
{
	return m_server_programs.size();
}

bool sinsp_analyzer::has_cpu_idle_data() const
{
	return !m_proc_stat.m_idle.empty();
}

double sinsp_analyzer::get_cpu_idle_data(const size_t cpuid) const
{
	return m_proc_stat.m_idle[cpuid];
}

bool sinsp_analyzer::has_cpu_steal_data() const
{
	return !m_proc_stat.m_steal.empty();
}

double sinsp_analyzer::get_cpu_steal_data(const size_t cpuid) const
{
	return m_proc_stat.m_steal[cpuid];
}

bool sinsp_analyzer::has_cpu_load_data() const
{
	return !m_proc_stat.m_loads.empty();
}

double sinsp_analyzer::get_cpu_load_data(size_t cpuid) const
{
	return m_proc_stat.m_loads[cpuid];
}

const env_hash::regex_list_t& sinsp_analyzer::get_environment_blacklist() const
{
	return *m_env_hash_config.m_env_blacklist.get();
}

bool sinsp_analyzer::find_java_process_name(const int pid, std::string& name) const
{
	bool found = false;

	auto process = m_jmx_metrics.find(pid);
	if (process != m_jmx_metrics.end())
	{
		name = process->second.name();
		found = true;
	}

	return found;
}

void sinsp_analyzer::secure_audit_filter_and_append_k8s_audit(
    const nlohmann::json& j,
    std::vector<std::string>& k8s_active_filters,
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters)
{
	if (m_secure_audit != nullptr)
	{
		m_secure_audit->filter_and_append_k8s_audit(j,
		                                            k8s_active_filters,
		                                            k8s_filters,
		                                            m_infrastructure_state);
	}
}

uint32_t sinsp_analyzer::get_thread_memory_id() const
{
	return m_thread_memory_id;
}

uint32_t sinsp_analyzer::get_num_dropped_ipv4_connections() const
{
	return m_ipv4_connections->get_n_drops();
}

void sinsp_analyzer::inject_statsd_metric(const std::string& container_id,
                                          const bool dest_is_ipv4_localhost,
                                          const char* const data,
                                          const uint32_t len)
{
	if (!m_statsite_proxy)
	{
		return;
	}

	//
	// This code involves several assumptions. I don't like it very much,
	// but it's what we've got so far. If the length is exactly 2000, that
	// probably implies that a) the data were truncated and b) the user has
	// not configured extended snaplen for the statsd port. If the length is
	// exactly 16000, that implies that a) the data were truncated and b)
	// the user HAS configured extended snaplen. Both of these situations
	// will result in the loss of statsd metrics, so we're going to emit
	// a very mild log message (mild because this is a guess).
	//
	if (len == 2000)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Possible statsd truncation (len = 2000)");
	}
	if (len == 16000)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Possible statsd truncation (len = 16000)");
	}

	if (!container_id.empty())
	{
		// Send the metric as is, so it will be aggregated by host
		m_statsite_proxy->send_metric(data, len);
		m_statsite_proxy->send_container_metric(container_id, data, len);
	}
	else if (m_statsd_capture_localhost.load(memory_order_relaxed) || !dest_is_ipv4_localhost ||
	         statsite_config::use_host_statsd())
	{
		m_statsite_proxy->send_metric(data, len);
	}
}

bool sinsp_analyzer::resolve_custom_container(sinsp_container_manager* const manager,
                                              THREAD_TYPE* const tinfo,
                                              const bool query_os_for_missing_info)
{
	return m_custom_container.resolve(manager, tinfo, query_os_for_missing_info);
}

void sinsp_analyzer::remove_ipv4_connection(const ipv4tuple& ipv4info)
{
	m_ipv4_connections->remove_connection(ipv4info);
}

uint32_t sinsp_analyzer::get_thread_count() const
{
	return m_inspector->m_thread_manager->get_thread_count();
}

bool sinsp_analyzer::detect_and_match_stress_tool(const std::string& command)
{
	if (m_configuration->get_detect_stress_tools())
	{
		if (m_stress_tool_matcher.match(command))
		{
			if (!m_inspector->is_nodriver())
			{
				m_mode_switch_state = sinsp_analyzer::MSR_REQUEST_NODRIVER;
			}

			return true;
		}
	}

	return false;
}

void sinsp_analyzer::simulate_drop_mode(const bool enabled)
{
#if defined(SIMULATE_DROP_MODE)
	m_inspector->m_isdropping = enabled;
#endif
}

void sinsp_analyzer::add_executed_command(const std::string& container_id,
                                          const sinsp_executed_command& command)
{
	m_executed_commands[container_id].push_back(command);
}

void sinsp_analyzer::set_last_dropmode_switch_time(const uint64_t last_dropmode_switch_time)
{
	m_last_dropmode_switch_time = last_dropmode_switch_time;
}

sinsp_analyzer::mode_switch_state sinsp_analyzer::get_mode_switch_state() const
{
	return m_mode_switch_state;
}

void sinsp_analyzer::set_mode_switch_state(const mode_switch_state state)
{
	m_mode_switch_state = state;
}

uint64_t sinsp_analyzer::get_prev_flush_time_ns() const
{
	return m_prev_flush_time_ns;
}

bool sinsp_analyzer::has_statsite_proxy() const
{
	return m_statsite_proxy != nullptr;
}

void sinsp_analyzer::set_metrics_dir(const std::string& metrics_dir)
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);
	m_metrics_dir = metrics_dir;
}

std::string sinsp_analyzer::get_metrics_dir()
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);
	return m_metrics_dir;
}

sinsp_threadinfo* sinsp_analyzer::build_threadinfo(sinsp* inspector)
{
#ifdef USE_AGENT_THREAD
	auto tinfo = new thread_analzyer_info(inspector, this);
	tinfo->init();
	return tinfo;
#else
	return new sinsp_threadinfo(inspector);
#endif
}

uint64_t sinsp_analyzer::get_sample_duration() const
{
	return c_flush_interval->get_value() / m_acked_sampling_ratio;
}

void sinsp_analyzer::set_env_hash_ttl(uint64_t secs)
{
	uint64_t nsecs = secs * ONE_SECOND_IN_NS;
	if (nsecs < c_flush_interval->get_value())
	{
		m_env_hash_config.m_env_hash_ttl = 0;
	}
	else
	{
		m_env_hash_config.m_env_hash_ttl = nsecs - c_flush_interval->get_value();
	}
}

uint64_t self_cputime_analyzer::read_cputime()
{
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	uint64_t total_cputime_us = ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
	                            ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
	auto ret = total_cputime_us - m_previouscputime;
	m_previouscputime = total_cputime_us;
	return ret;
}

void self_cputime_analyzer::begin_flush()
{
	m_othertime[m_index] = read_cputime();
}

void self_cputime_analyzer::end_flush()
{
	m_flushtime[m_index] = read_cputime();
	incr_index();
}

double self_cputime_analyzer::calc_flush_percent()
{
	double tot_flushtime = accumulate(m_flushtime.begin(), m_flushtime.end(), 0);
	double tot_othertime = accumulate(m_othertime.begin(), m_othertime.end(), 0);
	double ret = tot_flushtime / (tot_flushtime + tot_othertime);
	if (std::isnan(ret) || std::isinf(ret))
	{
		return 0;
	}
	return ret;
}

// This method is here because analyzer_container_state has not a .cpp file and
// adding it just for this constructor seemed an overkill
analyzer_container_state::analyzer_container_state()
{
	m_connections_by_serverport =
	    make_unique<decltype(m_connections_by_serverport)::element_type>();
	m_last_bytes_in = 0;
	m_last_bytes_out = 0;
	m_last_cpu_time = 0;
	m_last_cpuacct_cgroup.clear();
	m_filter_state = FILT_NONE;
}

void analyzer_container_state::clear()
{
	m_metrics.clear();
	m_req_metrics.clear();
	m_transaction_counters.clear();
	m_transaction_delays.clear();
	m_server_transactions.clear();
	m_client_transactions.clear();
	m_connections_by_serverport->clear();
	m_files_stat.clear();
	m_devs_stat.clear();
}

vector<string> stress_tool_matcher::m_comm_list;

void stress_tool_matcher::set_comm_list(const vector<string>& comms)
{
	m_comm_list = comms;
}

bool analyzer_container_state::should_report_container(const sinsp_configuration* config,
                                                       const sinsp_container_info& cinfo,
                                                       const infrastructure_state* infra_state,
                                                       uint64_t ts,
                                                       bool& optional)
{
#ifndef CYGWING_AGENT
	// if we've already performed filtering, use previously calculated state
	if ((m_filter_state != FILT_NONE) && (ts - m_filter_state_ts < FILTER_STATE_CACHE_TIME))
	{
		optional = m_matched_generically;
		return m_filter_state == FILT_INCL;
	}

	m_filter_state_ts = ts;

	const auto filters = config->get_container_filter();
	if (!filters || !filters->enabled())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
		                "container %s, no filter configured",
		                cinfo.m_id.c_str());
		m_filter_state = FILT_INCL;
		optional = true;
		return true;
	}

	bool include =
	    filters->match(nullptr, nullptr, &cinfo, *infra_state, nullptr, &m_matched_generically);
#else
	bool include = true;
#endif

	m_filter_state = include ? FILT_INCL : FILT_EXCL;
	optional = m_matched_generically;

	g_logger.format(sinsp_logger::SEV_DEBUG,
	                "container %s, %s in report",
	                cinfo.m_id.c_str(),
	                (m_filter_state == FILT_INCL) ? "include" : "exclude");
	return m_filter_state == FILT_INCL;
}
