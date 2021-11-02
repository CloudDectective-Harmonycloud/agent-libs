#include "common_logger.h"
#include "config_update.h"
#include "container_config.h"
#include "error_handler.h"
#include "infrastructure_state.h"
#include "memdumper.h"
#include "protocol_handler.h"
#include "running_state.h"
#include "security_config.h"
#include "sinsp_factory.h"
#include "sinsp_worker.h"
#include "statsite_config.h"
#include "type_config.h"
#include "user_event_logger.h"
#include "utils.h"

#include <Poco/DateTimeFormatter.h>
#include <Poco/NumberFormatter.h>
#include <Poco/ThreadPool.h>

#include <grpc/grpc.h>
#include <grpc/support/log.h>

using namespace std;
using namespace dragent;
using namespace libsanalyzer;

namespace
{
COMMON_LOGGER();

type_config<uint16_t> config_increased_snaplen_port_range_start(
    0,
    "Starting port in the range of ports to enable a larger snaplen on",
    "increased_snaplen_port_range_start");
type_config<uint16_t> config_increased_snaplen_port_range_end(
    0,
    "Ending port in the range of ports to enable a larger snaplen on",
    "increased_snaplen_port_range_end");
type_config<bool> c_procfs_scan_thread(false,
                                       "set to enable the procfs scanning thread",
                                       "procfs_scanner",
                                       "enabled");

}  // namespace

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration,
                           const internal_metrics::sptr_t& im,
                           protocol_handler& handler,
                           capture_job_handler* capture_job_handler)
    : m_job_requests_interval(1000000000),
      m_initialized(false),
      m_configuration(configuration),
      m_protocol_handler(handler),
      m_analyzer(NULL),
#ifndef CYGWING_AGENT
      m_security_mgr(NULL),
      m_compliance_mgr(NULL),
      m_hosts_metadata_uptodate(true),
#endif
      m_capture_job_handler(capture_job_handler),
      m_dump_job_requests(10),
      m_last_loop_ns(0),
      m_statsd_capture_localhost(false),
      m_grpc_trace_enabled(false),
      m_last_mode_switch_time(0),
      m_next_iflist_refresh_ns(0),
      m_aws_metadata_refresher(*configuration),
      m_internal_metrics(im)
{
}

sinsp_worker::~sinsp_worker()
{
	if (m_inspector)
	{
		m_inspector->set_log_callback(0);
		// Manually delete the inspector so that it is destroyed
		// before the other objects
		m_inspector.reset();
	}

	delete m_analyzer;
#ifndef CYGWING_AGENT
	if (m_security_mgr != nullptr)
	{
		delete m_security_mgr;
	}
	if (m_compliance_mgr != nullptr)
	{
		delete m_compliance_mgr;
	}
#endif
}

void sinsp_worker::init(sinsp::ptr& inspector,
                        sinsp_analyzer* analyzer,
                        security_mgr* sm,
                        compliance_mgr* cm)
{
	if (m_initialized)
	{
		return;
	}

	m_initialized = true;

	m_inspector = inspector;
	m_analyzer = analyzer;
	m_security_mgr = sm;
	m_compliance_mgr = cm;

	stress_tool_matcher::set_comm_list(m_configuration->m_stress_tools);

	for (const auto& comm : m_configuration->m_suppressed_comms)
	{
		m_inspector->suppress_events_comm(comm);
	}

	m_inspector->set_query_docker_image_info(m_configuration->m_query_docker_image_info);
	m_inspector->set_cri_socket_path(c_cri_socket_path->get_value());
	m_inspector->set_cri_timeout(c_cri_timeout_ms.get_value());
	m_inspector->set_cri_extra_queries(c_cri_extra_queries.get_value());
	m_inspector->set_cri_async(c_cri_async.get_value());
	m_inspector->set_cri_delay(c_cri_delay_ms.get_value());
	m_inspector->set_container_labels_max_len(m_configuration->m_containers_labels_max_len);

	if (c_cri_socket_path->get_value().empty())
	{
		LOG_INFO("CRI support disabled.");
	}
	else
	{
		LOG_INFO("CRI support enabled, socket: %s", c_cri_socket_path->get_value().c_str());
	}

	//
	// Start the capture with sinsp
	//
	LOG_INFO("Opening the capture source");
	if (!m_configuration->m_input_filename.empty())
	{
		m_inspector->open(m_configuration->m_input_filename);
	}
	else if (!feature_manager::instance().get_enabled(DRIVER))
	{
		m_inspector->open_nodriver();
		// Change these values so the inactive thread pruning
		// runs more often
		m_inspector->m_thread_timeout_ns = 0;
		m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;
	}
	else if (!feature_manager::instance().get_enabled(FULL_SYSCALLS))
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(
		    m_configuration->m_detect_stress_tools);
		m_inspector->open("");
		m_inspector->set_simpledriver_mode();
		m_analyzer->set_simpledriver_mode();
	}
	else
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(
		    m_configuration->m_detect_stress_tools);

		m_inspector->open("");

		if (m_configuration->m_snaplen != 0)
		{
			m_inspector->set_snaplen(m_configuration->m_snaplen);
		}

		uint16_t range_start = config_increased_snaplen_port_range_start.get_value();
		uint16_t range_end = config_increased_snaplen_port_range_end.get_value();

		if (range_start > 0 && range_end > 0)
		{
			try
			{
				m_inspector->set_fullcapture_port_range(range_start, range_end);
			}
			catch (const sinsp_exception& e)
			{
				// If (for some reason) sysdig doesn't have the corresponding changes
				// then it will throw a sinsp_exception when setting the fullcapture
				// range. Just log an error and continue.
				LOG_ERROR(
				    "Could not set increased snaplen size (are you running with updated "
				    "sysdig?): " +
				    string(e.what()));
			}
		}

		const uint16_t statsd_port = libsanalyzer::statsite_config::instance().get_udp_port();

		if (statsd_port != libsanalyzer::statsite_config::DEFAULT_STATSD_PORT)
		{
			try
			{
				m_inspector->set_statsd_port(statsd_port);
			}
			catch (const sinsp_exception& e)
			{
				// The version of sysdig we're working with doesn't
				// support this operation.
				LOG_ERROR(
				    "Could not set statsd port in driver (are "
				    "you running with updated sysdig?): " +
				    string(e.what()));
			}
		}
	}

#ifndef CYGWING_AGENT
	for (const auto type : m_configuration->m_suppressed_types)
	{
		const std::string type_str = to_string(type);

		try
		{
			LOG_DEBUG("Setting eventmask for ignored type: %s", type_str.c_str());
			m_inspector->unset_eventmask(type);
		}
		catch (const sinsp_exception& ex)
		{
			LOG_ERROR("Setting eventmask for type '%s' failed, err: %s",
			          type_str.c_str(),
			          ex.what());
		}
	}
#endif  // CYGWING_AGENT

	if (c_procfs_scan_thread.get_value())
	{
		LOG_INFO("Procfs scan thread enabled, ignoring switch events");
		try
		{
			m_inspector->unset_eventmask(PPME_SCHEDSWITCH_1_E);
			m_inspector->unset_eventmask(PPME_SCHEDSWITCH_6_E);
		}
		catch (const sinsp_exception& ex)
		{
			LOG_ERROR("Failed to ignore switch events, err: %s", ex.what());
		}
	}

	if (m_configuration->m_aws_metadata.m_public_ipv4)
	{
		sinsp_ipv4_ifinfo aws_interface(m_configuration->m_aws_metadata.m_public_ipv4,
		                                m_configuration->m_aws_metadata.m_public_ipv4,
		                                m_configuration->m_aws_metadata.m_public_ipv4,
		                                "aws");
		m_inspector->import_ipv4_interface(aws_interface);
	}

	m_analyzer->set_protocols_enabled(m_configuration->m_protocols_enabled);
	m_analyzer->set_statsd_capture_localhost(m_statsd_capture_localhost);

	m_analyzer->set_container_patterns(m_configuration->m_container_patterns);
	m_analyzer->set_containers_labels_max_len(m_configuration->m_containers_labels_max_len);
	m_next_iflist_refresh_ns = sinsp_utils::get_current_time_ns() + IFLIST_REFRESH_FIRST_TIMEOUT_NS;

	m_analyzer->set_user_event_queue(m_user_event_queue);

	m_analyzer->set_emit_tracers(m_configuration->m_emit_tracers);
	m_analyzer->set_flush_log_time(m_configuration->m_flush_log_time);
	m_analyzer->set_flush_log_time_duration(m_configuration->m_flush_log_time_duration);
	m_analyzer->set_flush_log_time_cooldown(m_configuration->m_flush_log_time_cooldown);

#ifndef CYGWING_AGENT
	m_analyzer->set_coclient_max_loop_evts(m_configuration->m_coclient_max_loop_evts);
#endif
	m_analyzer->set_max_n_external_clients(m_configuration->m_max_n_external_clients);
	m_analyzer->set_top_connections_in_sample(m_configuration->m_top_connections_in_sample);
	m_analyzer->set_top_processes_in_sample(m_configuration->m_top_processes_in_sample);
	m_analyzer->set_top_processes_per_container(m_configuration->m_top_processes_per_container);
	m_analyzer->set_report_source_port(m_configuration->m_report_source_port);

	m_analyzer->set_track_connection_status(m_configuration->m_track_connection_status);
	m_analyzer->set_connection_truncate_report_interval(
	    m_configuration->m_connection_truncate_report_interval);
	m_analyzer->set_connection_truncate_log_interval(
	    m_configuration->m_connection_truncate_log_interval);

	m_analyzer->set_username_lookups(m_configuration->m_username_lookups);

	m_analyzer->set_top_files(m_configuration->m_top_files_per_prog,
	                          m_configuration->m_top_files_per_container,
	                          m_configuration->m_top_files_per_host);

	m_analyzer->set_top_devices(m_configuration->m_top_file_devices_per_prog,
	                            m_configuration->m_top_file_devices_per_container,
	                            m_configuration->m_top_file_devices_per_host);
}

void sinsp_worker::run()
{
	uint64_t nevts = 0;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;

	m_pthread_id = pthread_self();

	LOG_INFO("sinsp_worker: Starting");

	if (!m_initialized)
	{
		throw sinsp_exception("Starting uninitialized worker");
	}

	auto& state = running_state::instance();
	if (m_configuration->m_config_test)
	{
		LOG_INFO("Config Test complete.");
		state.shut_down();
		m_analyzer->dump_config_test();
	}

	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	while (!state.is_terminated())
	{
		if (m_configuration->m_evtcnt != 0 && nevts == m_configuration->m_evtcnt)
		{
			LOG_INFO("All events have been processed.");
			state.shut_down();
			break;
		}

		res = m_inspector->next(&ev);

		if (res == SCAP_TIMEOUT)
		{
			m_last_loop_ns = sinsp_utils::get_current_time_ns();
			continue;
		}
		else if (res == SCAP_EOF)
		{
			break;
		}
		else if (res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			LOGGED_THROW(sinsp_exception, "%s", m_inspector->getlasterr().c_str());
		}

		if (m_analyzer->get_mode_switch_state() >= sinsp_analyzer::MSR_REQUEST_NODRIVER)
		{
			if (m_analyzer->get_mode_switch_state() == sinsp_analyzer::MSR_REQUEST_NODRIVER)
			{
				auto evt = sinsp_user_event(
				    ev->get_ts() / ONE_SECOND_IN_NS,
				    "Agent switch to nodriver",
				    "Agent switched to nodriver mode due to high overhead",
				    std::move(event_scope("host.mac", m_configuration->machine_id()).get_ref()),
				    {{"source", "agent"}},
				    user_event_logger::SEV_EVT_WARNING);
				user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);

				m_last_mode_switch_time = ev->get_ts();

				m_inspector->close();
				m_analyzer->set_mode_switch_state(sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER);
				m_analyzer->ack_sampling_ratio(1);

				m_inspector->open_nodriver();
				// Change these values so the inactive thread pruning
				// runs more often
				m_inspector->m_thread_timeout_ns = 0;
				m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;

				continue;
			}
			else
			{
				static bool full_mode_event_sent = false;
				if (ev->get_ts() - m_last_mode_switch_time > MIN_NODRIVER_SWITCH_TIME)
				{
					// TODO: investigate if we can void agent restart and just reopen the inspector
					LOGGED_THROW(sinsp_exception,
					             "restarting agent to restore normal operation mode");
				}
				else if (!full_mode_event_sent &&
				         ev->get_ts() - m_last_mode_switch_time >
				             MIN_NODRIVER_SWITCH_TIME - 2 * ONE_SECOND_IN_NS)
				{
					// Since we restart the agent to apply the switch back, we have to send the
					// event few seconds before doing it otherwise there can be chances that it's
					// not sent at all
					full_mode_event_sent = true;
					auto evt = sinsp_user_event(
					    ev->get_ts() / ONE_SECOND_IN_NS,
					    "Agent restore full mode",
					    "Agent restarting to restore full operation mode",
					    std::move(event_scope("host.mac", m_configuration->machine_id()).get_ref()),
					    {{"source", "agent"}},
					    user_event_logger::SEV_EVT_WARNING);

					user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);
				}
			}
		}

		//
		// Update the time
		//
		ts = ev->get_ts();
		m_last_loop_ns = ts;

		if (dragent_configuration::c_enable_aws_metadata.get_value())
		{
			if (!m_inspector->is_capture() && (ts > m_next_iflist_refresh_ns) &&
			    !m_aws_metadata_refresher.is_running())
			{
				Poco::ThreadPool::defaultPool().start(m_aws_metadata_refresher, "aws_metadata_refresher");
				m_next_iflist_refresh_ns =
				    sinsp_utils::get_current_time_ns() + IFLIST_REFRESH_TIMEOUT_NS;
			}
			if (m_aws_metadata_refresher.done())
			{
				LOG_INFO("Refresh network interfaces list");
				m_inspector->refresh_ifaddr_list();
				if (m_configuration->m_aws_metadata.m_public_ipv4)
				{
					sinsp_ipv4_ifinfo aws_interface(m_configuration->m_aws_metadata.m_public_ipv4,
					                                m_configuration->m_aws_metadata.m_public_ipv4,
					                                m_configuration->m_aws_metadata.m_public_ipv4,
					                                "aws");
					m_inspector->import_ipv4_interface(aws_interface);
				}
				m_aws_metadata_refresher.reset();
			}
		}

		k8s_metadata_sender::instance().send_k8s_metadata_message_on_interval(ts);

#ifndef CYGWING_AGENT
		bool update_hosts_metadata = !m_hosts_metadata_uptodate.test_and_set();

		// Possibly pass the event to the security manager
		if (m_security_mgr)
		{
			std::string errstr;
			if (update_hosts_metadata)
			{
				m_security_mgr->request_reload_policies_v2();
			}
			m_security_mgr->process_event(ev);
		}

		if (m_compliance_mgr)
		{
			if (update_hosts_metadata)
			{
				m_compliance_mgr->request_refresh_compliance_tasks();
			}
			m_compliance_mgr->process_event(ev);
		}
#endif

		m_capture_job_handler->process_event(ev);

		//
		// Update the event count
		//
		++nevts;
	}

	LOG_INFO("sinsp_worker: Terminating");
}

#ifndef CYGWING_AGENT
void sinsp_worker::request_load_policies_v2(const draiosproto::policies_v2& policies_v2)
{
	if (m_security_mgr)
	{
		m_security_mgr->request_load_policies_v2(policies_v2);
		return;
	}

	LOG_INFO("Saving policies_v2");
	if (m_security_policies_v2_backup)
	{
		*m_security_policies_v2_backup = policies_v2;
	}
	else
	{
		m_security_policies_v2_backup = make_unique<draiosproto::policies_v2>(policies_v2);
	}
}

bool sinsp_worker::is_stall_fatal() const
{
	// If the input filename is not empty then we are reading an scap file
	// that has old timestamps so tell the caller to not check for stalls
	return m_configuration->m_input_filename.empty();
}

void sinsp_worker::receive_hosts_metadata(const draiosproto::orchestrator_events& evts)
{
	m_analyzer->mutable_infra_state()->receive_hosts_metadata(evts.events());
	m_hosts_metadata_uptodate.clear();
}
#endif

void sinsp_worker::do_grpc_tracing()
{
	if (m_grpc_trace_enabled)
	{
		m_grpc_trace_enabled = false;
		m_configuration->m_dirty_shutdown_report_log_size_b =
		    m_configuration->m_dirty_shutdown_default_report_log_size_b;
		LOG_INFO("Received SIGSTKFLT, disabling gRPC tracing");
		grpc_tracer_set_enabled("all", 0);
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR);
	}
	else
	{
		m_grpc_trace_enabled = true;
		m_configuration->m_dirty_shutdown_report_log_size_b =
		    m_configuration->m_dirty_shutdown_trace_report_log_size_b;
		LOG_INFO("Received SIGSTKFLT, enabling gRPC tracing");
		grpc_tracer_set_enabled("all", 1);
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
	}
}
