#include "internal_metrics.h"

#include <algorithm>

type_config<bool> internal_metrics::c_extra_internal_metrics(
    false,
    "set to true to send full complement of internal metrics",
    "extra_internal_metrics");

internal_metrics::internal_metrics() {}

void internal_metrics::notify(Poco::Message::Priority sev)
{
	switch (sev)
	{
	case Poco::Message::PRIO_ERROR:
		++m_log.err;
		break;
	case Poco::Message::PRIO_WARNING:
		++m_log.warn;
		break;
	case Poco::Message::PRIO_INFORMATION:
		++m_log.info;
		break;
	case Poco::Message::PRIO_DEBUG:
		++m_log.debug;
		break;
	default:
		break;
	}
}

void internal_metrics::set_subprocesses(subprocs_t& subprocesses)
{
	Poco::ScopedWriteRWLock subprocs_lck(m_analyzer.subprocs_lock);
	m_analyzer.subprocs = subprocesses;
}

void internal_metrics::update_subprocess_metrics(sinsp_procfs_parser* procfs_parser)
{
	Poco::ScopedReadRWLock subprocs_lck(m_analyzer.subprocs_lock);

	for (auto& subproc : m_analyzer.subprocs)
	{
		std::string name = subproc.first;
		uint64_t pid = subproc.second;

		ASSERT(pid > 0);
		if (pid > 0)
		{
			if (m_analyzer.subprocs_old_jiffies.find(pid) == m_analyzer.subprocs_old_jiffies.end())
			{
				m_analyzer.subprocs_old_jiffies[pid] = (uint64_t)-1LL;
			}

			int64_t cpu = round(
			    procfs_parser->get_process_cpu_load_sync(pid,
			                                             &m_analyzer.subprocs_old_jiffies[pid]) *
			    100);
			long mem = procfs_parser->get_process_rss_bytes(pid) / 1024;

			if (name == "mountedfs_reader")
			{
				set_mountedfs_reader_cpu(cpu);
				set_mountedfs_reader_memory(mem);
			}
			else if (name == "cointerface")
			{
				set_cointerface_cpu(cpu);
				set_cointerface_memory(mem);
			}
			else if (name == "sdagent")
			{
				set_agent_cpu(cpu);
				set_agent_memory(mem);
			}
			else if (name == "sdjagent")
			{
				set_java_cpu(cpu);
				set_java_memory(mem);
			}
			else if (name == "statsite_forwarder")
			{
				set_statsite_forwarder_cpu(cpu);
				set_statsite_forwarder_memory(mem);
			}
			else if (name == "sdchecks")
			{
				set_appcheck_cpu(cpu);
				set_appcheck_memory(mem);
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_WARNING,
			                "watchdog: invalid pid %lu for subprocess %s",
			                pid,
			                name.c_str());
		}
	}
}

void internal_metrics::add_ext_source(ext_source* src)
{
	m_ext_sources.push_back(src);
}

void internal_metrics::send_command_categories(draiosproto::statsd_info* statsd_info)
{
	for (auto& pair : m_analyzer.m_command_categories)
	{
		if (pair.first == draiosproto::CAT_HEALTHCHECK)
		{
			// Keeping this as-is as it was a previously emitted metric
			write_metric(statsd_info,
			             "dragent.analyzer.n_container_healthcheck_command_lines",
			             draiosproto::STATSD_GAUGE,
			             pair.second);
		}

		const google::protobuf::EnumDescriptor* descriptor =
		    draiosproto::command_category_descriptor();

		std::string name = descriptor->FindValueByNumber(pair.first)->name();

		// Drop the leading CAT_ and convert to lower case
		if (name.find("CAT_", 0) == 0)
		{
			name.erase(0, 4);
		}

		std::transform(name.begin(), name.end(), name.begin(), ::tolower);

		write_metric(statsd_info,
		             "dragent.analyzer.command_line_cats.n_" + name,
		             draiosproto::STATSD_GAUGE,
		             pair.second);
	}
}

void internal_metrics::emit(draiosproto::statsd_info* statsd_info,
                            const scap_stats& capture_stats,
                            double flush_share,
                            uint32_t sampling_ratio,
                            uint64_t flush_duration_ns,
                            uint64_t n_proc_lookups,
                            uint64_t n_main_thread_lookups,
                            uint64_t max_sinsp_buf_used,
                            uint64_t analyzer_cpu_percentage)
{
	set_n_evts(capture_stats.n_evts);
	set_n_drops(capture_stats.n_drops);
	set_n_drops_buffer(capture_stats.n_drops_buffer);
	set_n_preemptions(capture_stats.n_preemptions);
	set_n_proc_lookups(n_proc_lookups);
	set_n_main_thread_lookups(n_main_thread_lookups);

	set_fp(static_cast<int64_t>(round(flush_share * 100)));
	set_sr(sampling_ratio);
	set_analyzer_cpu_percentage(analyzer_cpu_percentage);
	set_fl(flush_duration_ns / 1000000);

	bool sent;
	if (c_extra_internal_metrics.get_value())
	{
		sent = send_all(statsd_info, max_sinsp_buf_used);
	}
	else
	{
		sent = send_some(statsd_info, max_sinsp_buf_used);
	}

	if (sent)
	{
		if (g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			g_logger.log(statsd_info->DebugString(), sinsp_logger::SEV_TRACE);
		}
	}
	else
	{
		g_logger.log("Error processing agent internal metrics.", sinsp_logger::SEV_WARNING);
	}
}

bool internal_metrics::send_all(draiosproto::statsd_info* statsd_info, uint64_t max_sinsp_buf_used)
{
	bool ret = false;
	if (statsd_info)
	{
		// log
		write_metric(statsd_info, "dragent.log.err", draiosproto::STATSD_COUNT, m_log.err);
		write_metric(statsd_info, "dragent.log.warn", draiosproto::STATSD_COUNT, m_log.warn);
		write_metric(statsd_info, "dragent.log.info", draiosproto::STATSD_COUNT, m_log.info);
		write_metric(statsd_info, "dragent.log.debug", draiosproto::STATSD_COUNT, m_log.debug);

		// analyzer
		write_metric(statsd_info,
		             "dragent.analyzer.max_sinsp_buf_used",
		             draiosproto::STATSD_GAUGE,
		             max_sinsp_buf_used);
		write_metric(statsd_info,
		             "dragent.analyzer.processes",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.process_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.threads",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.thread_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.threads.dropped",
		             draiosproto::STATSD_COUNT,
		             m_analyzer.thread_drop_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.containers",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.container_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.javaprocs",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.javaproc_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.appchecks",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.appcheck_cnt);
		write_metric(statsd_info,
		             "dragent.analyzer.mesos.autodetect",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.mesos_autodetect ? 1 : 0);
		write_metric(statsd_info,
		             "dragent.analyzer.mesos.detected",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.mesos_detected ? 1 : 0);
		write_metric(statsd_info,
		             "dragent.analyzer.fp.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.fp);
		write_metric(statsd_info,
		             "dragent.analyzer.fl.ms",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.fl);
		write_metric(statsd_info, "dragent.analyzer.sr", draiosproto::STATSD_GAUGE, m_analyzer.sr);
		write_metric(statsd_info,
		             "dragent.analyzer.cpu_percentage",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.analyzer_cpu_percentage);

		write_metric(statsd_info,
		             "dragent.analyzer.n_evts",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_evts);
		write_metric(statsd_info,
		             "dragent.analyzer.n_drops",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_drops);
		write_metric(statsd_info,
		             "dragent.analyzer.n_drops_buffer",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_drops_buffer);
		write_metric(statsd_info,
		             "dragent.analyzer.n_preemptions",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_preemptions);

		write_metric(statsd_info,
		             "dragent.analyzer.n_proc_lookups",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_proc_lookups);
		write_metric(statsd_info,
		             "dragent.analyzer.n_main_thread_lookups",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_main_thread_lookups);

		write_metric(statsd_info,
		             "dragent.analyzer.n_command_lines",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_command_lines);

		write_metric(statsd_info,
		             "dragent.analyzer.baseliner_enabled",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.baseliner_enabled ? 1 : 0);

		send_command_categories(statsd_info);

		// subprocesses
		write_metric(statsd_info,
		             "dragent.subproc.agent.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.agent_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.agent.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.agent_memory);
		write_metric(statsd_info,
		             "dragent.subproc.java.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.java_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.java.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.java_memory);
		write_metric(statsd_info,
		             "dragent.subproc.appcheck.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.appcheck_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.appcheck.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.appcheck_memory);
		write_metric(statsd_info,
		             "dragent.subproc.mountedfs.reader.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.mountedfs_reader_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.mountedfs.reader.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.mountedfs_reader_memory);
		write_metric(statsd_info,
		             "dragent.subproc.cointerface.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.cointerface_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.cointerface.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.cointerface_memory);
		write_metric(statsd_info,
		             "dragent.subproc.statsite.forwarder.cpu.pct100",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.statsite_forwarder_cpu);
		write_metric(statsd_info,
		             "dragent.subproc.statsite.forwarder.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.statsite_forwarder_memory);

		send_secure_audit_metrics(statsd_info);

		// external sources
		for (auto& src : m_ext_sources)
		{
			src->send_all(statsd_info);
		}
		ret = true;
	}

	reset();
	return ret;
}

bool internal_metrics::send_some(draiosproto::statsd_info* statsd_info, uint64_t max_sinsp_buf_used)
{
	bool ret = false;
	if (statsd_info)
	{
		write_metric(statsd_info,
		             "dragent.analyzer.max_sinsp_buf_used",
		             draiosproto::STATSD_GAUGE,
		             max_sinsp_buf_used);
		write_metric(statsd_info,
		             "dragent.analyzer.fl.ms",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.fl);
		write_metric(statsd_info, "dragent.analyzer.sr", draiosproto::STATSD_GAUGE, m_analyzer.sr);

		write_metric(statsd_info,
		             "dragent.analyzer.n_evts",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_evts);
		write_metric(statsd_info,
		             "dragent.analyzer.n_drops",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_drops);
		write_metric(statsd_info,
		             "dragent.analyzer.n_drops_buffer",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_drops_buffer);
		write_metric(statsd_info,
		             "dragent.analyzer.n_main_thread_lookups",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_main_thread_lookups);

		write_metric(statsd_info,
		             "dragent.analyzer.n_command_lines",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.n_command_lines);

		send_command_categories(statsd_info);

		write_metric(statsd_info,
		             "dragent.subproc.cointerface.memory.kb",
		             draiosproto::STATSD_GAUGE,
		             m_analyzer.cointerface_memory);

		send_secure_audit_metrics(statsd_info);

		// external sources
		for (auto& src : m_ext_sources)
		{
			src->send_some(statsd_info);
		}
		ret = true;
	}

	reset();
	return ret;
}

void internal_metrics::send_secure_audit_metrics(draiosproto::statsd_info* statsd_info)
{
	// secure_audit metrics
	if (get_secure_audit_n_sent_protobufs() != -1)
	{
		write_metric(statsd_info,
		             "dragent.secure_audit.n_sent_protobufs",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_n_sent_protobufs());
		write_metric(statsd_info,
		             "dragent.secure_audit.fl.ms",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_fl_ms());
		write_metric(statsd_info,
		             "dragent.secure_audit.emit.ms",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_emit_ms());

		write_metric(statsd_info,
		             "dragent.secure_audit.executed_commands",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_executed_commands_count());
		write_metric(statsd_info,
		             "dragent.secure_audit.connections",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_connections_count());
		write_metric(statsd_info,
		             "dragent.secure_audit.k8s",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_k8s_count());
		write_metric(statsd_info,
		             "dragent.secure_audit.executed_commands_drop",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_executed_commands_dropped_count());
		write_metric(statsd_info,
		             "dragent.secure_audit.connections_drop",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_connections_dropped_count());
		write_metric(statsd_info,
		             "dragent.secure_audit.k8s_drop",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_k8s_dropped_count());

		write_metric(statsd_info,
		             "dragent.secure_audit.connections_no_interactive_drop",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_connections_not_interactive_dropped());
		write_metric(statsd_info,
		             "dragent.secure_audit.k8s_enrich_errors",
		             draiosproto::STATSD_GAUGE,
		             get_secure_audit_k8s_enrich_errors());
	}
}

void internal_metrics::reset()
{
	// only reset counters (which are essentially gauges
	// with value set by accumulation), true gauges are
	// better left as they are to avoid sending zeros
	// (eg. memory usages are updated from another
	// thread, and there's no guarantee that the update
	// will happen before the next emit, so it is better
	// to send a slightly stale value than zero)
	m_log.err = 0;
	m_log.warn = 0;
	m_log.info = 0;
	m_log.debug = 0;
}
