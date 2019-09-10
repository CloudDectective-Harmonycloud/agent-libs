/**
 * @file
 *
 * Implementation of metric_serializer -- an abstract base class for analyzer
 * metric serialization.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer.h"
#include "config.h"
#include "internal_metrics.h"
#include "sinsp.h"
#include "Poco/File.h"
#include "Poco/Path.h"

namespace libsanalyzer
{

type_config<std::string> metric_serializer::c_metrics_dir(
	"",
	"metricsfile.location. If unset, metrics won't be saved to disk.",
	"metricsfile",
	"location");

const uint64_t metric_serializer::NO_EVENT_NUMBER =
		std::numeric_limits<uint64_t>::max();

metric_serializer::data::data(const uint64_t evt_num,
                              const uint64_t ts,
                              const uint32_t sampling_ratio,
                              const double prev_flush_cpu_pct,
                              const uint64_t prev_flushes_duration_ns,
                              std::atomic<bool>& metrics_sent,
                              const double my_cpuload,
                              const int64_t n_proc_lookups,
                              const int64_t n_main_thread_lookups,
                              const draiosproto::metrics& metrics):
	m_evt_num(evt_num),
	m_ts(ts),
	m_sampling_ratio(sampling_ratio),
	m_prev_flush_cpu_pct(prev_flush_cpu_pct),
	m_prev_flushes_duration_ns(prev_flushes_duration_ns),
	m_metrics_sent(metrics_sent),
	m_my_cpuload(my_cpuload),
	m_n_proc_lookups(n_proc_lookups),
	m_n_main_thread_lookups(n_main_thread_lookups),
	m_metrics(std::make_shared<draiosproto::metrics>(metrics))
{
}

metric_serializer::metric_serializer(const internal_metrics::sptr_t& internal_metrics,
                                     const std::string& root_dir,
				     uncompressed_sample_handler& sample_handler):
	m_metrics_dir_mutex(),
	m_root_dir(root_dir),
	m_metrics_dir(""),
	m_internal_metrics(internal_metrics),
	m_uncompressed_sample_handler(sample_handler)
{ 
	if (!c_metrics_dir.get().empty())
	{
		std::string dir = Poco::Path(m_root_dir).append(c_metrics_dir.get()).toString();

		set_metrics_directory(dir);
	}
}

bool metric_serializer::get_emit_metrics_to_file() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return !m_metrics_dir.empty();
}

void metric_serializer::set_metrics_directory(const std::string& dir)
{
	// needs to be locked so user doesn't get bogus dir before we've "sanitized" it
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	m_metrics_dir = dir;

	if (!m_metrics_dir.empty())
	{
		if (m_metrics_dir[m_metrics_dir.size() -1] != DIR_PATH_SEPARATOR)
		{
			m_metrics_dir += DIR_PATH_SEPARATOR;
		}

		Poco::File md(m_metrics_dir);
		md.createDirectories();
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_INFO,
				"metricsfile.location not specified, metrics won't be saved to disk.");
	}
}

std::string metric_serializer::get_metrics_directory() const
{
	std::unique_lock<std::mutex> lock(m_metrics_dir_mutex);

	return m_metrics_dir;
}

} // end namespace libsanalyzer
