//
// Created by Luca Marturana on 29/06/15.
//

#include "app_checks.h"
#include "common_logger.h"
#include "prometheus.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "type_config.h"
#include <utils.h>
#include <zlib.h>

namespace
{

COMMON_LOGGER();

type_config<bool> c_sdagent_compression_enabled(
		false,
		"sdagent sends compressed metrics",
		"app_checks_compress_data");

}


using namespace std;

Json::Value yaml_to_json(const YAML::Node& yaml)
{
	Json::Value ret;
	switch(yaml.Type())
	{
	case YAML::NodeType::Scalar:
	{
		try
		{
			ret = yaml.as<int>();
		}
		catch (const YAML::BadConversion& ex)
		{
			try
			{
				ret = yaml.as<double>();
			}
			catch (const YAML::BadConversion& ex)
			{
				try
				{
					ret = yaml.as<bool>();
				}
				catch (const YAML::BadConversion& ex)
				{
					ret = yaml.as<string>();
				}
			}
		}
		break;
	}
	case YAML::NodeType::Sequence:
	{
		for(auto it = yaml.begin(); it != yaml.end(); ++it)
		{
			ret.append(yaml_to_json(*it));
		}
		break;
	}
	case YAML::NodeType::Map:
	{
		for(auto it = yaml.begin(); it != yaml.end(); ++it)
		{
			ret[it->first.as<string>()] = yaml_to_json(it->second);
		}
		break;
	}
	default:
		// Other types are null and undefined
		break;
	}
	return ret;
}

bool app_check::match(sinsp_threadinfo *tinfo) const
{
	// At least a pattern should be specified
	bool ret = (!m_comm_pattern.empty() || !m_exe_pattern.empty() || m_port_pattern > 0 || !m_arg_pattern.empty());
	if(!m_comm_pattern.empty())
	{
		ret &= tinfo->m_comm.find(m_comm_pattern) != string::npos;
	}
	if(!m_exe_pattern.empty())
	{
		ret &= tinfo->m_exe.find(m_exe_pattern) != string::npos;
	}
	if(m_port_pattern > 0)
	{
		auto ports = tinfo->m_ainfo->listening_ports();
		ret &= ports.find(m_port_pattern) != ports.end();
	}
	if(!m_arg_pattern.empty())
	{
		ret &= find_if(tinfo->m_args.begin(), tinfo->m_args.end(), [this](const string& arg)
		{
			return arg.find(m_arg_pattern) != string::npos;
		}) != tinfo->m_args.end();
	}
	return ret;
}

Json::Value app_check::to_json() const
{
	Json::Value ret;
	ret["name"] = m_name;
	if(!m_check_module.empty())
	{
		ret["check_module"] = m_check_module;
	}
	ret["conf"] = m_conf;
	if(m_interval > 0)
	{
		ret["interval"] = m_interval;
	}
	ret["log_errors"] = m_log_errors;
	ret["retry"] = m_retry;
	return ret;
}
bool YAML::convert<app_check>::decode(const YAML::Node &node, app_check &rhs)
{
	/*
	 * Example:
	 * name: redisdb
	 *	pattern:
	 *	  comm: redis-server
	 *	conf:
	 *	  host: 127.0.0.1
	 *	  port: {port}
	 *
	 *	The conf part is not used by dragent
	 */
	rhs.m_name = node["name"].as<string>();
	auto check_module_node = node["check_module"];
	if(check_module_node.IsScalar())
	{
		rhs.m_check_module = check_module_node.as<string>();
	}
	auto enabled_node = node["enabled"];
	if(enabled_node.IsScalar())
	{
		rhs.m_enabled = enabled_node.as<bool>();
	}
	auto log_errors_node = node["log_errors"];
	if(log_errors_node.IsScalar())
	{
		rhs.m_log_errors = log_errors_node.as<bool>();
	}
	auto retry_node = node["retry"];
	if(retry_node.IsScalar())
	{
		rhs.m_retry = retry_node.as<bool>();
	}

	auto pattern_node = node["pattern"];
	if(pattern_node.IsMap())
	{
		auto comm_node = pattern_node["comm"];
		if(comm_node.IsScalar())
		{
			rhs.m_comm_pattern = comm_node.as<string>();
		}
		auto exe_node = pattern_node["exe"];
		if(exe_node.IsScalar())
		{
			rhs.m_exe_pattern = exe_node.as<string>();
		}
		auto port_node = pattern_node["port"];
		if(port_node.IsScalar())
		{
			rhs.m_port_pattern = port_node.as<uint16_t>();
		}
		auto arg_node = pattern_node["arg"];
		if(arg_node.IsScalar())
		{
			rhs.m_arg_pattern = arg_node.as<string>();
		}
	}

	auto interval_node = node["interval"];
	if(interval_node.IsScalar())
	{
		rhs.m_interval = interval_node.as<int>();
	}

	auto conf_node = node["conf"];
	if (conf_node.IsMap())
	{
		rhs.m_conf = yaml_to_json(conf_node);
	}
	return true;
}

app_process::app_process(const app_check& check, sinsp_threadinfo *tinfo):
	m_pid(tinfo->m_pid),
	m_vpid(tinfo->m_vpid),
	m_ports(tinfo->m_ainfo->listening_ports()),
	m_check(check),
	m_solr_port(0)
{
	if(is_solr())
	{
		get_port_from_cmd(tinfo);
		if (m_ports.empty())
		{
			string cmdline = tinfo->m_comm;
			int i = 0;
			for (auto arg : tinfo->m_args)
			{
				cmdline = cmdline + " " + arg;
				if (++i >= 10) {
					cmdline = cmdline + " ...";
					break;
				}
			}
			g_logger.format(sinsp_logger::SEV_DEBUG, "No listening ports found for solr process: %d: %s", tinfo->m_pid, cmdline.c_str());
		}
	}
}

bool app_process::is_solr() const
{
	return m_check.module() == "solr";
}

void app_process::get_port_from_cmd(sinsp_threadinfo *tinfo)
{
	static const string& SOLR_PORT_ARG = "-Djetty.port=";
	assert(tinfo != nullptr);
	std::vector<std::string> args = tinfo->m_args;
	m_solr_port = 0;

	for(auto arg : args)
	{
		if(arg.size() > SOLR_PORT_ARG.size())
		{
			if(arg.substr(0, SOLR_PORT_ARG.size()) == SOLR_PORT_ARG)
			{
				try
				{
					m_solr_port = std::stoi(arg.substr(SOLR_PORT_ARG.size()));
				}
				catch(const std::exception& e)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "unable to get solr port from arg %s", arg.c_str());
				}
				break;
			}
		}
	}
}

void app_process::set_conf_vals(shared_ptr<app_process_conf_vals> &conf_vals)
{
	m_conf_vals = conf_vals;
}

Json::Value app_process::to_json() const
{
	Json::Value ret;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["check"] = m_check.to_json();
	if(is_solr() && m_solr_port > 0)
	{
		ret["solr_port"] = m_solr_port;
	}
	ret["ports"] = Json::Value(Json::arrayValue);
	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}
	Json::Value conf_vals;
	if(m_conf_vals)
	{
		conf_vals = m_conf_vals->vals();
	}
	else
	{
		conf_vals = Json::objectValue;
	}

	ret["conf_vals"] = conf_vals;

	return ret;
}

app_checks_proxy::app_checks_proxy():
	m_outqueue("/sdc_app_checks_in", posix_queue::SEND, 1),
	m_inqueue("/sdc_app_checks_out", posix_queue::RECEIVE, 2)
{
}

void app_checks_proxy::send_get_metrics_cmd(const vector<app_process> &processes, const vector<prom_process>& prom_procs, const prometheus_conf &prom_conf)
{
	Json::Value procs = Json::Value(Json::arrayValue);
	for(const auto& p : processes)
	{
		procs.append(p.to_json());
	}
	Json::Value promps = Json::Value(Json::arrayValue);
#ifndef CYGWING_AGENT
	for(const auto& p : prom_procs)
	{
		promps.append(p.to_json(prom_conf));
	}
#endif

	Json::Value command;
	command["processes"] = procs;
	command["prometheus"] = promps;
	string data = m_json_writer.write(command);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Send to sdchecks: %s", data.c_str());
	m_outqueue.send(data);
}

app_checks_proxy::metric_map_t app_checks_proxy::read_metrics(metric_limits::cref_sptr_t ml)
{
	metric_map_t ret;
	std::string msg;
	try
	{
		if(c_sdagent_compression_enabled.get_value())
		{
			// read the header
			uLongf uncompressed_size = 0;
			uLongf num_compressed_segments = 0;
			auto msg_header = m_inqueue.receive();
			if(!msg_header.empty())
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks (compressed header): %lu bytes", msg_header.size());
				// extract metadata from header
				Json::Value msg_header_json;
				if(m_json_reader.parse(msg_header, msg_header_json, false))
				{
					std::string magic;
					if(msg_header_json.isMember("magic") &&
						msg_header_json.isMember("uncompressed_size") &&
						msg_header_json.isMember("num_compressed_segments"))
					{
						magic = msg_header_json["magic"].asString();
						uncompressed_size = msg_header_json["uncompressed_size"].asUInt();
						num_compressed_segments = msg_header_json["num_compressed_segments"].asUInt();
						g_logger.format(sinsp_logger::SEV_DEBUG, "Header magic=%s, uncompressed_size=%lu, num_compressed_segments=%lu",
								magic.c_str(), uncompressed_size, num_compressed_segments);
					}
					else
					{
						g_logger.format(sinsp_logger::SEV_ERROR, "Unable to parse json in header for compressed message");
						return ret;
					}
					// validate metadata
					if(magic != "SDAGENT")
					{
						g_logger.format(sinsp_logger::SEV_ERROR, "Invalid magic in header, expected SDAGENT, found %s", magic.c_str());
						return ret;
					}
					if(num_compressed_segments != 1)
					{
						// We don't support more than 1 compressed segments
						// Add support for multiple segments in the future, if required
						g_logger.format(sinsp_logger::SEV_ERROR, "Invalid num_compressed_segments in header, expected 1, found %lu",
								num_compressed_segments);
						return ret;
					}

				}
			}
			// process the compressed data segment(s)
			// Note: Today, we support only 1 compressed segment
			auto compressed_msg = m_inqueue.receive();
			if(!compressed_msg.empty())
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks (commpressed message): %lu bytes", compressed_msg.size());
				// Allocate memory for the uncompressed data
				// Note: reserve() throws std::length_error exception if storage allocation fails,
				// which should be caught below
				std::vector<Bytef> uncompressed_msg;
				uncompressed_msg.reserve(uncompressed_size);
				// Uncompress the message
				int res = uncompress(&(uncompressed_msg[0]), &uncompressed_size, (const Bytef*)(compressed_msg.c_str()), compressed_msg.size());
				if (res != Z_OK)
				{
					g_logger.format(sinsp_logger::SEV_ERROR, "uncompress error %d", res);
					return ret;
				}
				msg = reinterpret_cast<char*>(&uncompressed_msg[0]);
				msg.erase(uncompressed_size, std::string::npos);
			}
		}
		else
		{
			msg = m_inqueue.receive();
		}

		if(!msg.empty())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %lu bytes", msg.size());
			Json::Value response_obj;
			if(m_json_reader.parse(msg, response_obj, false))
			{
				auto proc_metrics = [](Json::Value obj, app_check_data::check_type t, metric_limits::cref_sptr_t ml, metric_map_t &ret) {
					for(const auto& process : obj)
					{
						app_check_data data(process, ml);
						// only add if there are metrics or services
						if(data.metrics().size() || data.services().size() || data.total_metrics())
						{
							data.set_type(t);
							ret[data.pid()][data.name()] = move(data);
						}
					}
				};
				if (response_obj.isMember("processes"))
				{
					auto resp_obj = response_obj["processes"];
					proc_metrics(resp_obj, app_check_data::check_type::APPCHECK, ml, ret);
				}
				if (response_obj.isMember("prometheus"))
				{
					auto resp_obj = response_obj["prometheus"];
					proc_metrics(resp_obj, app_check_data::check_type::PROMETHEUS, ml, ret);
				}
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "app_checks_proxy::read_metrics: JSON parsing error:");
				g_logger.format(sinsp_logger::SEV_DEBUG, "%s", msg.c_str());
			}
		}
	}
	catch(std::exception& ex)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "app_checks_proxy::read_metrics error: %s", ex.what());
	}
	return ret;
}

app_check_data::app_check_data(const Json::Value &obj, metric_limits::cref_sptr_t ml):
	m_pid(obj["pid"].asInt()),
	m_expiration_ts(obj["expiration_ts"].asUInt64()),
	m_total_metrics(0)
{
	if(obj.isMember("display_name"))
	{
		m_process_name = obj["display_name"].asString();
	}
	if(obj.isMember("metrics"))
	{
		for(auto& m : obj["metrics"])
		{
			if(m.isArray() && m.size() && m[0].isConvertibleTo(Json::stringValue))
			{
				std::string filter;
				if(ml)
				{
					std::string filter;
					if(ml->allow(m[0].asString(), filter, nullptr, "app_check")) // allow() will log if logging is enabled
					{
						m_metrics.emplace_back(m);
					}
				}
				else // no filters, add all metrics and log explicitly
				{
					metric_limits::log(m[0].asString(), "app_check", true, metric_limits::log_enabled(), " ");
					m_metrics.emplace_back(m);
				}
				++m_total_metrics;
			}
		}
	}

	if(obj.isMember("service_checks"))
	{
		const Json::Value& service_checks = obj["service_checks"];

		for(const auto& s : service_checks)
		{
			if(s.isMember("check") && s["check"].isConvertibleTo(Json::stringValue))
			{
				if(ml)
				{
					std::string filter;
					if(ml->allow(s["check"].asString(), filter, nullptr, "app_check")) // allow() will log if logging is enabled
					{
						m_service_checks.emplace_back(s);
					}
				}
				else // no filters, add all metrics and log explicitly
				{
					metric_limits::log(s["check"].asString(), "app_check", true, metric_limits::log_enabled(), " ");
					m_service_checks.emplace_back(s);
				}
				++m_total_metrics;
			}
		}
	}
}

unsigned app_check_data::to_protobuf(draiosproto::app_info *proto, uint16_t& limit, uint16_t max_limit) const
{
	unsigned emitted_metrics = 0;

	bool ml_log = metric_limits::log_enabled();
	if(limit == 0 && !ml_log) { return emitted_metrics; }
	// Right now process name is not used by backend
	//proto->set_process_name(m_process_name);
	for(const auto& m : m_metrics)
	{
		ASSERT(((limit == 0) && ml_log) || (limit != 0));
		if((limit == 0) && ml_log)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "[app_check] metric over limit (total, %u max): %s",
							max_limit, m.name().c_str());
			continue;
		}
		m.to_protobuf(proto->add_metrics());
		emitted_metrics++;
		if((--limit == 0) && !ml_log) { return emitted_metrics; }
	}

	// Right now service checks are not supported by the backend
	// we are sending them as 1/0 metrics
	for(const auto& s : m_service_checks)
	{
		ASSERT(((limit == 0) && ml_log) || (limit != 0));
		if((limit == 0) && ml_log)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "[app_check] metric over limit (total, %u max): %s",
							max_limit, s.name().c_str());
			continue;
		}
		s.to_protobuf_as_metric(proto->add_metrics());
		emitted_metrics++;
		if((--limit == 0) && !ml_log) { return emitted_metrics; }
	}

	return emitted_metrics;
}

const std::unordered_map<string, std::pair<app_metric::type_t, app_metric::prometheus_type_t>> app_metric::metric_type_mapping = {
		{"gauge",   {app_metric::type_t::GAUGE,          app_metric::prometheus_type_t::INVALID}},
		{"rate",    {app_metric::type_t::RATE,           app_metric::prometheus_type_t::INVALID}},
		{"buckets", {app_metric::type_t::BUCKETS,        app_metric::prometheus_type_t::INVALID}},
		{"pr-c",    {app_metric::type_t::PROMETHEUS_RAW, app_metric::prometheus_type_t::COUNTER}},
		{"pr-g",    {app_metric::type_t::PROMETHEUS_RAW, app_metric::prometheus_type_t::GAUGE}},
		{"pr-h",    {app_metric::type_t::PROMETHEUS_RAW, app_metric::prometheus_type_t::HISTOGRAM}},
		{"pr-s",    {app_metric::type_t::PROMETHEUS_RAW, app_metric::prometheus_type_t::SUMMARY}},
		{"pr-u",    {app_metric::type_t::PROMETHEUS_RAW, app_metric::prometheus_type_t::UNKNOWN}},
};

app_metric::app_metric(const Json::Value &obj):
	m_name(obj[0].asString()),
	m_type(type_t::GAUGE)
{
	auto metadata = obj[3];
	if(metadata.isMember("type"))
	{
		auto type = metadata["type"].asString();
		auto iter(metric_type_mapping.find(type));
		if (iter != metric_type_mapping.end()) {
			m_type = iter->second.first;

			if (m_type == type_t::PROMETHEUS_RAW) {
				// obj[2] is either "NaN" or a double
				m_prometheus_type = iter->second.second;
				if (obj[2].isString() && !strcmp("NaN", obj[2].asCString())) {
					m_value = nan("");
				} else {
					m_value = obj[2].asDouble();
				}

			} else if (m_type == type_t::BUCKETS) {
				// obj[2] is a map of <label, count>
				const auto &buckets(obj[2]);
				const auto labels = buckets.getMemberNames();
				for (const auto& l: labels)
				{
					try
					{
						m_buckets.emplace(l, buckets[l].asUInt64());
					}
					catch(const Json::LogicError& ex)
					{
						// This can happen if we try to parse
						// a negative value
						LOG_ERROR("Cannot convert bucket value for "
						          "metric '%s' to UInt64: \"%s\": %s; dropping. "
						          "Error: %s",
						          Json::FastWriter().write(obj).c_str(),
						          l.c_str(),
						          Json::FastWriter().write(buckets[l]).c_str(),
						          ex.what());
					}
				}

			} else {
				// obj[2] is just a double
				m_value = obj[2].asDouble();
			}

		} else {
			g_logger.format(sinsp_logger::SEV_ERROR, "[app_check] unknown metric type: %s",
			                type.c_str());
			m_value = obj[2].asDouble();
		}
	}

	if(metadata.isMember("tags"))
	{
		for(const auto& tag_obj : metadata["tags"])
		{
			auto tag_as_str = tag_obj.asString();
			auto colon = tag_as_str.find(':');
			if(colon != string::npos)
			{
				m_tags[tag_as_str.substr(0, colon)] = tag_as_str.substr(colon+1, tag_as_str.size()-colon);
			}
			else
			{
				m_tags[tag_as_str] = "";
			}
		}
	}
}

void app_metric::to_protobuf(draiosproto::app_metric *proto) const
{
	proto->set_name(m_name);
	proto->set_type(static_cast<draiosproto::app_metric_type>(m_type));
	if (m_type != type_t::BUCKETS) {
		proto->set_value(m_value);
	} else {
		for (auto &b: m_buckets) {
			auto bucket = proto->add_buckets();
			bucket->set_label(b.first);
			bucket->set_count(b.second);
		}
	}
	if (m_type == type_t::PROMETHEUS_RAW) {
		proto->set_prometheus_type(static_cast<draiosproto::prometheus_type>(m_prometheus_type));
	}
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}

/*
 * example:
 * {"status": 0, "tags": ["redis_host:127.0.0.1", "redis_port:6379"],
 *   "timestamp": 1435684284.087451, "check": "redis.can_connect",
 *   "host_name": "vagrant-ubuntu-vivid-64", "message": null, "id": 44}
 */
app_service_check::app_service_check(const Json::Value &obj):
	m_status(static_cast<status_t>(obj["status"].asUInt())),
	m_name(obj["check"].asString())
{
	if(obj.isMember("tags"))
	{
		for(const auto& tag_obj : obj["tags"])
		{
			auto tag_as_str = tag_obj.asString();
			auto colon = tag_as_str.find(':');
			if(colon != string::npos)
			{
				m_tags[tag_as_str.substr(0, colon)] = tag_as_str.substr(colon+1, tag_as_str.size()-colon);
			}
			else
			{
				m_tags[tag_as_str] = "";
			}
		}
	}
	if(obj.isMember("message") && obj["message"].isString())
	{
		m_message = obj["message"].asString();
	}
}

void app_service_check::to_protobuf(draiosproto::app_check *proto) const
{
	proto->set_name(m_name);
	proto->set_value(static_cast<draiosproto::app_check_value>(m_status));
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}

void app_service_check::to_protobuf_as_metric(draiosproto::app_metric *proto) const
{
	proto->set_name(m_name);
	if(m_status == status_t::OK)
	{
		proto->set_value(1.0);
	}
	else
	{
		proto->set_value(0.0);
	}
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}

