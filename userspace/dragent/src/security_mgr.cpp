#ifndef CYGWING_AGENT
#include <google/protobuf/text_format.h>

#include "sinsp_worker.h"
#include "infrastructure_state.h"
#include "common_logger.h"

#include "security_config.h"
#include "security_mgr.h"

// we get nlohmann jsons from falco k8s audit, while dragent dragent
// generally uses the `jsoncpp' library
#include <nlohmann/json.hpp>

using namespace std;
using nlohmann::json;
namespace security_config = libsanalyzer::security_config;

type_config<bool> security_mgr::c_event_labels_enabled(
        true,
        "Policy Events Labels enabled",
        "event_labels", "enabled");

type_config<int> security_mgr::c_event_labels_max_agent_tags(
		30,
		"Event Labels - Max agent tags to be considered",
		"event_labels", "max_agent_tags"
		);

type_config<std::vector<std::string>> security_mgr::c_event_labels_include(
		{},
		"Event Labels included",
		"event_labels", "include"
		);

type_config<std::vector<std::string>> security_mgr::c_event_labels_exclude(
		{},
		"Event Labels excluded",
		"event_labels", "exclude"
);

// XXX/mstemm TODO
// - Is there a good way to immediately check the status of a sysdig capture that I can put in the action result?
// - The currently event handling doesn't actually work with on
// - default, where no policy matches. I think I need to have special
// - case for when the hash table doesn't match anything.

// Refactor TODO
// - Double check for proper use of std:: namespace
// - Double check for proper includes in all files
// - Add unit tests
// - Make sure all objects will gracefully fail if init() is not called

security_mgr::security_mgr(const string& install_root)
	: m_k8s_audit_server_started(false),
	  m_k8s_audit_server_loaded(false),
	  m_k8s_audit_server_load_in_progress(false),
	  m_initialized(false),
	  m_inspector(NULL),
	  m_sinsp_handler(NULL),
	  m_analyzer(NULL),
	  m_capture_job_handler(NULL),
	  m_configuration(NULL),
	  m_cointerface_sock_path("unix:" + install_root + "/run/cointerface.sock")
{
	m_security_evt_metrics = {make_shared<security_evt_metrics>(m_process_metrics), make_shared<security_evt_metrics>(m_container_metrics),
				  make_shared<security_evt_metrics>(m_readonly_fs_metrics),
				  make_shared<security_evt_metrics>(m_readwrite_fs_metrics),
				  make_shared<security_evt_metrics>(m_nofd_readwrite_fs_metrics),
				  make_shared<security_evt_metrics>(m_net_inbound_metrics), make_shared<security_evt_metrics>(m_net_outbound_metrics),
				  make_shared<security_evt_metrics>(m_tcp_listenport_metrics), make_shared<security_evt_metrics>(m_udp_listenport_metrics),
				  make_shared<security_evt_metrics>(m_syscall_metrics), make_shared<security_evt_metrics>(m_falco_metrics)};
	scope_info sinfo;
	security_policies_group dummy(sinfo, m_inspector, m_configuration);
	dummy.init_metrics(m_security_evt_metrics);
	configure_event_labels_set();
}

security_mgr::~security_mgr()
{
	if (security_config::get_k8s_audit_server_enabled())
	{
	    stop_k8s_audit_tasks();
	}
}

void security_mgr::init(sinsp *inspector,
			sinsp_data_handler *sinsp_handler,
			sinsp_analyzer *analyzer,
			capture_job_handler *capture_job_handler,
			dragent_configuration *configuration,
			const internal_metrics::sptr_t& metrics)

{
	m_inspector = inspector;
	m_sinsp_handler = sinsp_handler;
	m_analyzer = analyzer;
	m_capture_job_handler = capture_job_handler;
	m_configuration = configuration;

	m_fastengine_rules_library = make_shared<security_rule_library>();

	m_inspector->m_container_manager.subscribe_on_new_container([this](const sinsp_container_info &container_info, sinsp_threadinfo *tinfo) {
		on_new_container(container_info, tinfo);
	});
	m_inspector->m_container_manager.subscribe_on_remove_container([this](const sinsp_container_info &container_info) {
		on_remove_container(container_info);
	});

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evtsources.assign(ESRC_MAX+1, false);

	m_report_events_interval = make_unique<run_on_interval>(security_config::get_report_interval_ns());
	m_report_throttled_events_interval = make_unique<run_on_interval>(security_config::get_throttled_report_interval_ns());

	m_actions_poll_interval = make_unique<run_on_interval>(security_config::get_actions_poll_interval_ns());

	// Only check the above every second
	m_check_periodic_tasks_interval = make_unique<run_on_interval>(1000000000);

	m_coclient = make_shared<coclient>(configuration->c_root_dir.get());

	m_actions.init(this, m_coclient);

	for(auto &metric : m_security_evt_metrics)
	{
		metric->reset();
		metrics->add_ext_source(metric.get());
	}
	m_metrics.reset();
	metrics->add_ext_source(&m_metrics);

	m_initialized = true;
}

bool security_mgr::load_policies_file(const char *filename, std::string &errstr)
{
	draiosproto::policies policies;

	int fd = open(filename, O_RDONLY);
	google::protobuf::io::FileInputStream fstream(fd);
	if (!google::protobuf::TextFormat::Parse(&fstream, &policies)) {
		errstr = string("Failed to parse policies file ")
			+ filename;
		close(fd);
		return false;
	}
	close(fd);

	return load_policies(policies, errstr);
}

bool security_mgr::load_policies_v2_file(const char *filename, std::string &errstr)
{
	draiosproto::policies_v2 policies_v2;

	int fd = open(filename, O_RDONLY);
	google::protobuf::io::FileInputStream fstream(fd);
	if (!google::protobuf::TextFormat::Parse(&fstream, &policies_v2)) {
		errstr = string("Failed to parse policies file ")
			+ filename;
		close(fd);
		return false;
	}
	close(fd);

	return load_policies_v2(policies_v2, errstr);
}


bool security_mgr::load_baselines_file(const char *filename, std::string &errstr)
{
	draiosproto::baselines baselines;

	int fd = open(filename, O_RDONLY);
	google::protobuf::io::FileInputStream fstream(fd);
	if (!google::protobuf::TextFormat::Parse(&fstream, &baselines)) {
		errstr = string("Failed to parse baselines file ")
			+ filename;
		close(fd);
		return false;
	}
	close(fd);

	return load_baselines(baselines, errstr);
}

void security_mgr::load_policy(const security_policy &spolicy, std::list<std::string> &ids)
{
	scope_info sinfo = { spolicy.scope_predicates(), spolicy.container_scope(), spolicy.host_scope() };
	std::shared_ptr<security_policies_group> grp;

	for (const auto &id : ids)
	{
		if(spolicy.match_scope(id, m_analyzer))
		{
			std::shared_ptr<security_baseline> baseline = {};
			if(!id.empty() && spolicy.has_baseline_details())
			{
				// smart policy
				baseline = m_baseline_mgr.lookup(id, m_analyzer->infra_state(), spolicy);
				if(!baseline)
				{
					// no baseline found for this container, skipping
					continue;
				}

				sinfo.preds.MergeFrom(baseline->predicates());
			}
			else
			{
				// manual policy, sinfo is already correct
			}

			// get/create the policies group and add the policy
			grp = get_policies_group_of(sinfo);
			grp->add_policy(spolicy, baseline);
			m_scoped_security_policies[id].emplace(grp);
		}
	}
}

void security_mgr::load_policy_v2(std::shared_ptr<security_policy_v2> spolicy_v2, std::list<std::string> &ids)
{
	g_log->debug("Loading v2 policy " + spolicy_v2->DebugString() +
		     ", testing against set of " + to_string(ids.size()) +
		     " container ids");

	for (const auto &id : ids)
	{
		if(spolicy_v2->match_scope(id, m_analyzer))
		{
			g_log->debug("Policy " + spolicy_v2->name() + " matched scope for container " + id);

			// get/create the policies group and add the policy
			std::shared_ptr<security_rules_group> grp;

			grp = get_rules_group_of(spolicy_v2->scope_predicates());
			grp->add_policy(spolicy_v2);
			m_scoped_security_rules[id].emplace(grp);
		}
		else
		{
			g_log->debug("Policy " + spolicy_v2->name() + " did not match scope for container " + id);
		}
	}
}

bool security_mgr::load_falco_rules_files(const draiosproto::falco_rules_files &files, std::string &errstr)
{
	bool verbose = false;
	bool all_events = false;

	for(auto &file : files.files())
	{
		// Find the variant that has the highest required
		// engine version that is compatible with our engine
		// version.
		int best_variant = -1;
		uint32_t best_engine_version = 0;

		for(int i=0; i < file.variants_size(); i++)
		{
			auto &variant = file.variants(i);

			if(variant.required_engine_version() <= m_falco_engine->engine_version() &&
			   ((variant.required_engine_version() > best_engine_version) ||
			    (best_variant == -1)))
			{
				best_variant = i;
				best_engine_version=variant.required_engine_version();
			}
		}

		if(best_variant == -1)
		{
			g_log->information("Could not find any compatible variant for falco rules file " + file.filename() + ", skipping");
		}
		else
		{
			try {
				g_log->information("Loading falco rules content tag=" + files.tag() +
					     " filename=" + file.filename() +
					     " required_engine_version=" + to_string(best_engine_version));
				m_falco_engine->load_rules(file.variants(best_variant).content(),
							   verbose, all_events);
			}
			catch (falco_exception &e)
			{
				errstr = e.what();
				return false;
			}
		}
	}

	return true;
}

bool security_mgr::load(std::string &errstr)
{
	// Always use v2 policies if available
	if(m_policies_v2_msg)
	{
		return load_v2(*(m_policies_v2_msg.get()), errstr);
	}
	else if (m_policies_msg && m_baselines_msg)
	{
		return load_v1(*(m_policies_msg.get()), *(m_baselines_msg.get()), errstr);
	}

	// We didn't actually load any policies yet but it's not an error.
	return true;
}

bool security_mgr::load_v1(const draiosproto::policies &policies, const draiosproto::baselines &baselines, std::string &errstr)
{
	Poco::ScopedWriteRWLock lck(m_policies_lock);

	google::protobuf::TextFormat::Printer print;
	string tmp;

	print.SetSingleLineMode(true);
	print.PrintToString(baselines, &tmp);

	g_log->debug("Loading baselines message: " + tmp);

	if(m_analyzer)
	{
		m_analyzer->infra_state()->clear_scope_cache();
	}

	m_baseline_mgr.load(baselines, errstr);

	print.PrintToString(policies, &tmp);

	g_log->debug("Loading policies message: " + tmp);

	for(auto &policy : policies.policy_list())
	{
		// There must be falco rules content if there are any falco policies
		if(policy.has_falco_details() && policy.enabled())
		{
			if(!policies.has_falco_rules() && !policies.has_falco_group())
			{
				errstr = "One or more falco policies, but no falco ruleset";
				return false;
			}
			else
			{
				break;
			}
		}
	}

	m_falco_engine = make_shared<falco_engine>(true, m_configuration->c_root_dir.get() + "/share/lua/");
	m_falco_engine->set_inspector(m_inspector);
	m_falco_engine->set_sampling_multiplier(m_configuration->m_falco_engine_sampling_multiplier);

	// Load all falco rules files into the engine. We'll selectively
	// enable them based on the contents of the policies.

	if(policies.has_falco_rules())
	{
		bool verbose = false;
		bool all_events = false;

		// Only load the first entry (system rules aka
		// sysdig-provided one) in content if there is no
		// falco_group.default_files.
		if(!(policies.has_falco_group() && policies.falco_group().has_default_files()) &&
		   policies.falco_rules().contents_size() > 0)
		{
			const std::string &system_rules = policies.falco_rules().contents(0);
			try {
				g_log->debug("Loading System Falco Rules Content: " + system_rules);
				m_falco_engine->load_rules(system_rules, verbose, all_events);
			}
			catch (falco_exception &e)
			{
				errstr = e.what();
				return false;
			}
		}

		// Only load the second entry (user rules aka
		// customer-provided one) in content if there is no
		// falco_group.custom_files.
		if(!(policies.has_falco_group() && policies.falco_group().has_custom_files()) &&
		   policies.falco_rules().contents_size() > 1)
		{
			const std::string &user_rules = policies.falco_rules().contents(1);
			try {
				g_log->debug("Loading User Falco Rules Content: " + user_rules);
				m_falco_engine->load_rules(user_rules, verbose, all_events);
			}
			catch (falco_exception &e)
			{
				errstr = e.what();
				return false;
			}
		}
	}

	if(policies.has_falco_group())
	{
		if(policies.falco_group().has_default_files())
		{
			if(!load_falco_rules_files(policies.falco_group().default_files(), errstr))
			{
				return false;
			}
		}

		if(policies.falco_group().has_custom_files())
		{
			if (!load_falco_rules_files(policies.falco_group().custom_files(), errstr))
			{
				return false;
			}
		}
	}

	m_policies.clear();
	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evtsources.assign(ESRC_MAX+1, false);
	if(m_analyzer)
	{
		m_analyzer->infra_state()->clear_scope_cache();
	}

	m_scoped_security_policies.clear();
	m_policies_groups.clear();

	std::list<std::string> ids{
		"" // tinfo.m_container_id is empty for host events
	};
	const auto &containers = *m_inspector->m_container_manager.get_containers();
	for (const auto &c : containers)
	{
		ids.push_back(c.first);
	}
	uint64_t num_enabled = 0;
	for(auto &policy : policies.policy_list())
	{
		if(policy.enabled())
		{
			num_enabled++;
		}
		else
		{
			continue;
		}
		std::shared_ptr<security_policy> spolicy = std::make_shared<security_policy>(policy);
		m_policies.insert(make_pair(policy.id(), spolicy));

		load_policy(*spolicy.get(), ids);
	}

	m_metrics.set_policies_count(policies.policy_list().size(), num_enabled);

	for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
	{
		for(const auto &group: m_policies_groups)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | group->m_evttypes[evttype];
		}
	}

	for(uint32_t evtsource = 0; evtsource < ESRC_MAX; evtsource++)
	{
		for(const auto &group: m_policies_groups)
		{
			m_evtsources[evtsource] = m_evtsources[evtsource] | group->m_evtsources[evtsource];
		}
	}

	if(!m_policies_groups.empty())
	{
		g_log->information(to_string(m_policies_groups.size()) + " policies groups loaded");
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			for (const auto &group : m_policies_groups)
			{
				g_log->debug(group->to_string());
			}
			g_log->debug("splitted between " + to_string(m_scoped_security_policies.size()) + " entities as follows:");
			for (const auto &it : m_scoped_security_policies)
			{
				string str = "  " + (it.first.empty() ? "host" : it.first) + ": { ";
				for(const auto &group: it.second)
				{
					str += group->to_string() + ", ";
				}
				str = str.substr(0, str.size() - 2) + " }";
				g_log->debug(str);
			}
		}
	}

	return true;
}

bool security_mgr::load_v2(const draiosproto::policies_v2 &policies_v2, std::string &errstr)
{
	Poco::ScopedWriteRWLock lck(m_policies_lock);

	if(m_analyzer)
	{
		m_analyzer->infra_state()->clear_scope_cache();
	}

	g_log->debug("Loading policies_v2 message: " + policies_v2.DebugString());

	m_fastengine_rules_library->reset();

	m_falco_engine = make_shared<falco_engine>(true, m_configuration->c_root_dir.get() + "/share/lua/");
	m_falco_engine->set_inspector(m_inspector);
	m_falco_engine->set_sampling_multiplier(m_configuration->m_falco_engine_sampling_multiplier);

	// Load all falco rules files into the engine. We'll selectively
	// enable them based on the contents of the policies.

	if(policies_v2.has_falco_group())
	{
		if(policies_v2.falco_group().has_default_files())
		{
			if(!load_falco_rules_files(policies_v2.falco_group().default_files(), errstr))
			{
				return false;
			}
		}

		if(policies_v2.falco_group().has_custom_files())
		{
			if (!load_falco_rules_files(policies_v2.falco_group().custom_files(), errstr))
			{
				return false;
			}
		}
	}

	if(policies_v2.has_fastengine_files())
	{
		for(auto &rules_file : policies_v2.fastengine_files().files())
		{
			if(rules_file.has_json_content())
			{
				m_fastengine_rules_library->parse(rules_file.json_content());
			}
		}
	}

	m_policies_v2.clear();
	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_evtsources.assign(ESRC_MAX+1, false);
	if(m_analyzer)
	{
		m_analyzer->infra_state()->clear_scope_cache();
	}

	m_scoped_security_rules.clear();
	m_rules_groups.clear();

	std::list<std::string> ids{
		"" // tinfo.m_container_id is empty for host events
	};
	const auto &containers = *m_inspector->m_container_manager.get_containers();
	for (const auto &c : containers)
	{
		ids.push_back(c.first);
	}
	uint64_t num_enabled = 0;
	for(auto &policy : policies_v2.policy_list())
	{
		if(policy.enabled())
		{
			num_enabled++;
		}
		else
		{
			continue;
		}
		std::shared_ptr<security_policy_v2> spolicy = std::make_shared<security_policy_v2>(policy);
		m_policies_v2.insert(make_pair(policy.id(), spolicy));

		load_policy_v2(spolicy, ids);
	}

	m_metrics.set_policies_count(policies_v2.policy_list().size(), num_enabled);

	for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
	{
		for(const auto &group: m_rules_groups)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | group->m_evttypes[evttype];
		}
	}

	for(uint32_t evtsource = 0; evtsource < ESRC_MAX; evtsource++)
	{
		for(const auto &group: m_rules_groups)
		{
			m_evtsources[evtsource] = m_evtsources[evtsource] | group->m_evtsources[evtsource];
		}
	}

	log_rules_group_info();

	return true;
}

void security_mgr::log_rules_group_info()
{
	if(!m_rules_groups.empty())
	{
		g_log->information(to_string(m_rules_groups.size()) + " rules groups loaded");
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			for (const auto &group : m_rules_groups)
			{
				g_log->debug(group->to_string());
			}
			g_log->debug("splitted between " + to_string(m_scoped_security_rules.size()) + " entities as follows:");
			for (const auto &it : m_scoped_security_rules)
			{
				string str = "  " + (it.first.empty() ? "host" : it.first) + ": { ";
				for(const auto &group: it.second)
				{
					str += group->to_string() + ", ";
				}
				str = str.substr(0, str.size() - 2) + " }";
				g_log->debug(str);
			}
		}
	}
}

bool security_mgr::load_baselines(const draiosproto::baselines &baselines, std::string &errstr)
{
 	m_baselines_msg.reset(new draiosproto::baselines(baselines));

	return load(errstr);
}

bool security_mgr::load_policies(const draiosproto::policies &policies, std::string &errstr)
{
	m_policies_msg.reset(new draiosproto::policies(policies));

	return load(errstr);
}

bool security_mgr::load_policies_v2(const draiosproto::policies_v2 &policies_v2, std::string &errstr)
{
	m_policies_v2_msg.reset(new draiosproto::policies_v2(policies_v2));

	return load(errstr);
}

bool security_mgr::reload_policies(std::string &errstr)
{
	return load(errstr);
}

bool security_mgr::event_qualifies(sinsp_evt *evt)
{
	// if this event is from a docker container and the process name starts with
	// runc, filter it out since behaviors from those processes cannot really
	// be considered neither host nor container events.

	// The checks are intentionally ordered from the fastest to the slowest,
	// so we first check if the process is runc and if we have a container event,
	// and only if that's true we check if it's a docker container event.

	// CONTAINER_JSON events are always ok as the rules that use
	// container events focus on container properties.
	if(evt->get_type() == PPME_CONTAINER_JSON_E)
	{
		return true;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return true;
	}

	if(tinfo->m_container_id.empty() || strncmp(tinfo->get_comm().c_str(), "runc:[", 6) != 0)
	{
		return true;
	}

	const auto container_info = m_inspector->m_container_manager.get_container(tinfo->m_container_id);
	if(!container_info)
	{
		return true;
	}

	if(is_docker_compatible(container_info->m_type))
	{
		return false;
	}

	// ...

	return true;
}

bool security_mgr::event_qualifies(json_event *evt)
{

	return true;
}

void security_mgr::perform_periodic_tasks(uint64_t ts_ns)
{
	m_check_periodic_tasks_interval->run([this, ts_ns]()
        {
		// Possibly report the current set of events.
		m_report_events_interval->run([this, ts_ns]()
                {
			report_events(ts_ns);
		}, ts_ns);

		// Possibly report counts of the number of throttled policy events.
		m_report_throttled_events_interval->run([this, ts_ns]()
		{
			report_throttled_events(ts_ns);
		}, ts_ns);

		// Drive the coclient loop to pick up any async grpc responses
		m_actions_poll_interval->run([this, ts_ns]()
                {
			m_coclient->process_queue();
			m_actions.periodic_cleanup(ts_ns);
		}, ts_ns);

		if (security_config::get_k8s_audit_server_enabled())
		{
			if(m_k8s_audit_server_load)
			{
				m_k8s_audit_server_load->process_queue();
			}

			if(m_k8s_audit_server_start)
			{
				m_k8s_audit_server_start->process_queue();
			}

			if(!m_k8s_audit_server_loaded && !m_k8s_audit_server_load_in_progress)
			{
				load_k8s_audit_server();
			}
		}
	}, ts_ns);
}

bool security_mgr::should_evaluate_event(gen_event *evt,
					 std::string *container_id,
					 sinsp_evt **sevt,
					 sinsp_threadinfo **tinfo)
{
	bool evaluate_event = false;

	switch (evt->get_source())
	{
	case ESRC_SINSP:
		// Consider putting this in check_periodic_tasks above.
		m_actions.check_outstanding_actions(evt->get_ts());

		try
		{
			*sevt = dynamic_cast<sinsp_evt *>(evt);
		}
		catch (std::bad_cast& bc)
		{
			g_log->error("Bad cast for SINSP event");
			break;
		}

		*tinfo = (*sevt)->get_thread_info();

		if(!m_evttypes[(*sevt)->get_type()])
		{
			m_metrics.incr(metrics::MET_MISS_EVTTYPE);
		}
		else if(!event_qualifies(*sevt))
		{
			m_metrics.incr(metrics::MET_MISS_QUAL);
		}
		else if(!*tinfo)
		{
			m_metrics.incr(metrics::MET_MISS_TINFO);
		}
		else
		{
			*container_id = (*tinfo)->m_container_id;
			evaluate_event = true;

		}
		break;
	case ESRC_K8S_AUDIT:
		evaluate_event = true;
		break;
	default:
		g_log->error("Invalid event source" + std::to_string(evt->get_source()));
		break;
	}

	return evaluate_event;

}

void security_mgr::process_event(gen_event *evt)
{
	// Always use v2 policies if available
	if(m_policies_v2_msg)
	{
		return process_event_v2(evt);
	}
	else
	{
		return process_event_v1(evt);
	}
}

void security_mgr::process_event_v1(gen_event *evt)
{
	// Write lock acquired in load_*()
	if(!m_initialized || !m_policies_lock.tryReadLock())
	{
		return;
	}

	perform_periodic_tasks(evt->get_ts());

	std::string container_id = "";
	sinsp_evt *sevt = NULL;
	sinsp_threadinfo *tinfo = NULL;

	if (should_evaluate_event(evt, &container_id, &sevt, &tinfo))
	{
		std::vector<security_policies::match_result *> best_matches;
		security_policies::match_result *match;

		for (const auto &group : m_scoped_security_policies[container_id])
		{
			// An event matches a policy upon three
			// matching of three conditions:
			// 1. event source overlap
			// 2. event type overlap
			// 3. at least one policy in the group match
			//    the event and return a non-null match
			if(group->m_evtsources[evt->get_source()] &&
			   group->m_evttypes[evt->get_type()] &&
			   (match = group->match_event(evt)) != NULL)
			{
				if(match->effect() != draiosproto::EFFECT_ACCEPT)
				{
					g_log->debug("Event matched policy #" + to_string(match->policy()->id()) + " \"" + match->policy()->name() + "\"" +
						     " details:\n" + match->detail()->DebugString() +
						     "effect: " + draiosproto::match_effect_Name(match->effect()));
				}

				best_matches.push_back(match);
			}
		}

		// Sort the matches by policy order.
		std::sort(best_matches.begin(), best_matches.end(), security_policies::match_result::compare_ptr);

		for(auto &match : best_matches)
		{
			if(match->effect() == draiosproto::EFFECT_ACCEPT)
			{
				g_log->trace("Taking ACCEPT action via policy: " + match->policy()->name());
				break;
			}
			else if (match->effect() == draiosproto::EFFECT_DENY)
			{
				g_log->debug("Taking DENY action via policy: " + match->policy()->name());

				if(throttle_policy_event(evt->get_ts(), container_id, match->policy()->id(), match->policy()->name()))
				{
					uint64_t policy_version = 1;

					add_policy_event_metrics(*match);

					draiosproto::policy_event *event = create_policy_event(evt->get_ts(),
											       container_id,
											       tinfo,
											       match->policy()->id(),
											       match->take_detail(),
											       policy_version);

					// Not throttled--perform the actions associated
					// with the policy. The actions will add their action
					// results to the policy event as they complete.
					m_actions.perform_actions(evt->get_ts(),
								  tinfo,
								  match->policy()->name(),
								  match->policy()->actions(),
								  event);
				}

				break;
			}
		}

		for(auto &match : best_matches)
		{
			delete(match);
		}
	}

	m_policies_lock.unlock();
}

void security_mgr::process_event_v2(gen_event *evt)
{
	// Write lock acquired in load_*()
	if(!m_initialized || !m_policies_lock.tryReadLock())
	{
		return;
	}

	perform_periodic_tasks(evt->get_ts());

	std::string container_id = "";
	sinsp_evt *sevt = NULL;
	sinsp_threadinfo *tinfo = NULL;

	if (should_evaluate_event(evt, &container_id, &sevt, &tinfo))
	{
		std::list<security_rules::match_result> results;

		for (const auto &group : m_scoped_security_rules[container_id])
		{
			// An event matches a policy upon three
			// matching of three conditions:
			// 1. event source overlap
			// 2. event type overlap
			// 3. at least one policy in the group match
			//    the event and return a non-null match

			if(group->m_evtsources[evt->get_source()] &&
			   group->m_evttypes[evt->get_type()])
			{
				std::list<security_rules::match_result> gresults;

				gresults = group->match_event(evt);

				results.splice(results.end(), gresults);
			}
		}

		// Take all actions for all results
		for(auto &result : results)
		{
			g_log->debug("Taking action via policy: " + result.m_policy->name() + ". detail=" + result.m_detail.DebugString());

			if(throttle_policy_event(evt->get_ts(), container_id, result.m_policy->id(), result.m_policy->name()))
			{
				uint64_t policy_version = 2;

				add_policy_event_metrics(result);

				draiosproto::policy_event *event = create_policy_event(evt->get_ts(),
										       container_id,
										       tinfo,
										       result.m_policy->id(),
										       result.m_detail,
										       policy_version);

				// Not throttled--perform the actions associated
				// with the policy. The actions will add their action
				// results to the policy event as they complete.
				m_actions.perform_actions(evt->get_ts(),
							  tinfo,
							  result.m_policy->name(),
							  result.m_policy->actions(),
							  event);
			}
		}
	}

	m_policies_lock.unlock();
}

bool security_mgr::start_capture(uint64_t ts_ns,
				 const string &policy,
				 const string &token, const string &filter,
				 uint64_t before_event_ns, uint64_t after_event_ns,
				 bool apply_scope, std::string &container_id,
				 uint64_t pid,
				 std::string &errstr)
{
	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_handler::start_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
	job_request->m_token = token;

	job_request->m_start_details->m_filter = filter;

	if(apply_scope && container_id != "")
	{
		// Limit the capture to the container where the event occurred.
		if(!job_request->m_start_details->m_filter.empty())
		{
			job_request->m_start_details->m_filter += " and ";
		}

		job_request->m_start_details->m_filter += "container.id=" + container_id;
	}

	job_request->m_start_details->m_duration_ns = after_event_ns;
	job_request->m_start_details->m_past_duration_ns = before_event_ns;
	job_request->m_start_details->m_start_ns = ts_ns;
	job_request->m_start_details->m_notification_desc = policy;
	job_request->m_start_details->m_notification_pid = pid;
	job_request->m_start_details->m_defer_send = true;

	// Note: Not enforcing any maximum size.
	return m_capture_job_handler->queue_job_request(m_inspector, job_request, errstr);
}

void security_mgr::start_sending_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_SEND_START;
	job_request->m_token = token;

	if (!m_capture_job_handler->queue_job_request(m_inspector, job_request, errstr))
	{
		g_log->error("security_mgr::start_sending_capture could not start sending capture token=" + token + "(" + errstr + "). Trying to stop capture.");
		stop_capture(token);
	}
}

void security_mgr::stop_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_handler::dump_job_request> stop_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	stop_request->m_stop_details = make_unique<capture_job_handler::stop_job_details>();

	stop_request->m_request_type = capture_job_handler::dump_job_request::JOB_STOP;
	stop_request->m_token = token;

	// Any call to security_mgr::stop_capture is for an aborted
	// capture, in which case the capture should not be sent at all.
	stop_request->m_stop_details->m_remove_unsent_job = true;

	if (!m_capture_job_handler->queue_job_request(m_inspector, stop_request, errstr))
	{
		g_log->critical("security_mgr::start_sending_capture could not stop capture token=" + token + "(" + errstr + ")");

		// This will result in a capture that runs to
		// completion but is never sent, and a file on
		// disk that is never cleaned up.
	}
}

sinsp_analyzer *security_mgr::analyzer()
{
	return m_analyzer;
}

baseline_mgr &security_mgr::baseline_manager()
{
	return m_baseline_mgr;
}

void security_mgr::send_policy_event(uint64_t ts_ns, shared_ptr<draiosproto::policy_event> &event, bool send_now)
{
	// Not throttled, queue the policy event or send
	// immediately.
	if(send_now)
	{
		draiosproto::policy_events events;
		events.set_machine_id(m_configuration->machine_id());
		events.set_customer_id(m_configuration->m_customer_id);
		draiosproto::policy_event *new_event = events.add_events();
		new_event->MergeFrom(*event);
		report_events_now(ts_ns, events);
	}
	else
	{
		draiosproto::policy_event *new_event = m_events.add_events();
		new_event->MergeFrom(*event);
	}
}

bool security_mgr::throttle_policy_event(uint64_t ts_ns,
					 std::string &container_id,
					 uint64_t policy_id,
					 const std::string &policy_name)
{
	bool accepted = true;

	// Find the matching token bucket, creating it if necessary
	rate_limit_scope_t scope(container_id, policy_id);

	auto it = m_policy_rates.lower_bound(rate_limit_scope_t(scope));

	if (it == m_policy_rates.end() ||
	    it->first != scope)
	{
		it = m_policy_rates.emplace_hint(it, make_pair(scope, token_bucket()));
		it->second.init(security_config::get_policy_events_rate(),
		                security_config::get_policy_events_max_burst(),
		                ts_ns);

		g_log->debug("security_mgr::accept_policy_event creating new token bucket for policy=" + policy_name
			     + ", container=" + container_id);
	}

	if(it->second.claim(1, ts_ns))
	{
		g_log->debug("security_mgr::accept_policy_event allowing policy=" + policy_name
			     + ", container=" + container_id
			     + ", tokens=" + NumberFormatter::format(it->second.get_tokens()));
	}
	else
	{
		accepted = false;

		// Throttled. Increment the throttled count.

		auto it2 = m_policy_throttled_counts.lower_bound(rate_limit_scope_t(scope));

		if (it2 == m_policy_throttled_counts.end() ||
		    it2->first != scope)
		{
			it2 = m_policy_throttled_counts.emplace_hint(it2, make_pair(scope, 0));
		}

		it2->second = it2->second + 1;

		g_log->debug("security_mgr::accept_policy_event throttling policy=" + policy_name
			     + ", container=" + container_id
			     + ", tcount=" + NumberFormatter::format(it2->second));
	}

	return accepted;
}

void security_mgr::add_policy_event_metrics(const security_policies::match_result &res)
{
	m_metrics.incr(metrics::MET_POLICY_EVTS);
	switch(res.policies_type())
	{
	case draiosproto::PTYPE_PROCESS:
		m_metrics.incr(metrics::MET_POLICY_EVTS_PROCESS);
		break;
	case draiosproto::PTYPE_CONTAINER:
		m_metrics.incr(metrics::MET_POLICY_EVTS_CONTAINER);
		break;
	case draiosproto::PTYPE_FILESYSTEM:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FILESYSTEM);
		break;
	case draiosproto::PTYPE_NETWORK:
		m_metrics.incr(metrics::MET_POLICY_EVTS_NETWORK);
		break;
	case draiosproto::PTYPE_SYSCALL:
		m_metrics.incr(metrics::MET_POLICY_EVTS_SYSCALL);
		break;
	case draiosproto::PTYPE_FALCO:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FALCO);
		break;
	default:
		g_log->error("Unknown policy type " + to_string(res.policies_type()));
		break;
	}

	// If the policy has a severity field, map the severity as
	// number to one of the values low, medium, high and increment
	if(res.policy()->has_severity())
	{
		if(res.policy()->severity() <= 3)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_HIGH);
		}
		else if (res.policy()->severity() <= 5)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_MEDIUM);
		}
		else
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_LOW);
		}
	}

	m_metrics.incr_policy(res.policy()->name());
}

void security_mgr::add_policy_event_metrics(const security_rules::match_result &res)
{
	m_metrics.incr(metrics::MET_POLICY_EVTS);
	switch(res.m_rule_type)
	{
	case draiosproto::PTYPE_PROCESS:
		m_metrics.incr(metrics::MET_POLICY_EVTS_PROCESS);
		break;
	case draiosproto::PTYPE_CONTAINER:
		m_metrics.incr(metrics::MET_POLICY_EVTS_CONTAINER);
		break;
	case draiosproto::PTYPE_FILESYSTEM:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FILESYSTEM);
		break;
	case draiosproto::PTYPE_NETWORK:
		m_metrics.incr(metrics::MET_POLICY_EVTS_NETWORK);
		break;
	case draiosproto::PTYPE_SYSCALL:
		m_metrics.incr(metrics::MET_POLICY_EVTS_SYSCALL);
		break;
	case draiosproto::PTYPE_FALCO:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FALCO);
		break;
	default:
		g_log->error("Unknown policy type " + to_string(res.m_rule_type));
		break;
	}

	// If the policy has a severity field, map the severity as
	// number to one of the values low, medium, high and increment
	if(res.m_policy->has_severity())
	{
		if(res.m_policy->severity() <= 3)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_HIGH);
		}
		else if (res.m_policy->severity() <= 5)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_MEDIUM);
		}
		else
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_LOW);
		}
	}

	m_metrics.incr_policy(res.m_policy->name());
}

draiosproto::policy_event * security_mgr::create_policy_event(int64_t ts_ns,
							      std::string &container_id,
							      sinsp_threadinfo *tinfo,
							      uint64_t policy_id,
							      draiosproto::event_detail *details,
							      uint64_t policy_version)
{
	draiosproto::policy_event *event = new draiosproto::policy_event();

	event->set_timestamp_ns(ts_ns);
	event->set_policy_id(policy_id);
	event->set_policy_version(policy_version);
	if(!container_id.empty())
	{
		event->set_container_id(container_id);
	}

	event->set_allocated_event_details(details);

	// If the policy event comes from falco, copy the information
	// to the falco_details section of the policy event. This is
	// for backwards compatibility with older backend versions.
	if(details->has_output_details() && details->output_details().output_type() == draiosproto::PTYPE_FALCO)
	{
		draiosproto::falco_event_detail *fdet = event->mutable_falco_details();
		fdet->set_rule(details->output_details().output_fields().at("falco.rule"));
		fdet->set_output(details->output_details().output());
	}

	if(m_analyzer)
	{
		event->set_sinsp_events_dropped(analyzer()->recent_sinsp_events_dropped());
	}

	if (c_event_labels_enabled.get())
	{
		set_event_labels(container_id, tinfo, event);
	}

	return event;
}

draiosproto::policy_event * security_mgr::create_policy_event(int64_t ts_ns,
							      std::string &container_id,
							      sinsp_threadinfo *tinfo,
							      uint64_t policy_id,
							      draiosproto::event_detail &details,
							      uint64_t policy_version)
{
	draiosproto::policy_event *event = new draiosproto::policy_event();

	event->set_timestamp_ns(ts_ns);
	event->set_policy_id(policy_id);
	event->set_policy_version(policy_version);
	if(!container_id.empty())
	{
		event->set_container_id(container_id);
	}

	draiosproto::event_detail* mdetails = event->mutable_event_details();
	*mdetails = details;

	// If the policy event comes from falco, copy the information
	// to the falco_details section of the policy event. This is
	// for backwards compatibility with older backend versions.
	if(details.has_output_details() && details.output_details().output_type() == draiosproto::PTYPE_FALCO)
	{
		draiosproto::falco_event_detail *fdet = event->mutable_falco_details();
		fdet->set_rule(details.output_details().output_fields().at("falco.rule"));
		fdet->set_output(details.output_details().output());
	}

	if(m_analyzer)
	{
		event->set_sinsp_events_dropped(analyzer()->recent_sinsp_events_dropped());
	}

	if (c_event_labels_enabled.get())
	{
		set_event_labels(container_id, tinfo, event);
	}

	return event;
}

void security_mgr::set_event_labels(std::string &container_id,
									sinsp_threadinfo *tinfo,
									draiosproto::policy_event *event)
{
	// Process Name
	if (m_event_labels.find("process.name") != m_event_labels.end())
	{
		if (tinfo != nullptr && tinfo->m_tid > 0)
		{
			std::string cmdline;
			sinsp_threadinfo::populate_cmdline(cmdline, tinfo);
			if (!cmdline.empty()) {
				(*event->mutable_event_labels())["process.name"] = std::move(cmdline);
			}
		}
	}

	// Host Name
	if (m_event_labels.find("host.hostName") != m_event_labels.end())
	{
		string host_name = sinsp_gethostname();
		if (!host_name.empty()) {
			(*event->mutable_event_labels())["host.hostName"] = std::move(host_name);
		}
	}

	// Agent Tags
	if (m_event_labels.find("agent.tag") != m_event_labels.end()) {
		std::vector<std::string> tags = sinsp_split(m_configuration->m_host_tags, ',');

		std::string tag_prefix = "agent.tag.";

		int count_tags = 0;
		for (auto &pair : tags) {
			if (count_tags >= c_event_labels_max_agent_tags.get())
			{
				break;
			}

			std::vector<std::string> parts = sinsp_split(pair, ':');

			if (parts.size() == 2) {
				// Do not include hardcoded "sysdig_secure.enabled" tag
				if (parts[0] != "sysdig_secure.enabled") {
					(*event->mutable_event_labels())[tag_prefix + parts[0]] = parts[1];
					count_tags++;
				}
			}
		}
	}

	// Infrastructure Lookup for Kubernetes Labels
	infrastructure_state::uid_t uid;
	uid = std::make_pair("container", container_id);

	std::unordered_map<std::string, std::string>event_labels;
	m_analyzer->infra_state()->find_tag_list(uid, m_event_labels, event_labels);

	for (auto& it: event_labels)
	{
		(*event->mutable_event_labels())[it.first] = std::move(it.second);
	}

	// Kubernetes Cluster Name
	if (m_event_labels.find("kubernetes.cluster.name") != m_event_labels.end())
	{
		// kubernetes.cluster.name should be pushed only if the event is related to k8s
		// Use Pod Name label to check it
		if (event_labels.find("kubernetes.pod.name") != event_labels.end())
		{
			if (!m_configuration->m_k8s_cluster_name.empty())
			{
				(*event->mutable_event_labels())["kubernetes.cluster.name"] = m_analyzer->infra_state()->get_k8s_cluster_name();
			}
		}
	}
}

void security_mgr::report_events(uint64_t ts_ns)
{
	if(m_events.events_size() == 0)
	{
		g_log->debug("security_mgr::report_events: no events");
		return;
	}

	report_events_now(ts_ns, m_events);
	m_events.Clear();
}

void security_mgr::report_events_now(uint64_t ts_ns, draiosproto::policy_events &events)
{
	if(events.events_size() == 0)
	{
		g_log->error("security_mgr::report_events_now: empty set of events ?");
		return;
	} else {
		g_log->information("security_mgr::report_events_now: " + to_string(events.events_size()) + " events");
	}

	events.set_machine_id(m_configuration->machine_id());
	events.set_customer_id(m_configuration->m_customer_id);
	m_sinsp_handler->security_mgr_policy_events_ready(ts_ns, &events);
}

void security_mgr::report_throttled_events(uint64_t ts_ns)
{
	uint32_t total_throttled_count = 0;

	if(m_policy_throttled_counts.size() > 0)
	{
		draiosproto::throttled_policy_events tevents;
		tevents.set_machine_id(m_configuration->machine_id());
		tevents.set_customer_id(m_configuration->m_customer_id);

		for(auto &it : m_policy_throttled_counts)
		{
			draiosproto::throttled_policy_event *new_tevent = tevents.add_events();
			new_tevent->set_timestamp_ns(ts_ns);
			new_tevent->set_container_id(it.first.first);
			new_tevent->set_policy_id(it.first.second);
			new_tevent->set_count(it.second);
			total_throttled_count += it.second;
		}

		m_sinsp_handler->security_mgr_throttled_events_ready(ts_ns, &tevents, total_throttled_count);
	}

	// Also remove any token buckets that haven't been seen in
	// (1/rate * max burst) seconds. These token buckets have
	// definitely reclaimed all their tokens, even if fully consumed.
	auto bucket = m_policy_rates.begin();
	while(bucket != m_policy_rates.end())
	{
		if((ts_ns - bucket->second.get_last_seen()) >
		   (1000000000UL *
			(1 / security_config::get_policy_events_rate()) * security_config::get_policy_events_max_burst()))
		{
			g_log->debug("Removing token bucket for container=" + bucket->first.first
				     + ", policy_id=" + to_string(bucket->first.second));
			m_policy_rates.erase(bucket++);
		}
		else
		{
			bucket++;
		}
	}


	m_policy_throttled_counts.clear();
}

void security_mgr::on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo)
{
	string errstr;

	// It's a write lock because m_policies_groups could be
	// modified in load_policy()
	Poco::ScopedWriteRWLock lck(m_policies_lock);

	std::list<std::string> ids{container_info.m_id};

	// In practice, only one of m_policies_groups/m_rules_groups
	// and m_policies/m_policies_v2 will actually have items.

	for(const auto &it : m_policies)
	{
		load_policy(*it.second.get(), ids);
	}

	for(const auto &it : m_policies_v2)
	{
		load_policy_v2(it.second, ids);
	}

	for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
	{
		for(const auto &group: m_policies_groups)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | group->m_evttypes[evttype];
		}

		for(const auto &group: m_rules_groups)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | group->m_evttypes[evttype];
		}
	}

	log_rules_group_info();
}

void security_mgr::on_remove_container(const sinsp_container_info& container_info)
{
	// TODO if needed
	// since we are resetting everything every time we load the policies
}

std::shared_ptr<security_mgr::security_policies_group> security_mgr::get_policies_group_of(scope_info &sinfo)
{
	for(const auto &group : m_policies_groups)
	{
		if(group->m_scope_info == sinfo)
		{
			return group;
		}
	}

	std::shared_ptr<security_policies_group> grp = make_shared<security_policies_group>(sinfo, m_inspector, m_configuration);
	grp->init(m_falco_engine, m_security_evt_metrics);

	m_policies_groups.emplace_back(grp);

	return grp;
};

std::shared_ptr<security_mgr::security_rules_group> security_mgr::get_rules_group_of(const scope_predicates &preds)
{
	for(const auto &group : m_rules_groups)
	{
		if(group->m_scope_predicates.size() != preds.size())
		{
			continue;
		}

		bool match_predicates = true;

		for(int i=0; i < group->m_scope_predicates.size(); i++)
		{
			if(group->m_scope_predicates[i].SerializeAsString() != preds[i].SerializeAsString())
			{
				match_predicates = false;
				break;
			}
		}

		if(match_predicates)
		{
			return group;
		}
	}

	std::shared_ptr<security_rules_group> grp = make_shared<security_rules_group>(preds, m_inspector, m_configuration);
	grp->init(m_falco_engine, m_fastengine_rules_library, m_security_evt_metrics);

	g_log->debug("Creating Rules Group: " + grp->to_string());
	m_rules_groups.emplace_back(grp);

	return grp;
};

void security_mgr::load_k8s_audit_server()
{
	sdc_internal::k8s_audit_server_load load;
	load.set_tls_enabled(security_config::get_k8s_audit_server_tls_enabled());
	load.set_url(security_config::get_k8s_audit_server_url());
	load.set_port(security_config::get_k8s_audit_server_port());

	if (security_config::get_k8s_audit_server_tls_enabled())
	{
		sdc_internal::k8s_audit_server_X509 *x509 = load.add_x509();
		x509->set_x509_cert_file(security_config::get_k8s_audit_server_x509_cert_file());
		x509->set_x509_key_file(security_config::get_k8s_audit_server_x509_key_file());
	}

	auto callback = [this](bool successful, sdc_internal::k8s_audit_server_load_result &lresult)
	{
		m_k8s_audit_server_load_in_progress = false;
		if(successful)
		{
			g_log->debug("Response from K8s Audit Server load: lresult=" +
				     lresult.DebugString());
			m_k8s_audit_server_loaded = true;
			start_k8s_audit_server_tasks();
		}
		else
		{
			g_log->error("Could not load K8s Audit Server.");
		}
	};

	g_log->debug(string("Sending load message to K8s Audit Server: ") + load.DebugString());
	m_k8s_audit_server_load_in_progress = true;

	m_k8s_audit_server_load_conn = grpc_connect<sdc_internal::K8sAudit::Stub>(m_cointerface_sock_path);
	m_k8s_audit_server_load = make_unique<unary_grpc_client(&sdc_internal::K8sAudit::Stub::AsyncLoad)>(m_k8s_audit_server_load_conn);
	m_k8s_audit_server_load->do_rpc(load, callback);
}

void security_mgr::start_k8s_audit_server_tasks()
{
	g_log->debug("Starting K8s Audit Server");
	sdc_internal::k8s_audit_server_start start;

	// just in case we get called multiple times, tear down the
	// previous GRPCs objects
	m_k8s_audit_server_start = NULL;
	m_k8s_audit_server_start_conn = NULL;

	auto callback = [this](streaming_grpc::Status status, sdc_internal::k8s_audit_event &jevt)
		{
			if(status == streaming_grpc::ERROR)
			{
				g_log->error("Could not start K8s Audit Server tasks, trying again in " +
					     NumberFormatter::format(security_config::get_k8s_audit_server_refresh_interval() / 1000000000) +
					     " seconds");
			}
			else if(status == streaming_grpc::SHUTDOWN)
			{
				g_log->error("K8s Audit Server shut down connection, trying again in " +
					     NumberFormatter::format(security_config::get_k8s_audit_server_refresh_interval() / 1000000000) +
					     " seconds");
			}
			else
			{
				if(!jevt.successful())
				{
					g_log->error(string("Could not start K8s Audit Server tasks (") + jevt.errstr()+ "), trying again in " +
						     NumberFormatter::format(security_config::get_k8s_audit_server_refresh_interval() / 1000000000) +
						     " seconds");
				} else {
					std::list<json_event> jevts;
					nlohmann::json j;

					g_log->debug("Response from K8s Audit Server start: jevt=" +
						     jevt.DebugString());
					try {
						j = json::parse( jevt.evt_json() );
					} catch  (json::parse_error& e) {
						g_log->error(string("Could not parse data: ") + e.what());
						return false;
					}
					if(!m_falco_engine->parse_k8s_audit_json(j, jevts))
					{
						g_log->error(string("Data not recognized as a K8s Audit Event"));
						return false;
					}
					for(auto jev : jevts)
					{
						// instead of calling directly process_event, it might be worth enqueue into a list and have a worker thread processing the list
						process_event(&jev);
					}
					return true;
				}
			}
			return false;
		};

	// m_k8s_audit_server_started = true;

	g_log->debug(string("Sending start message to K8s Audit Server: ") + start.DebugString());

	m_k8s_audit_server_start_conn = grpc_connect<sdc_internal::K8sAudit::Stub>(m_cointerface_sock_path);
	m_k8s_audit_server_start = make_unique<streaming_grpc_client(&sdc_internal::K8sAudit::Stub::AsyncStart)>(m_k8s_audit_server_start_conn);
	m_k8s_audit_server_start->do_rpc(start, callback);
}

void security_mgr::stop_k8s_audit_tasks()
{
	bool stopped = false;
	auto callback = [this, &stopped](bool successful, sdc_internal::k8s_audit_stop_result &res)
	{
		// cointerface might shut down before dragent, causing
		// the stop to itself not complete. So only log
		// failures at debug level.
		if(!successful)
		{
			g_log->debug("K8s Audit Server Stop() call was not successful");
		}

		if(!res.successful())
		{
			g_log->debug("K8s Audit Server Stop() call returned error " + res.errstr());
		}

		stopped = true;
	};

	sdc_internal::k8s_audit_server_stop stop;

	shared_ptr<sdc_internal::K8sAudit::Stub> k8s_audit_stop_conn =
		grpc_connect<sdc_internal::K8sAudit::Stub>(m_cointerface_sock_path);
	unary_grpc_client(&sdc_internal::K8sAudit::Stub::AsyncStop) grpc_stop(k8s_audit_stop_conn);

	grpc_stop.do_rpc(stop, callback);

	// Wait up to 10 seconds for a response
	for(uint32_t i=0; i < 100; i++)
	{
		Poco::Thread::sleep(100);
		grpc_stop.process_queue();

		if(stopped)
		{
			return;
		}
	}

        g_log->error("Did not receive response to K8s Audit Stop() call within 10 seconds");
}

// Given two vectors of strings 'include' and 'exclude'
// if a key is present in both include and exclude ignore it
// otherwise create a set of 'include' strings
void security_mgr::configure_event_labels_set(){
	for (const auto& s : c_event_labels_include.get()){
		m_event_labels.insert(s);
	}
	for (const auto& s : c_event_labels_exclude.get()){
		m_event_labels.erase(s);
	}
}

#endif // CYGWING_AGENT
