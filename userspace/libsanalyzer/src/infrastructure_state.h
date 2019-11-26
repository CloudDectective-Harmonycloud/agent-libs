#ifndef CYGWING_AGENT
#ifndef INFRASTRUCTURE_STATE_H
#define INFRASTRUCTURE_STATE_H

#include <map>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "analyzer_utils.h"
#include "analyzer_settings.h"
#include "coclient.h"
#include "k8s_limits.h"
#include "sdc_internal.pb.h"
#include "type_config.h"

typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;
typedef google::protobuf::RepeatedPtrField<draiosproto::container_group> container_groups;

class event_scope;

class infrastructure_state
{
public:
	// <kind, UID> strings
	using uid_t = std::pair<std::string, std::string>;

	// { host/container id : {scope hash : scope match result} }
	using policy_cache_t = std::unordered_map<std::string, std::unordered_map<size_t, bool>>;

	// Pass a 4th optional argument to turn on m_k8s_subscribed for unit tests. Need to refactor.
	infrastructure_state(sinsp *inspector,
			     const std::string& rootdir,
			     bool force_k8s_subscribed = false);
	using reg_id_t = std::string;

	~infrastructure_state();

	void init(const std::string& machine_id, const std::string& host_tags);
	bool inited();

	static std::string as_string(const scope_predicates &predicates);

	void subscribe_to_k8s();

	bool subscribed();

	void refresh(uint64_t ts);

	// Check the uid against the scope predicates in predicates
	// and return whether or not the uid matches the predicates.
	bool match_scope(const uid_t &uid, const scope_predicates &predicates);

	// Register a set of scope predicates with this object and
	// keep track of whether the predicates match the current
	// state. This is most interesting for container-level scope,
	// where the predicates are re-tested as containers come and go.
	//
	// Returns true if the scope could be registered, false otherwise.
	bool register_scope(reg_id_t &reg,
			    bool host_scope, bool container_scope,
			    const scope_predicates &predicates);

	// Check a previously registered scope to see if it matches
	// the current state
	bool check_registered_scope(reg_id_t &reg);

	void calculate_rate_metrics(draiosproto::container_group *cg, const uint64_t ts);
	void delete_rate_metrics(const uid_t &key);

	void state_of(const std::vector<std::string> &container_ids, container_groups* state, const uint64_t ts);
	void state_of(const std::vector<std::string> &container_ids, draiosproto::k8s_state* state, const uint64_t ts);

	void get_state(container_groups* state, const uint64_t ts);
	void get_state(draiosproto::k8s_state* state, uint64_t ts);

	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);
	void on_remove_container(const sinsp_container_info& container_info);

	void receive_hosts_metadata(const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events);

	void clear_scope_cache();

	void load_single_event(const draiosproto::congroup_update_event &evt, bool overwrite = false);

	bool find_tag(uid_t uid, std::string tag, std::string &value) const
	{
		std::unordered_set<uid_t> visited;
		return find_tag(uid, tag, value, visited);
	}

	/// Find list of key-value tags present in infrastructure_state
	/// \param uid  UID of the starting node of the graph
	/// \param tags_set  Set of tags we are looking for
	/// \param labels  Populated key/value map containing found tags
	/// \return
	int find_tag_list(uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string, string> &labels) const
	{
		std::unordered_set<uid_t> visited;
		return find_tag_list(uid, tags_set, labels, visited);
	}
	int get_scope_names(uid_t uid, event_scope *scope) const
	{
		std::unordered_set<uid_t> visited;
		return get_scope_names(uid, scope, visited);
	}

	void scrape_mesos_env(const sinsp_container_info& container, sinsp_threadinfo *tinfo);
	void get_orch_labels(const uid_t uid, google::protobuf::RepeatedPtrField<draiosproto::container_label>* labels, std::unordered_set<uid_t> *visited = nullptr);
	static bool is_mesos_label(const std::string &lbl);

	std::unique_ptr<draiosproto::container_group> get(uid_t uid);
	bool has(uid_t uid) const;
	unsigned int size();

	// Return the cluster name that must be set
	// for the orch state. This is what will be
	// displayed on the front end.
	std::string get_k8s_cluster_name();
	// If the agent tags contain a tag for:
	// cluster:$NAME ; then extract $NAME and return it
	std::string get_cluster_name_from_agent_tags() const;
	// The UID of the default namespace is used as the cluster id
	std::string get_k8s_cluster_id() const;
	void init_k8s_limits(filter_vec_t filters, bool log, uint16_t cache_size);

	void add_annotation_filter(const std::string &ann);
	bool find_parent_kind(const uid_t uid, std::string kind, uid_t &found_id)
	{
		std::unordered_set<uid_t> visited;
		return find_parent_kind(uid, kind, found_id, visited);
	}

	// Find our k8s node from our current container, any of the given container ids
	// or from IP address, in that order, if not found already
	void find_our_k8s_node(const std::vector<std::string> *container_ids);

	// Return the k8s pod UID from namespace and pod name
	std::string get_k8s_pod_uid(const std::string &namespace_name, const std::string &pod_name) const;

	// Return the container ID from the pod UID and the pod container name
	std::string get_container_id_from_k8s_pod_and_k8s_pod_name(const uid_t& p_uid, const std::string &pod_container_name) const;

	const std::string& get_k8s_url();
	const std::string& get_k8s_ca_certificate();
	const std::string& get_k8s_bt_auth_token();
	const std::string& get_k8s_ssl_certificate();
	const std::string& get_k8s_ssl_key();
	std::unordered_set<std::string> test_only_get_container_ids() const;

private:

	void configure_k8s_environment();

	// These return true if the new entry has been added, false if it already existed
	bool add(uid_t key);

	void emit(const draiosproto::container_group *grp, draiosproto::k8s_state *state, uint64_t ts);

	void resolve_names(draiosproto::k8s_state *state);

	void state_of(const draiosproto::container_group *grp,
		      container_groups* state,
		      std::unordered_set<uid_t>& visited, uint64_t ts);

	// Get object names from object and its parents and add them to scope
	int get_scope_names(uid_t uid, event_scope *scope, std::unordered_set<uid_t> &visited) const;

	void state_of(const draiosproto::container_group *grp,
		      draiosproto::k8s_state *state,
		      std::unordered_set<uid_t>& visited, uint64_t ts);

	bool find_parent_kind(const uid_t child_id, string kind, uid_t &found_id,
		std::unordered_set<uid_t> &visited) const;

	bool find_tag(uid_t uid, std::string tag, std::string &value, std::unordered_set<uid_t> &visited) const;
	int find_tag_list(uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string,string> &labels, std::unordered_set<uid_t> &visited) const;
	bool walk_and_match(draiosproto::container_group *congroup,
			    scope_predicates &preds,
			    std::unordered_set<uid_t> &visited_groups);

	void handle_event(const draiosproto::congroup_update_event *evt, bool overwrite = false);
	
	void refresh_hosts_metadata();

	void connect(infrastructure_state::uid_t& key);

	// Remove given key. Set update to true if the key will be reinstantiated as part of an update
	void remove(infrastructure_state::uid_t& key, bool update = false);
	bool has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links, const uid_t& uid);

	bool get_cached_result(const std::string &entity_id, size_t h, bool *res);
	void insert_cached_result(const std::string &entity_id, size_t h, bool res);
	void clear_cached_result(const std::string &entity_id);

	void reset();

	void print_state() const;
	void print_obj(const uid_t &key) const;

	void connect_to_k8s(uint64_t ts = sinsp_utils::get_current_time_ns());
	void k8s_generate_user_event(const bool success);

	bool is_valid_for_export(const draiosproto::container_group *grp) const;

	void purge_tags_and_copy(uid_t, const draiosproto::container_group& cg);

	bool match_scope_all_containers(const scope_predicates &predicates);

	std::map<uid_t, std::unique_ptr<draiosproto::container_group>> m_state;
	std::unordered_map<uid_t, std::vector<uid_t>> m_orphans;

	struct reg_scope_t {
		bool m_host_scope;
		bool m_container_scope;
		scope_predicates m_predicates;
		bool m_scope_match;
	};

	std::map<reg_id_t, reg_scope_t> m_registered_scopes;

	std::queue<draiosproto::congroup_update_event> m_host_events_queue;
	std::mutex m_host_events_queue_mutex;

	policy_cache_t m_policy_cache;

	sinsp *m_inspector;
	std::string m_machine_id;

	std::hash<std::string> m_str_hash_f;

	coclient m_k8s_coclient;
	coclient::response_cb_t m_k8s_callback;
	bool m_k8s_subscribed;   // True if we're supposed to connect to k8s
	bool m_k8s_connected;    // True if we have an active RPC connection
	k8s_limits m_k8s_limits;
	mutable std::string m_k8s_cached_cluster_id;
	run_on_interval m_k8s_refresh_interval;
	run_on_interval m_k8s_connect_interval;
	int m_k8s_prev_connect_state;
	std::string m_k8s_node;
	std::string m_k8s_node_uid;
	bool m_k8s_node_actual;	// True if node found from following a running container

	struct rate_metric_state_t {
		rate_metric_state_t() : val(0), ts(0), last_rate(0) {}
		double val;
		time_t ts;
		double last_rate;
	};

	std::unordered_map<uid_t, std::unordered_map<std::string, rate_metric_state_t>> m_rate_metric_state;
	std::unordered_map<std::string, rate_metric_state_t> m_pod_restart_rate;
	static double calculate_rate(rate_metric_state_t& prev, double value, uint64_t ts);

	std::set<std::string> m_annotation_filter;

	std::string m_root_dir;

	// the config value, c_k8s_url, only represents what we get out of the
	// config. We do some post processing to get the value we actually use and store
	// it here.
	std::string m_k8s_url;
	std::string m_k8s_bt_auth_token;
	std::string m_k8s_ca_certificate;
	std::string m_k8s_ssl_certificate;
	std::string m_k8s_ssl_key;
	// Local cache for k8s_cluster_name
	std::string m_k8s_cluster_name;

private:
	/**
	 * adjusts path for changes in configured root dir
	 */
	std::string normalize_path(const std::string& path) const;

public: // configs
	static type_config<uint32_t> c_orchestrator_queue_len;
	static type_config<int32_t> c_orchestrator_gc;
	static type_config<uint32_t> c_orchestrator_informer_wait_time_s;
	static type_config<uint32_t> c_orchestrator_tick_interval_ms;
	static type_config<uint32_t> c_orchestrator_low_ticks_needed;
	static type_config<uint32_t> c_orchestrator_low_event_threshold;
	static type_config<bool> c_orchestrator_filter_empty;
	static type_config<uint32_t> c_orchestrator_batch_messages_queue_length;
	static type_config<uint32_t> c_orchestrator_batch_messages_tick_interval_ms;
	static type_config<bool> c_k8s_ssl_verify_certificate;
	static type_config<std::vector<std::string>> c_k8s_include_types;
	static type_config<uint32_t> c_k8s_event_counts_log_time;
	static type_config<uint64_t> c_k8s_timeout_s;
	static type_config<std::string>::ptr c_k8s_ssl_key_password;
	static type_config<std::string> c_k8s_ssl_certificate_type;
	static type_config<bool> c_k8s_autodetect;
	static type_config<uint64_t> c_k8s_refresh_interval;
	static type_config<uint32_t>::ptr c_k8s_max_rnd_conn_delay;

private: // configs which have non-static fields that we actually use. You probably don't
	 // want these. In almost all cases, you'll probably want to use the normalized
	 // member variables.
	static type_config<std::string> c_k8s_url;
	static type_config<std::string> c_k8s_bt_auth_token;
	static type_config<std::string> c_k8s_ca_certificate;
	static type_config<std::string> c_k8s_ssl_certificate;
	static type_config<std::string> c_k8s_ssl_key;

	friend class new_k8s_delegator;
	friend class test_helper;
};

class new_k8s_delegator
{
public:
	new_k8s_delegator() : m_prev_deleg(false), m_cached_deleg(false) { }

	bool has_agent(infrastructure_state *, const infrastructure_state::uid_t uid, std::unordered_set<infrastructure_state::uid_t> *visited = nullptr);
	bool is_delegated_now(infrastructure_state *, int num_delegated);
	bool is_delegated(infrastructure_state *, int num_delegated, uint64_t);

private:
	bool m_prev_deleg;
	bool m_cached_deleg;

	run_on_interval m_delegation_interval = { K8S_DELEGATION_INTERVAL };
};

#endif // INFRASTRUCTURE_STATE_H
#endif // CYGWING_AGENT
