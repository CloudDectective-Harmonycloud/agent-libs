#pragma once
#ifndef CUSTOM_CONTAINER_HARD_LIMIT
#define CUSTOM_CONTAINER_HARD_LIMIT 150
#endif

#ifndef CUSTOM_CONTAINER_ID_LENGTH_LIMIT
#define CUSTOM_CONTAINER_ID_LENGTH_LIMIT 100
#endif

#ifndef _WIN32

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

#include <Poco/Exception.h>
#include <Poco/Foundation.h>
#include <Poco/RegularExpression.h>

// suppress deprecated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

#include "sinsp.h"

namespace custom_container {

struct match {
	std::string m_str;
	Poco::RegularExpression::MatchVec m_matches;

	void render(std::string& out, int capture_id) const
	{
		if ((int)m_matches.size() <= capture_id)
		{
			throw Poco::RuntimeException(std::string("Requested substitution of group ") +
				std::to_string(capture_id) + " while maximum is " + std::to_string((int)m_matches.size() - 1));
		}

		const auto& match = m_matches[capture_id];
		out.append(m_str.substr(match.offset, match.length));
	}
};

typedef std::unordered_map<std::string, match> render_context;

class subst_token {
public:
	subst_token(const std::string& var_name, int capture_id=-1):
		m_var_name(var_name),
		m_capture_id(capture_id)
	{
	}

	void render(std::string& out, const render_context& ctx, const std::vector<std::string>& env) const;

	bool operator==(const subst_token& other) const
	{
		return m_capture_id == other.m_capture_id &&
			m_var_name == other.m_var_name;
	}

protected:
	std::string m_var_name;
	int m_capture_id = 0; // -1 means use var_name itself as expansion
};


class subst_template {
public:
	subst_template()
	{
	}

	subst_template(const std::string& pattern)
	{
		parse(pattern);
	}

	void render(std::string& out, const render_context& ctx, const std::vector<std::string>& env) const
	{
		for (const auto& tok: m_tokens)
		{
			tok.render(out, ctx, env);
		}
	}

	bool empty() const
	{
		return m_tokens.empty();
	}

VISIBILITY_PRIVATE
	const std::vector<subst_token>& get_tokens() const
	{
		return m_tokens;
	}

protected:
	void parse(const std::string& pattern);

	std::vector<subst_token> m_tokens;
};

class resolver {
public:
	resolver();

	void set_enabled(bool enabled)
	{
		if (enabled && m_id_pattern.empty())
		{
			throw Poco::RuntimeException("Custom containers enabled without custom_containers.id template set");
		}
		if (enabled && !m_cgroup_match && m_environ_match.empty())
		{
			throw Poco::RuntimeException("Custom containers enabled with neither cgroup nor environ match set");
		}
		m_enabled = enabled;
	}

	void set_cgroup_match(const std::string& rx)
	{
		if (rx.empty())
		{
			m_cgroup_match.reset(nullptr);
		}
		else
		{
			m_cgroup_match.reset(new Poco::RegularExpression(rx, 0));
		}
	}

	void set_environ_match(const std::string& var_name, const std::string& rx)
	{
		if (var_name.empty())
		{
			throw Poco::RuntimeException("Environment variable to match cannot be empty");
		}
		std::string s(var_name);
		m_environ_match[s].reset(new Poco::RegularExpression(rx, 0));
	}

	void set_environ_match(const std::unordered_map<std::string, std::string>& matches)
	{
		for (const auto it : matches) {
			set_environ_match(it.first, it.second);
		}
	}

	void set_id_pattern(const std::string& pattern)
	{
		std::string p(pattern);
		m_id_pattern = subst_template(p);
	}

	void set_name_pattern(const std::string& pattern)
	{
		std::string p(pattern);
		m_name_pattern = subst_template(p);
	}

	void set_image_pattern(const std::string& pattern)
	{
		std::string p(pattern);
		m_image_pattern = subst_template(p);
	}

	void set_label_pattern(const std::string& label, const std::string& pattern)
	{
		std::string l(label);
		std::string p(pattern);
		m_label_patterns.emplace(l, p);
	}

	void set_label_pattern(const std::unordered_map<std::string, std::string>& patterns)
	{
		for (const auto it : patterns) {
			set_label_pattern(it.first, it.second);
		}
	}

	void set_max(int max)
	{
		if (max >= CUSTOM_CONTAINER_HARD_LIMIT)
		{
			max = CUSTOM_CONTAINER_HARD_LIMIT;
		}
		m_max = max;
	}

	void set_max_id_length(int max)
	{
		if (max >= CUSTOM_CONTAINER_ID_LENGTH_LIMIT)
		{
			max = CUSTOM_CONTAINER_ID_LENGTH_LIMIT;
		}
		m_max_id_length = max;
	}

	void set_incremental_metadata(bool incremental_metadata)
	{
		m_incremental_metadata = incremental_metadata;
	}

	void set_config_test(bool config_test)
	{
		m_config_test = config_test;
	}

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);

	void dump_container_table();

	// return a comma-separated list of labels
	// a vector<string> would be cleaner but we only use this in one place
	// (passing the list of labels to prometheus exporter) which expects
	// this format.
	// if we (eventually) allow multiple custom container configs (matching
	// multiple configurations), this method should return a set<string>
	// (or get one as a reference and modify it in place)
	std::string get_labels() const;


protected:
	bool m_enabled = false;
	bool m_limit_logged = false;

	// when true, we keep scanning processes in the container for metadata until we fill
	// the name, image and all labels or until the timeout expires
	// when false, we stop scanning as soon as we find the container name
	bool m_incremental_metadata = false;

	bool m_config_test = false;
	int m_max = 0;
	int m_max_id_length = 0;
	char m_label_value_substitution_char = '\0';
	static const std::string s_label_name_whitelist;
	static const std::string s_label_value_whitelist;

	std::unique_ptr<Poco::RegularExpression> m_cgroup_match;
	std::unordered_map<std::string, std::unique_ptr<Poco::RegularExpression>> m_environ_match;

	subst_template m_id_pattern;
	subst_template m_name_pattern;
	subst_template m_image_pattern;
	std::unordered_map<std::string, subst_template> m_label_patterns;

	bool match_cgroup(sinsp_threadinfo* tinfo, render_context& render_ctx);
	bool match_environ(sinsp_threadinfo* tinfo, render_context& render_ctx);
	sinsp_threadinfo* match_environ_tree(sinsp_threadinfo *tinfo, render_context &render_ctx);

	void init_label_value_substitution_char();
	void sanitize_label_name(std::string& val) const;
	void sanitize_label_value(std::string& val) const;

	match m_hostname;

	YAML::Node m_dump;
};



}
#endif // _WIN32
