/**
 * @file
 *
 * Interface to type_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <algorithm>
#include <cctype>
#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

class yaml_configuration;

namespace test_helpers
{
template<typename config_type>
class scoped_config;
}

/**
 * This configuration scheme provides an easy way of acquiring
 * config values from a central location without having to pass
 * them around, and without the central location needing to be
 * aware of how to parse individual types.
 *
 * Usage:
 *
 * (in some cpp file)
 *
 * type_config<uint64_t> my_config_variable_name(some_default_value,
 *                                               "key_name_in_yaml");
 *
 * OR if using the optional fields (like min and max)
 *
 * type_config<uint64_t>::ptr  my_config_variable_name =
 *      type_config_builder<int>(some_default_value, "key_name_in_yaml")
 *          .min(10).max(50).build();
 *
 * The data is automatically populated from the yaml, and can then be freely
 * used:
 *
 * my_config_variable_name.get_value()
 *
 * If you have a not-yet-supported type, you'll most likely get a compile error
 * saying it can't find "get_value_string<your_type>". If your type is a scalar,
 * then you'll simply need to implement that function. If it's specific to your
 * module, you should just do this in your module, otherwise, add it to the cpp
 * file here so it is shared.
 *
 * If your data type is NOT a scalar, then you'll likely need to implement your
 * own init function. It probably makes the most sense to derive directly from
 * configuration_unit
 *
 * NOTE: registering new keys is NOT thread safe, and thus should only be done
 * statically, which will guarantee us single-threadedness
 */
class configuration_unit
{
public:
	class exception : public std::runtime_error
	{
	public:
		exception(const std::string& msg);
	};

	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value requires fewer values, set the other strings to "".
	 * This constructor should register this object with the
	 * configuration_manager class.
	 */
	configuration_unit(const std::string& key,
	                   const std::string& subkey,
	                   const std::string& subsubkey,
	                   const std::string& description);
	virtual ~configuration_unit();

	/**
	 * Return a "key: value" representation of this config.
	 *
	 * Expected to generally be of the form
	 * key.subkey.subsubkey: value
	 * subkeys can be skipped if empty, and more complex config types may
	 * need to modify this format as they see fit
	 *
	 * @return the string conversion of this object
	 */
	std::string to_string() const;

	/**
	 * Returns a string representation of the value of this config.
	 */
	virtual std::string value_to_string() const = 0;

	/**
	 * Returns a string representation of the value of this config which is
	 * also valid YAML. May or may not be the same as value_to_string.
	 *
	 * Not guaranteed to parse to the same value, and thus should not
	 * be relied upon.
	 */
	virtual std::string value_to_yaml() const = 0;

	/**
	 * Updates this configuration_unit%'s value based on the content of
	 * the given string.
	 *
	 * @param[in] value A string representation of the new value of this
	 *                  configuration_unit.
	 *
	 * @returns true if the given value could be parsed into the type
	 *          modeled by this configuration_unit; false otherwise.
	 */
	virtual bool string_to_value(const std::string& value) = 0;

	/**
	 * Initializes the value stored in the raw config.
	 *
	 * @param raw_config the yaml_configuration containing the configuration
	 *                   data
	 */
	virtual void init(const yaml_configuration& raw_config) = 0;

	/**
	 * Return the canonical string for the config.
	 *
	 * key_string will be of the form:
	 * key | key.subkey | key.subkey.subsubkey
	 *
	 * @return the canonical string for the config
	 */
	const std::string& get_key_string() const;

	/** Returns the primary key for this configuration_unit. */
	const std::string& get_key() const;

	/** Returns the primary subkey for this configuration_unit. */
	const std::string& get_subkey() const;

	/** Returns the primary subsubkey for this configuration_unit. */
	const std::string& get_subsubkey() const;

	/** Returns the description for this configuration_unit. */
	const std::string& get_description() const;

	/** Stop this configuration value from showing up in logs */
	void hidden(bool value);

	/** Returns whether the value is hidden from logs */
	bool hidden() const;

	/** Set alternate key; this is useful for legacy key names */
	void alternate_key(const std::string& key,
	                   const std::string& subkey = std::string(),
	                   const std::string& subsubkey = std::string())
	{
		m_keys.push_back(config_key(key, subkey, subsubkey));
	}

	/** Called after all configuration params have been init'd */
	virtual void post_init() = 0;

	/**
	 * Returns a JSON-formatted representation of this configuration_unit.
	 */
	std::string to_json() const;

	/**
	 * Update the state of this configuration_unit based on the json.
	 *
	 * @throws configuration_unit::exception if it fails to update
	 *         this configuration_unit based on the given json.
	 */
	void from_json(const std::string& json);

	/**
	 * Returns whether this was set via a config file, or just assumed the default value
	 */
	virtual bool is_set_in_config() const { return false; }

	/**
	 * API for explicitly setting the value in config. generally only for test usage
	 */
	virtual void set_set_in_config(bool val) {}

protected:
	struct config_key
	{
		config_key(const std::string& key_value,
		           const std::string& subkey_value,
		           const std::string& subsubkey_value)
		    : key(key_value),
		      subkey(subkey_value),
		      subsubkey(subsubkey_value)
		{
		}

		std::string to_string() const
		{
			if (subkey.empty())
			{
				return key;
			}
			else if (subsubkey.empty())
			{
				return key + "." + subkey;
			}
			else
			{
				return key + "." + subkey + "." + subsubkey;
			}
		}

		const std::string key;
		const std::string subkey;
		const std::string subsubkey;
	};
	const std::vector<config_key>& keys() { return m_keys; }

	/**
	 * Returns a string representation for anything that std::to_string() can
	 * handle.
	 */
	template<typename value_type>
	static std::string get_value_string(const value_type& value)
	{
		return std::to_string(value);
	}

	/**
	 * Override of get_value_string() for type std::vector<value_type>.
	 *
	 * @returns a string representation of the given value_vector in the form
	 *          "[value1, value2, value3]"
	 */
	template<typename value_type>
	static std::string get_value_string(const std::vector<value_type>& value_vector)
	{
		std::stringstream out;

		out << "[";

		typename std::vector<value_type>::const_iterator i = value_vector.begin();

		if (i != value_vector.end())
		{
			out << get_value_string<value_type>(*i);

			for (++i; i != value_vector.end(); ++i)
			{
				out << ", " << get_value_string<value_type>(*i);
			}
		}

		out << "]";

		return out.str();
	}

	/**
	 * Convert the given str to the given value of the given value_type.
	 *
	 * @tparam value_type The type of the value to get from the string
	 *
	 * @param[in]  str   The string representation of the value.
	 * @param[out] value The output value
	 *
	 * @returns true if the given str was parsed into a value of the
	 *          given value_type, false otherwise.
	 */
	template<typename value_type>
	static bool get_value(const std::string& str, value_type& value)
	{
		std::stringstream out;
		value_type value_in;

		out << str;
		out >> value_in;

		if (out)
		{
			value = value_in;
			return true;
		}

		return false;
	}

	/**
	 * Override of get_value() for type std::vector<value_type>.
	 *
	 * Current we do not support parsing string->vector<value> so this
	 * always returns false.
	 */
	template<typename value_type>
	static bool get_value(const std::string& str, std::vector<value_type>& value)
	{
		return false;
	}

private:
	const config_key& primary_key() const { return m_keys[0]; }

	// The primary key is kept at index 0 and is populated by the
	// constructor so it should always exist. Alternate keys, if they exist,
	// are at later indexes.
	std::vector<config_key> m_keys;
	const std::string m_description;
	std::string m_keystring;
	bool m_hidden;
};

/**
 * Specialization of get_value_string() for type bool.
 *
 * @returns "true" if the given value is true and "false" otherwise.
 */
template<>
inline std::string configuration_unit::get_value_string<bool>(const bool& value)
{
	return value ? "true" : "false";
}

/**
 * Specialization of get_value_string() for type string.
 *
 * @returns the given value.
 */
template<>
inline std::string configuration_unit::get_value_string<std::string>(const std::string& value)
{
	return value;
}

/**
 * An implementation of configuration_unit which supports scalar types.
 *
 * Typename can be an arbitrary type which yaml_configuration::get_scalar can
 * parse
 */
template<typename data_type>
class type_config : public configuration_unit
{
	static_assert(!std::is_same<data_type, uint8_t>::value, "data_type = uint8_t is not supported");
	static_assert(!std::is_same<data_type, int8_t>::value, "data_type = int8_t is not supported");

public:
	using ptr = std::shared_ptr<const type_config<data_type>>;
	using mutable_ptr = std::shared_ptr<type_config<data_type>>;

	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value only requires fewer values, set the other strings to "". This
	 * constructor should register this object with the configuration_manager
	 * class.
	 *
	 * The value of this config is set to the default at construction, and
	 * so will be valid, even if the yaml file has not been parsed yet.
	 */
	type_config(const data_type& default_value,
	            const std::string& description,
	            const std::string& key,
	            const std::string& subkey = "",
	            const std::string& subsubkey = "");

public:  // stuff for configuration_unit
	std::string value_to_string() const override;
	std::string value_to_yaml() const override;
	bool string_to_value(const std::string& value) override;
	void init(const yaml_configuration& raw_config) override;

	/**
	 * sets the value of this config to input value
	 */
	virtual void set(const data_type& value);

	/**
	 * Returns a const reference to the current value of this type_config.
	 *
	 * @return the value of this config
	 */
	const data_type& get_value() const;

	/**
	 * Returns a non-const reference to the current value of this
	 * type_config.
	 *
	 * @return the value of this config
	 */
	data_type& get_value();

	/**
	 * Returns whether this was set via a config file, or just assumed the default value
	 */
	virtual bool is_set_in_config() const override { return m_data_set_in_config; }

	/**
	 * Only for test usage
	 */
	virtual void set_set_in_config(bool val) override { m_data_set_in_config = val; }

public:  // other stuff
	/**
	 * Returns a the value configured in the yaml (or the default).
	 * This is useful to get what the value was before the
	 * post_init() function changes the value.
	 *
	 * @return the value of this config
	 */
	const data_type& configured() const;

	/**
	 * Sets a new default value. While it shouldn't be common, is required for a
	 * very small number of configs that have their default value determined
	 * dynamically.
	 */
	void set_default(const data_type& value);

	/**
	 * Set the minimum value.
	 */
	void min(const data_type& value);

	/**
	 * Set the maximum value.
	 */
	void max(const data_type& value);

	/**
	 * Set whether the param can be changed from the default outside
	 * of an internal build
	 */
	void mutable_only_in_internal_build(bool value) { m_mutable_only_in_internal = value; }

	/**
	 * Get whether the param can be changed from the default outside of an
	 * internal build
	 */
	bool mutable_only_in_internal_build() { return m_mutable_only_in_internal; }

	/**
	 *
	 *
	 * Set the post_init delegate. This allows the configuration value to be
	 * changed after all init functions are called for all configuration
	 * parameters. This is useful if one config depends on another. Example
	 * usage:
	 * .post_init([](type_config<int>& config)
	 * {
	 *	config.get_value() = c_other_config.configured() == 0 ? 0 : config.get_value();
	 * });
	 */
	using post_init_delegate = std::function<void(type_config<data_type>&)>;
	void post_init(const post_init_delegate& value);

	/**
	 *  Call the post_init delegate if it was provided
	 */
	void post_init() override;

private:
	data_type m_default;
	data_type m_data;
	bool m_data_set_in_config;

	/**
	 * The value configured by the user. This can vary from m_data when
	 * m_data is overriden in the post_init delegate.
	 */
	data_type m_configured;
	bool m_mutable_only_in_internal;

	// Using unique_ptr in lieu of std::optional
	std::unique_ptr<data_type> m_min;
	std::unique_ptr<data_type> m_max;
	post_init_delegate m_post_init;

	friend class test_helper;
	template<typename config_type>
	friend class test_helpers::scoped_config;
};

/**
 * Helper to create a (usually static) instance of an
 * type_config by calling functions to set the appropriate
 * characteristics. This keeps us from having many different
 * constructors for the type_config
 */
template<typename data_type>
class type_config_builder
{
public:
	type_config_builder(const data_type& default_value,
	                    const std::string& description,
	                    const std::string& key,
	                    const std::string& subkey = "",
	                    const std::string& subsubkey = "")
	    : m_type_config(
	          new type_config<data_type>(default_value, description, key, subkey, subsubkey))
	{
	}

	/**
	 * Set the max configuration value
	 */
	type_config_builder& max(const data_type& value)
	{
		m_type_config->max(value);
		return *this;
	}

	/**
	 * Set the min configuration value
	 */
	type_config_builder& min(const data_type& value)
	{
		m_type_config->min(value);
		return *this;
	}

	/**
	 * Keep the config from showing up in logs
	 */
	type_config_builder& hidden()
	{
		m_type_config->hidden(true);
		return *this;
	}

	/** Set alternate key; this is useful for legacy key names */
	void alternate_key(const std::string& key,
	                   const std::string& subkey = std::string(),
	                   const std::string& subsubkey = std::string())
	{
		m_type_config->alternate_key(key, subkey, subsubkey);
		return *this;
	}

	/**
	 * Only allow the default value to be overridden in an internal test
	 * build
	 */
	type_config_builder& mutable_only_in_internal_build()
	{
		m_type_config->mutable_only_in_internal_build(true);
		return *this;
	}

	/**
	 * Set a delegate that will be called after all of the
	 * configurables are init'd. This is useful if one config
	 * depends on another.
	 */
	type_config_builder& post_init(const typename type_config<data_type>::post_init_delegate& value)
	{
		m_type_config->post_init(value);
		return *this;
	}

	/**
	 * Return the generated instance
	 */
	typename type_config<data_type>::ptr build() { return m_type_config; }

	/**
	 * Return a mutable version of the generated instance. Since
	 * these configs are meant to only be changed during static
	 * init, make sure you know what you are doing if you use this.
	 */
	typename type_config<data_type>::mutable_ptr build_mutable() { return m_type_config; }

private:
	typename type_config<data_type>::mutable_ptr m_type_config;
};

/**
 * Specialization of get_value() for type std::string.
 */
template<>
inline bool configuration_unit::get_value<std::string>(const std::string& str, std::string& value)
{
	value = str;
	return true;
}

/**
 * Specialization of get_value for type bool
 */
template<>
inline bool configuration_unit::get_value<bool>(const std::string& str, bool& value)
{
	bool parse_successful = true;
	std::string lower_str = str;

	// clang-format off
	std::transform(lower_str.begin(),
	               lower_str.end(),
	               lower_str.begin(),
	               [](char c){return std::tolower(c);});
	// clang-format on

	if (lower_str == "true")
	{
		value = true;
	}
	else if (lower_str == "false")
	{
		value = false;
	}
	else
	{
		parse_successful = false;
	}

	return parse_successful;
}

#include "type_config.hpp"
