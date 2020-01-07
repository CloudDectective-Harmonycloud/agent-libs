#include "label_limits.h"

label_limits::label_limits(const filter_vec_t& filters,
			   uint32_t max_entries,
			   uint64_t expire_seconds)
	: user_configured_limits(filters,
				 "Labels",
				 log_flags<label_limits>::m_log,
				 log_flags<label_limits>::m_enable_log,
				 log_flags<label_limits>::m_last,
				 log_flags<label_limits>::m_running,
				 max_entries,
				 expire_seconds)
{
}

void label_limits::sanitize_filters()
{
}


INITIALIZE_LOG(label_limits);


