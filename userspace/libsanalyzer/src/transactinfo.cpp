#include <algorithm>

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#define VISIBILITY_PRIVATE

#include "analyzer.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "connectinfo.h"
#include "parser_http.h"
#include "sinsp.h"
#include "sinsp_int.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_transact_table implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_transaction_table::sinsp_transaction_table(sinsp_analyzer& analyzer)
    : m_n_client_transactions(0),
      m_n_server_transactions(0),
      m_analyzer(analyzer)
{
}

sinsp_transaction_table::~sinsp_transaction_table() {}

bool sinsp_transaction_table::is_transaction_server(thread_analyzer_info* ptinfo)
{
	if (ptinfo->m_transaction_metrics.get_counter()->m_count_in >=
	        TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS &&
	    ptinfo->m_transaction_metrics.get_counter()->m_time_ns_in /
	            ptinfo->m_transaction_metrics.get_counter()->m_count_in <
	        TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_transaction_table::emit(thread_analyzer_info* ptinfo,
                                   void* fdinfo,
                                   sinsp_connection* pconn,
                                   sinsp_partial_transaction* tr
#if _DEBUG
                                   ,
                                   sinsp_evt* evt,
                                   uint64_t fd,
                                   uint64_t ts
#endif
)
{
	std::unordered_map<int64_t, std::vector<sinsp_transaction> >::iterator it;

	sinsp_partial_transaction::direction startdir;
	sinsp_partial_transaction::direction enddir;

	sinsp_fdinfo_t* ffdinfo = (sinsp_fdinfo_t*)fdinfo;

	//
	// Detect the side and and determine the trigger directions
	//
	ASSERT(ffdinfo->is_role_server() || ffdinfo->is_role_client());
	if (ffdinfo->is_role_server())
	{
		startdir = sinsp_partial_transaction::DIR_IN;
		enddir = sinsp_partial_transaction::DIR_OUT;
	}
	else
	{
		startdir = sinsp_partial_transaction::DIR_OUT;
		enddir = sinsp_partial_transaction::DIR_IN;
	}

	//
	// Based on the direction, add the transaction
	//
	if (tr->m_prev_direction == startdir)
	{
		tr->m_prev_prev_start_time = tr->m_prev_start_time;
		tr->m_prev_prev_end_time = tr->m_prev_end_time;
		tr->m_prev_prev_start_of_transaction_time = tr->m_prev_start_of_transaction_time;
	}
	// Emit transaction only if protoparser is null or if it has parsed a valid protocol
	// right now apply protocol validation also on TLS. Because in case of subsampling
	// protocol parsing may fail for other protocols and return wrong result. On TLS instead
	// a strict protocol parsing is needed
	else if ((tr->m_protoparser == nullptr ||
	          tr->m_protoparser->get_type() != sinsp_protocol_parser::PROTO_TLS ||
	          (tr->m_protoparser->get_type() == sinsp_protocol_parser::PROTO_TLS &&
	           tr->m_protoparser->m_is_valid)) &&
	         (tr->m_prev_direction == enddir ||
	          tr->m_prev_direction == sinsp_partial_transaction::DIR_CLOSE))
	{
		if (tr->m_prev_prev_start_time == 0)
		{
			//
			// This can happen if we drop events or if a connection
			// starts with a write, which can happen with fucked up protocols
			// like the mysql one
			//
			return;
		}

		//
		// Update the metrics related to this transaction
		//
		ASSERT(ptinfo != NULL);
		ASSERT(tr->m_prev_end_time > tr->m_prev_prev_start_of_transaction_time);

		uint64_t delta = tr->m_prev_end_time - tr->m_prev_prev_start_of_transaction_time;

		if (ffdinfo->is_role_server())
		{
			bool isexternal = pconn->is_server_only();
			m_n_server_transactions++;

			if (ffdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				if (isexternal)
				{
					ptinfo->m_th_analysis_flags |=
					    thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER;
				}
				else
				{
					ptinfo->m_th_analysis_flags |=
					    thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER;
				}
			}
			else if (ffdinfo->m_type == SCAP_FD_UNIX_SOCK)
			{
				ptinfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_UNIX_SERVER;
			}
			else
			{
				ASSERT(false);
			}

			ptinfo->m_transaction_metrics.add_in(1, delta);
			pconn->m_transaction_metrics.add_in(1, delta);

			if (isexternal)
			{
				ptinfo->m_external_transaction_metrics.add_in(1, delta);
			}

			ptinfo->add_completed_server_transaction(tr, isexternal);

			if (tr->m_protoparser != NULL)
			{
				ptinfo->main_thread_ainfo()->m_protostate.update(
				    tr,
				    delta,
				    true,
				    m_analyzer.m_configuration->get_protocols_truncation_size());
			}
		}
		else
		{
			bool isexternal = pconn->is_client_only();
			m_n_client_transactions++;

			if (ffdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				if (isexternal)
				{
					ptinfo->m_th_analysis_flags |=
					    thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT;
				}
				else
				{
					ptinfo->m_th_analysis_flags |=
					    thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT;
				}
			}
			else if (ffdinfo->m_type == SCAP_FD_UNIX_SOCK)
			{
				ptinfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_UNIX_CLIENT;
			}
			else
			{
				ASSERT(false);
			}

			ptinfo->m_transaction_metrics.add_out(1, delta);
			pconn->m_transaction_metrics.add_out(1, delta);

			if (isexternal)
			{
				ptinfo->m_external_transaction_metrics.add_out(1, delta);
			}

			ptinfo->add_completed_client_transaction(tr, isexternal);

			if (tr->m_protoparser != NULL)
			{
				ptinfo->main_thread_ainfo()->m_protostate.update(
				    tr,
				    delta,
				    false,
				    m_analyzer.m_configuration->get_protocols_truncation_size());
			}
		}

		// Mark the transaction as done
		tr->m_prev_prev_start_time = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_transactinfo implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_partial_transaction::sinsp_partial_transaction()
{
	m_protoparser = nullptr;
	m_type = TYPE_UNKNOWN;
	reset();
}

void sinsp_partial_transaction::reset()
{
	m_direction = DIR_UNKNOWN;
	m_start_time = 0;
	m_end_time = 0;
	m_prev_direction = DIR_UNKNOWN;
	m_prev_start_time = 0;
	m_prev_end_time = 0;
	m_prev_prev_start_time = 0;
	m_prev_prev_end_time = 0;
	m_cpuid = -1;
	m_start_of_transaction_time = 0;
	m_prev_start_of_transaction_time = 0;
	m_prev_prev_start_of_transaction_time = 0;
	m_is_active = false;
	m_n_direction_switches = 0;
	m_prev_bytes_in = 0;
	m_prev_bytes_out = 0;
}

sinsp_partial_transaction::~sinsp_partial_transaction()
{
	if (m_protoparser)
	{
		delete m_protoparser;
		m_protoparser = nullptr;
	}
}

sinsp_partial_transaction::sinsp_partial_transaction(const sinsp_partial_transaction& other)
{
	*this = other;

	m_protoparser = nullptr;
	m_reassembly_buffer.reset();
}

inline sinsp_partial_transaction::updatestate sinsp_partial_transaction::update_int(
    thread_analyzer_info* ptinfo,
    uint64_t enter_ts,
    uint64_t exit_ts,
    direction dir,
    char* data,
    uint32_t original_len,
    uint32_t len,
    bool is_server)
{
	if (dir == DIR_IN)
	{
		m_bytes_in += len;

		if (m_direction != DIR_IN)
		{
			updatestate res;

			if (m_direction == DIR_UNKNOWN)
			{
				res = STATE_SWITCHED;
				m_bytes_in = len;
			}
			else
			{
				m_prev_direction = m_direction;
				m_prev_start_time = m_start_time;
				m_prev_end_time = m_end_time;
				m_prev_bytes_in = m_bytes_in - len;
				m_prev_bytes_out = m_bytes_out;
				m_bytes_in = len;
				m_prev_start_of_transaction_time = m_start_of_transaction_time;
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if (len != 0)
			{
				m_direction = dir;

				if (m_bytes_in == len)
				{
					m_start_of_transaction_time = exit_ts;
				}
			}
			else
			{
				m_direction = DIR_UNKNOWN;
			}

			return res;
		}
		else
		{
			ASSERT(exit_ts >= m_end_time);

			if (is_server)
			{
				if (exit_ts - m_end_time > TRANSACTION_READ_LIMIT_NS)
				{
					//
					// This server-side transaction has stopped on a read for
					// a long time. We assume it's not a client server transaction
					// (it could be an upload or a peer to peer application)
					// and we drop it.
					//
					return STATE_NO_TRANSACTION;
				}
			}

			m_end_time = exit_ts;
			return STATE_ONGOING;
		}
	}
	else if (dir == DIR_OUT)
	{
		m_bytes_out += len;

		if (m_direction != DIR_OUT)
		{
			updatestate res;

			if (m_direction == DIR_UNKNOWN)
			{
				res = STATE_SWITCHED;
				m_bytes_out = len;
			}
			else
			{
				m_prev_direction = m_direction;
				m_prev_start_time = m_start_time;
				m_prev_end_time = m_end_time;
				m_prev_bytes_in = m_bytes_in;
				m_prev_bytes_out = m_bytes_out - len;
				m_bytes_out = len;
				m_prev_start_of_transaction_time = m_start_of_transaction_time;
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if (len != 0)
			{
				m_direction = dir;

				if (m_bytes_out == len)
				{
					m_start_of_transaction_time = exit_ts;
				}
			}
			else
			{
				m_direction = DIR_UNKNOWN;
			}

			return res;
		}
		else
		{
			ASSERT(exit_ts >= m_end_time);

			if (!is_server)
			{
				if (exit_ts - m_end_time > TRANSACTION_READ_LIMIT_NS)
				{
					//
					// This client-side transaction has stopped on a write for
					// a long time. We assume it's not a client server transaction
					// (it could be an upload or a peer to peer application)
					// and we drop it.
					//
					return STATE_NO_TRANSACTION;
				}
			}

			m_end_time = exit_ts;
			return STATE_ONGOING;
		}
	}
	else if (dir == DIR_CLOSE)
	{
		m_prev_direction = m_direction;
		m_prev_start_time = m_start_time;
		m_prev_end_time = m_end_time;
		m_prev_start_of_transaction_time = m_start_of_transaction_time;
		m_prev_bytes_in = m_bytes_in;
		m_prev_bytes_out = m_bytes_out;

		m_direction = DIR_UNKNOWN;
		return STATE_SWITCHED;
	}
	else
	{
		ASSERT(false);
		return STATE_ONGOING;
	}
}

void sinsp_partial_transaction::update(sinsp_analyzer* analyzer,
                                       thread_analyzer_info* ptinfo,
                                       void* fdinfo,
                                       sinsp_connection* pconn,
                                       uint64_t enter_ts,
                                       uint64_t exit_ts,
                                       int32_t cpuid,
                                       direction dir,
#if _DEBUG
                                       sinsp_evt* evt,
                                       uint64_t fd,
#endif
                                       char* data,
                                       uint32_t original_len,
                                       uint32_t len)
{
	if (pconn == NULL)
	{
		mark_inactive();
		return;
	}

	if (cpuid != -1)
	{
		m_cpuid = cpuid;
	}

	sinsp_fdinfo_t* ffdinfo = (sinsp_fdinfo_t*)fdinfo;

	sinsp_partial_transaction::updatestate res = update_int(ptinfo,
	                                                        enter_ts,
	                                                        exit_ts,
	                                                        dir,
	                                                        data,
	                                                        len,
	                                                        original_len,
	                                                        ffdinfo->is_role_server());
	if (res == STATE_SWITCHED)
	{
		m_tid = ptinfo->m_tid;
		m_n_direction_switches++;

		analyzer->m_trans_table->emit(ptinfo,
		                              fdinfo,
		                              pconn,
		                              this
#if _DEBUG
		                              ,
		                              evt,
		                              fd,
		                              exit_ts
#endif
		);

		if (dir == DIR_CLOSE)
		{
			m_prev_direction = DIR_UNKNOWN;
		}
	}
	else if (res == STATE_NO_TRANSACTION)
	{
		reset();
		return;
	}

	if (m_protoparser && len)
	{
		sinsp_protocol_parser::msg_type mtype =
		    m_protoparser->should_parse(ffdinfo, dir, res == STATE_SWITCHED, data, len);

		if (sinsp_protocol_parser::MSG_REQUEST == mtype)
		{
			if (m_protoparser->parse_request(data, len))
			{
				//
				// This is related to measuring transaction resources, and is not
				// implemented yet.
				//
				// ptinfo->m_ainfo->m_transactions_in_progress.push_back(this);
			}
		}
		else if (sinsp_protocol_parser::MSG_RESPONSE == mtype)
		{
			if (m_protoparser->m_is_req_valid)
			{
				m_protoparser->parse_response(data, len);
			}
		}
	}
}

void sinsp_partial_transaction::mark_active_and_reset(sinsp_partial_transaction::type newtype)
{
	m_type = newtype;
	m_bytes_in = 0;
	m_bytes_out = 0;
	m_prev_bytes_in = 0;
	m_prev_bytes_out = 0;
	m_is_active = true;
}

void sinsp_partial_transaction::mark_inactive()
{
	m_is_active = false;
}
