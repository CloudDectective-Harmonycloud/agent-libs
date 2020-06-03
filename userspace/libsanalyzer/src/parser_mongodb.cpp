#include "analyzer_int.h"
#include "parser_mongodb.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sqlparser.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at
// http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

protocol_mongodb* protocol_mongodb::s_protocol_mongodb = new protocol_mongodb();

protocol_mongodb& protocol_mongodb::instance()
{
	return *protocol_mongodb::s_protocol_mongodb;
}

protocol_mongodb::protocol_mongodb()
    : protocol_base(),
      feature_base(MONGODB_STATS,
                   &draiosproto::feature_status::set_mongodb_stats_enabled,
                   {PROTOCOL_STATS})
{
}

bool protocol_mongodb::is_protocol(sinsp_evt* evt,
                                   sinsp_partial_transaction* trinfo,
                                   sinsp_partial_transaction::direction trdir,
                                   const uint8_t* buf,
                                   uint32_t buflen,
                                   uint16_t serverport) const
{
	if (!get_enabled())
	{
		return false;
	}

	if (buflen >= 16 && (*(int32_t*)(buf + 12) == 1 ||
	                     (*(int32_t*)(buf + 12) > 2000 && *(int32_t*)(buf + 12) < 2008)))
	{
		return true;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_mongodb_parser implementation
///////////////////////////////////////////////////////////////////////////////

const uint32_t sinsp_mongodb_parser::commands_size = 11;

const char* sinsp_mongodb_parser::commands[] = {
    "insert",
    "update",
    "aggregate",
    "delete",
    "count",
    "distinct",
    "mapreduce",
    "geonear",
    "geosearch",
    "find",
    "findandmodify",
};

const uint32_t sinsp_mongodb_parser::commands_sizes_map[] = {sizeof("insert"),
                                                             sizeof("update"),
                                                             sizeof("aggregate"),
                                                             sizeof("delete"),
                                                             sizeof("count"),
                                                             sizeof("distinct"),
                                                             sizeof("mapreduce"),
                                                             sizeof("geonear"),
                                                             sizeof("geosearch"),
                                                             sizeof("find"),
                                                             sizeof("findandmodify")};

const sinsp_mongodb_parser::opcode sinsp_mongodb_parser::commands_to_opcode[] = {
    MONGODB_OP_INSERT,
    MONGODB_OP_UPDATE,
    MONGODB_OP_AGGREGATE,
    MONGODB_OP_DELETE,
    MONGODB_OP_COUNT,
    MONGODB_OP_DISTINCT,
    MONGODB_OP_MAP_REDUCE,
    MONGODB_OP_GEO_NEAR,
    MONGODB_OP_GEO_SEARCH,
    MONGODB_OP_FIND,
    MONGODB_OP_FIND_AND_MODIFY,
};

sinsp_mongodb_parser::sinsp_mongodb_parser()
    : m_collection(NULL),
      m_error_code(0),
      m_opcode(MONGODB_OP_NONE),
      m_wireopcode(WIRE_OP_NONE),
      m_parsed(false)
{
}

inline void sinsp_mongodb_parser::reset()
{
	m_parsed = false;
	m_is_valid = false;
	m_is_req_valid = false;
	m_collection = NULL;
	m_collection_storage.clear();
	m_error_code = 0;
	m_opcode = MONGODB_OP_NONE;
	m_wireopcode = WIRE_OP_NONE;
	m_reassembly_buf.clear();
}

sinsp_mongodb_parser::proto sinsp_mongodb_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_MONGODB;
}

sinsp_protocol_parser::msg_type sinsp_mongodb_parser::should_parse(
    sinsp_fdinfo_t* fdinfo,
    sinsp_partial_transaction::direction dir,
    bool is_switched,
    const char* buf,
    uint32_t buflen)
{
	if ((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_IN) ||
	    (fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_OUT))
	{
		if (is_switched)
		{
			reset();
			return sinsp_protocol_parser::MSG_REQUEST;
		}
		else
		{
			if (!m_parsed)
			{
				return sinsp_protocol_parser::MSG_REQUEST;
			}
		}
	}
	else if ((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_OUT) ||
	         (fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_IN))
	{
		if (is_switched)
		{
			m_parsed = false;
			m_reassembly_buf.clear();
			return sinsp_protocol_parser::MSG_RESPONSE;
		}
		else
		{
			if (!m_parsed)
			{
				return sinsp_protocol_parser::MSG_RESPONSE;
			}
		}
	}

	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_mongodb_parser::parse_request(const char* buf, uint32_t buflen)
{
	if (buflen + m_reassembly_buf.get_size() > 16)
	{
		const char* rbuf;
		uint32_t rbuflen;

		//
		// Reconstruct the buffer
		//
		if (m_reassembly_buf.get_size() == 0)
		{
			rbuf = buf;
			rbuflen = buflen;
		}
		else
		{
			m_reassembly_buf.copy(buf, buflen);
			rbuf = m_reassembly_buf.get_buf();
			rbuflen = m_reassembly_buf.get_size();
		}
		m_wireopcode = (wire_opcode)(*(int32_t*)(rbuf + 12));
		//
		// Do the parsing
		//
		switch (m_wireopcode)
		{
		case WIRE_OP_QUERY:
		{
			// Extract collection name
			if (rbuflen > 49)
			{
				const char* start_collection = rbuf + 20;
				for (unsigned int j = 0; j < rbuflen - 20; ++j)
				{
					if (*start_collection == '.')
					{
						++start_collection;
						break;
					}
					++start_collection;
				}
				if (*(uint32_t*)(start_collection) == *(uint32_t*)"$cmd")
				{
					const char* doc = start_collection + 5 + 8;
					// In this case document is:
					// |size(int32_t)|0x02|insert|0|size(int32_t)|collection|0|
					// bytes
					// |    4        |  1 | var  |1|     4       | var      |1|

					// Extract command
					uint32_t command = *(uint32_t*)(doc + 5) | 0x20202020;
					for (unsigned int j = 0; j < commands_size; ++j)
					{
						if (command == *(uint32_t*)(commands[j]))
						{
							// Discern if it's find or findandmodify, right now it's the
							// only clash, otherwise we'll need a better approach
							if (j == 9 &&
							    (*(uint32_t*)(doc + 5 + 4) | 0x20202020) == *(uint32_t*)"andm")
							{
								continue;
							}
							m_opcode = commands_to_opcode[j];
							start_collection = doc + 5 + commands_sizes_map[j] + 4;
							m_collection = m_collection_storage.copy(start_collection, rbuflen, 1);
							m_parsed = true;
							m_is_req_valid = true;
							break;
						}
					}
				}
				else
				{
					m_opcode = MONGODB_OP_FIND;
					m_collection = m_collection_storage.copy(start_collection, rbuflen, 1);
					m_parsed = true;
					m_is_req_valid = true;
				}
			}
			else
			{
				// in this case wait a little more if some more data arrives
				if (m_reassembly_buf.get_size() == 0)
				{
					m_reassembly_buf.copy(buf, buflen);
				}
				return true;
			}
			break;
		}
		case WIRE_OP_GET_MORE:
		{
			m_opcode = MONGODB_OP_GET_MORE;
			// Extract collection name
			if (rbuflen >= 20)
			{
				const char* start_collection = rbuf + 20;
				for (unsigned int j = 0; j < rbuflen - 20; ++j)
				{
					if (*start_collection == '.')
					{
						++start_collection;
						break;
					}
					++start_collection;
				}
				m_collection = m_collection_storage.copy(start_collection, buflen, 1);
			}
			m_parsed = true;
			m_is_req_valid = true;
			break;
		}
		default:
			break;
		}

		m_reassembly_buf.clear();
	}
	else
	{
		m_reassembly_buf.copy(buf, buflen);
	}
	return true;
}

bool sinsp_mongodb_parser::parse_response(const char* buf, uint32_t buflen)
{
	if (buflen + m_reassembly_buf.get_size() >= 16)
	{
		const char* rbuf;
		uint32_t rbuflen;

		//
		// Reconstruct the buffer
		//
		if (m_reassembly_buf.get_size() == 0)
		{
			rbuf = buf;
			rbuflen = buflen;
		}
		else
		{
			m_reassembly_buf.copy(buf, buflen);
			rbuf = m_reassembly_buf.get_buf();
			rbuflen = m_reassembly_buf.get_size();
		}

		int32_t* opcode = (int32_t*)(rbuf + 12);

		if (*opcode == WIRE_OP_REPLY)
		{
			if (rbuflen == 16)
			{
				if (m_reassembly_buf.get_size() == 0)
				{
					m_reassembly_buf.copy(buf, buflen);
				}
				return true;
			}
			int32_t* response_flags = (int32_t*)(rbuf + 16);
			if (*response_flags & 0x2)
			{
				m_error_code = 1;
			}
			if (m_opcode == MONGODB_OP_INSERT || m_opcode == MONGODB_OP_DELETE ||
			    m_opcode == MONGODB_OP_UPDATE)
			{
				if (rbuflen >= (16 + 4 + 8 + 4 + 4 + 4 + 1 + 2 + 1 + 4 + 1 + 2 + 1 + 4))
				{
					// clang-format off
					// Look for "n" field,
					// |16bytes header|responseFlags(int32)|cursorid(int64)|startingFrom(int32)|numberReturned(int32)|document
					// | 16  | 4 | 8 | 4 | 4 |
					// document (insert and delete):
					// |size(int32)|0x10|ok|0|int32|0x10|n|0|nvalue|
					// | 4         | 1  |2 |1|   4 |  1 |1|1|
					// document (update):
					// |size(int32)|0x10|ok|0|int32|0x10|nModified|0|nvalue|
					// | 4         | 1  |2 |1|   4 |  1 |9|1|
					// clang-format on
					uint32_t nshift = 1;
					if (m_opcode == MONGODB_OP_UPDATE)
					{
						nshift = 9;
					}
					int32_t ok = *(int32_t*)(rbuf + 16 + 4 + 8 + 4 + 4 + 4 + 1 + 2 + 1);
					int32_t n =
					    *(int32_t*)(rbuf + 16 + 4 + 8 + 4 + 4 + 4 + 1 + 2 + 1 + 4 + 1 + nshift + 1);
					if (ok == 0 || n == 0)
					{
						m_error_code = 1;  // Right now is like a boolean
					}
					else
					{
						m_error_code = 0;
					}
				}
				else
				{
					if (m_reassembly_buf.get_size() == 0)
					{
						m_reassembly_buf.copy(buf, buflen);
					}
					return true;
				}
			}
			m_parsed = true;
			m_is_valid = true;
		}
	}

	return true;
}
