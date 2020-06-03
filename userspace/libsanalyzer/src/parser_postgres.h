///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at
// http://dev.postgres.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma once
#include "feature_manager.h"
#include "protocol_manager.h"
#include "sqlparser.h"

class protocol_postgres : public protocol_base, public feature_base
{
private:
    static protocol_postgres* s_protocol_postgres;

public:
    protocol_postgres();

    static protocol_postgres& instance();

    bool is_protocol(sinsp_evt* evt,
                     sinsp_partial_transaction* trinfo,
                     sinsp_partial_transaction::direction trdir,
                     const uint8_t* buf,
                     uint32_t buflen,
                     uint16_t serverport) const override;
};

///////////////////////////////////////////////////////////////////////////////
// POSTGRES parser
///////////////////////////////////////////////////////////////////////////////

class sinsp_postgres_parser : public sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MT_NONE = 0,
		MT_LOGIN,
		MT_QUERY,
	};

	sinsp_postgres_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo,
	                                             sinsp_partial_transaction::direction dir,
	                                             bool is_switched,
	                                             const char* buf,
	                                             uint32_t buflen);
	bool parse_request(const char* buf, uint32_t buflen);
	bool parse_response(const char* buf, uint32_t buflen);
	proto get_type();

	char* m_query;

private:
	inline void reset();

	sinsp_autobuffer m_reassembly_buf;
	bool m_parsed;
	sinsp_autobuffer m_storage;

	msg_type m_msgtype;
	char* m_database;
	char* m_statement;
	char* m_error_message;
	uint16_t m_error_code;

	sinsp_sql_parser m_query_parser;

	friend class sinsp_protostate;
	friend class sql_state;
};
