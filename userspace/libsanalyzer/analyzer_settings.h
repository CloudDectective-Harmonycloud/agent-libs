//
// The analyzer emit interval
//
#define ANALYZER_SAMPLE_LENGTH_NS 1000000000

//
// The transaction delays update interval
//
#define TRANSACTION_DELAYS_INTERVAL_NS (5 * ONE_SECOND_IN_NS)

//
// If this is defined, the analyzer will include thread information inside
// the protocol buffers that it sends to the agent
//
#undef ANALYZER_EMITS_THREADS

//
// If this is defined, the analyzer will include process information inside
// the protocol buffers that it sends to the agent
//
#define ANALYZER_EMITS_PROCESSES

//
// If this is defined, the analyzer will include program information inside
// the protocol buffers that it sends to the agent
//
#define ANALYZER_EMITS_PROGRAMS

//
// The min and max size for the memory buffer used as a target for protobuf 
// serialization. Min is the starting value, while max is the growth limit.
// This imposes a limit to the number of bytes that can be sent out by
// the agent.
//
#define MIN_SERIALIZATION_BUF_SIZE_BYTES 128
#define MAX_SERIALIZATION_BUF_SIZE_BYTES 32000000

//
// The time after which a connection is considered stale and is removed from 
// the connection table.
//
#define DEFAULT_CONNECTION_TIMEOUT_SEC 90

//
// Max size that the connection table can reach
//
#define MAX_CONNECTION_TABLE_SIZE 65536

//
// Max number of connections that can go in a sample that is sent to the backend.
// 0 means no limit.
// This can be ovverridden through sinsp_configuration::set_max_connections_in_proto().
//
#define DEFAULT_MAX_CONNECTIONS_IN_PROTO 100

//
// If this is set, all the connections *coming* from the external world
// are aggreagated into a single connection in the protocol samples.
// This can be overridden by set_aggregate_connections_in_proto().
//
#define AGGREGATE_CONNECTIONS_IN_PROTO true

//
// Transaction constants
//
#define TRANSACTION_TIMEOUT_NS 100000000
#define TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS 2
#define TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS (3 * ONE_SECOND_IN_NS)

//
// Process health score calculation constants
//
#define MAX_HEALTH_CONCURRENCY 16
#define CONCURRENCY_OBSERVATION_INTERVAL_NS 1000000

//
// When returning the top error codes for a host or a process,
// this is the max number of entries in the list.
//
#define MAX_N_ERROR_CODES_IN_PROTO 5

//
// Protocol header constants
//
#define PROTOCOL_VERSION_NUMBER 1
#define PROTOCOL_MESSAGE_TYPE_NUMBER 1

//
// Number of samples after which the process information *of every process* is included in the sample.
// Usually, the sample includes only process information for processes that have been created
// during the sample or that did an execve during the sample.
// Every once in a while, tough, we force the inclusion of every process, to make sure the backend stays
// in sync.
// This constant controls after how many normal samples we include a "full process" sample.
//
#define PROCINFO_IN_SAMPLE_INTERVAL 1

//
// Maximum numeber of external TCP/UDP client endpoints that are reported independently.
// If the number goes beyond this treshold, the clients will be aggregated into a single
// 0.0.0.0 endpoint.
//
#define MAX_N_EXTERNAL_CLIENTS 30

//
// FD class customized with the storage we need
//
#include "tuples.h"
#include "transactinfo.h"
class sinsp_partial_transaction;
template<class T> class sinsp_fdinfo;
typedef sinsp_fdinfo<sinsp_partial_transaction> sinsp_fdinfo_t;
