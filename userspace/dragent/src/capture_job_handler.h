#pragma once

// capture_job_handler is responsible for half of the work related to
//   sysdig captures, specifically:
//  - When there's a new memdump job, copying the in-memory buffer to
//    a file on disk and applying that job's filter.
//  - Transmitting complete capture files to the collector.
//

// This class (which should run in its own thread) coordinates with
// the event handling in the sinsp_worker thread, namely copying
// events to the in-memory buffer as well as the various files for
// active dump jobs.

#include <memory>
#include <atomic>

#include "Poco/RWLock.h"

#include "sinsp.h"

#include "memdumper.h"

#include "configuration.h"
#include "event_source.h"
#include "infra_event_sink.h"
#include "protocol.h"
#include "running_state_runnable.h"
#include "dragent_message_queues.h"
#include "thread_safe_container/blocking_queue.h"

// Generic interface to allow queuing of capture job requests
class capture_job_queue_handler
{
public:

	public:

	class start_job_details
	{
	public:
		start_job_details():
			m_duration_ns(0),
			m_max_size(0),
			m_past_duration_ns(0),
			m_past_size(0),
			m_notification_pid(0),
			m_defer_send(false),
			m_start_ns(0),
			m_send_initial_keepalive(true),
			m_delete_file_when_done(true),
			m_send_file(true),
			m_dumper(NULL)
		{
		}

		uint64_t m_duration_ns;
		uint64_t m_max_size;
		uint64_t m_past_duration_ns;
		uint64_t m_past_size;
		std::string m_notification_desc;
		uint64_t m_notification_pid;

		// If true, none of the capture file will be sent
		// until a later JOB_SEND_START message is
		// received.
		bool m_defer_send;

		// Start the capture as close as possible to this
		// time. If 0 will use current time.
		uint64_t m_start_ns;

		// If true, send a keepalive message immediately.
		bool m_send_initial_keepalive;

		std::string m_filter;
		bool m_delete_file_when_done;
		bool m_send_file;
		std::string m_file;
		sinsp_dumper *m_dumper;
	};

	class stop_job_details
	{
	public:
		bool m_remove_unsent_job;
	};

	class dump_job_request
	{
	public:
		enum request_type {
			JOB_START,
			JOB_STOP,
			JOB_SEND_START
		};

		static std::string request_type_str(request_type &type)
		{
			switch(type)
			{
			case JOB_START :
				return std::string("start");
				break;
			case JOB_STOP :
				return std::string("stop");
				break;
			case JOB_SEND_START :
				return std::string("send_start");
				break;
			default:
				return std::string("unknown");
				break;
			}
		}

		dump_job_request() {};

		std::string m_token;
		request_type m_request_type;

		// Only valid when type == JOB_START
		std::unique_ptr<start_job_details> m_start_details;

		// Only valid when type == JOB_STOP
		std::unique_ptr<stop_job_details> m_stop_details;
	};

	virtual bool queue_job_request(sinsp *inspector,
	                               std::shared_ptr<dump_job_request> job_request,
	                               std::string &errstr) = 0;
};

class capture_job;
class capture_job_handler : public dragent::running_state_runnable,
                            public dragent::infra_event_sink,
                            public capture_job_queue_handler,
                            public event_listener
{
public:
	friend class capture_job;

	capture_job_handler(dragent_configuration *configuration,
			    protocol_queue *queue);

	virtual ~capture_job_handler();

	// Must be called after the configuration has been loaded and before run()
	void init(const sinsp *inspector);

	// Run forever, handling dump requests and sending them when
	// they're complete.
	void do_run() override;

	// Incorporate this event into any relevant dump files. This
	// is called from a separate thread from the thread that
	// called run().
	void process_event(sinsp_evt *evt) override;

	// Schedule a new capture job. This is called from a separate
	// thread that called run(). Returns true if the request was
	// successfully saved, false and fills in errstr
	// otherwise. Even when returning true, the capture job might
	// return an error later. In that case, an error message will
	// be sent to the connection manager's queue.
	bool queue_job_request(sinsp *inspector,
	                       std::shared_ptr<dump_job_request> job_request,
	                       std::string &errstr) final;

	// Change the chunk size used for event captures. This is only
	// used for testing.
	void set_dump_chunk_size(uint64_t size)
	{
		m_max_chunk_size = size;
	}

	// Get the last time at which this thread checked for job requests
	uint64_t get_last_job_check_ns()
	{
		return m_last_job_check_ns;
	}

	inline Poco::RWLock &jobs_lock()
	{
		return m_jobs_lock;
	}

	void send_error(const std::string& token, const std::string& error);

	// Inject a notification event into the event stream (at least
	// the part that's visible by capture jobs). This will make
	// sure it's present in the memdump buffer and any active
	// capture jobs. It will not be handled by the analyzer or
	// sinsp_worker.
	void push_notification(uint64_t ts, uint64_t tid, std::string id, std::string description);
	void push_infra_event(uint64_t ts,
	                      uint64_t tid,
	                      const std::string& source,
	                      const std::string& name,
	                      const std::string& description,
	                      const std::string& scope) override;

	int64_t m_sysdig_pid;

	// Mutex that protects access to the end of the active memdump buffer
	Poco::Mutex m_membuf_mtx;
	std::unique_ptr<sinsp_memory_dumper> m_memdumper;

	// Only used in unit tests to force a faster shutdown.
	bool m_force_cleanup = false;

	// Returns whether a job is in progress or not
	bool get_job_in_progress() const
	{
		return m_job_in_progress;
	}

private:
	// Clean up all jobs
	void cleanup();

	static const std::string m_name;

	void process_job_requests();
	void start_job(std::string &token,
		       const start_job_details& request);

	void add_job(std::shared_ptr<capture_job> &job);

	void flush_jobs(uint64_t ts);

	void cleanup_jobs(uint64_t ts);

	bool can_send(uint32_t buffer_size, uint64_t ts_ns);

	void prepare_response(const std::string& token, draiosproto::dump_response* response);
	std::shared_ptr<serialized_buffer> dump_response_to_queue_item(const draiosproto::dump_response& response);
	bool queue_item(std::shared_ptr<serialized_buffer> &item, protocol_queue::item_priority priority);
	bool queue_response(const draiosproto::dump_response& response, protocol_queue::item_priority priority);

	static const uint64_t default_max_chunk_size;
	static const uint64_t m_keepalive_interval_ns;

	pid_t m_sysdig_sid;
	run_on_interval m_log_stats_interval;

	// The sinsp_worker's inspector. Only used to compile filters when creating jobs.
	sinsp *m_inspector;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	uint64_t m_max_chunk_size;
	thread_safe_container::blocking_queue<std::shared_ptr<dump_job_request>> m_dump_job_requests;

	// Mutex that protects access to the list of jobs
	Poco::RWLock m_jobs_lock;

	std::vector<std::shared_ptr<capture_job>> m_jobs;
	token_bucket m_sysdig_captures_tb;
	std::atomic<uint64_t> m_last_job_check_ns;
	std::atomic<uint64_t> m_last_event_ns;

	sinsp_evt m_notification_evt;
	uint8_t m_notification_scap_evt_storage[4096];
	scap_evt* m_notification_scap_evt;

	std::atomic<bool> m_job_in_progress;
};

