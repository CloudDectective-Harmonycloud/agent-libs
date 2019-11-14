#include <sys/types.h>
#include <sys/socket.h>
#include <sys/quota.h>

#include <memory>
#include <map>
#include <fstream>

#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>

#include <gtest.h>

#include <sinsp.h>
#include <scap.h>

#include <sinsp_worker.h>
#include <configuration.h>
#include <protocol.h>

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <metrics.h>
#include <thread>

#include "docker_utils.h"
#include "security_config.h"

using namespace std;
namespace security_config = libsanalyzer::security_config;

class test_helper
{
public:
        static bool send_all(internal_metrics& im,
                             draiosproto::statsd_info* statsd_info)
        {
                return im.send_all(statsd_info);
        }
};

class security_policy_error_handler : public Poco::ErrorHandler
{
public:
	security_policy_error_handler() {};

	void exception(const Poco::Exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got Poco::Exception " << exc.displayText();
	}

	void exception(const std::exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got std::exception " << exc.what();
	}

	void exception() {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got unknown exception";
	}
};

// Performs a role similar to sinsp_worker, but much simpler. Only
// contains the inspector loop, security_mgr, and a sinsp_data_handler
// to accept policy events.
namespace {
uncompressed_sample_handler_dummy g_sample_handler;
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_handler;

class test_sinsp_worker : public Runnable
{
public:
	test_sinsp_worker(sinsp *inspector,
			  security_mgr *mgr,
			  bool load_v1_policies,
			  std::string baselines_file,
			  std::string policies_file)
		: m_ready(false),
		  m_mgr(mgr),
		  m_inspector(inspector),
		  m_load_v1_policies(load_v1_policies),
		  m_baselines_file(baselines_file),
		  m_policies_file(policies_file),
		  m_policies_loaded(false)
	{
		m_inspector->set_log_callback(common_logger::sinsp_logger_callback);
		m_inspector->start_dropping_mode(1);
	}

	~test_sinsp_worker()
	{
		m_inspector->set_log_callback(0);
	}

	void run()
	{
		g_log->information("test_sinsp_worker: Starting");

		while(!dragent_configuration::m_terminate)
		{
			int32_t res;
			sinsp_evt* ev;

			res = m_inspector->next(&ev);

			if(res == SCAP_TIMEOUT)
			{
				continue;
			}
			else if(res == SCAP_EOF)
			{
				break;
			}
			else if(res != SCAP_SUCCESS)
			{
				cerr << "res = " << res << endl;
				throw sinsp_exception(m_inspector->getlasterr().c_str());
			}

			// At this point infra state has been initialized with
			// host information, so we can load policies.
			if(!m_policies_loaded)
			{
				std::string errstr;
				if(m_load_v1_policies)
				{
					ASSERT_TRUE(m_mgr->load_baselines_file(m_baselines_file.c_str(), errstr))
						<< "Could not load security baselines file: " + errstr;
					ASSERT_TRUE(m_mgr->load_policies_file(m_policies_file.c_str(), errstr))
						<< "Could not load v1 security policies file: " + errstr;
				}
				else
				{
					ASSERT_TRUE(m_mgr->load_policies_v2_file(m_policies_file.c_str(), errstr))
						<< "Could not load v2 security policies file: " + errstr;
				}
				m_policies_loaded = true;
			}

			m_mgr->process_event(ev);

			if(!m_ready)
			{
				g_log->information("test_sinsp_worker: ready");
				string filter = "(proc.name = tests or proc.aname = tests) or container.name in (sec_ut, fs-root-image, blacklisted_image, non_alpine, busybox_some_tag, baseline-test, denyme, inout_test, fs_usecase, mycurl, overlap_test, helloworld) or container.image = swarm_service_ut_image:latest";
				m_inspector->set_filter(filter.c_str());
				m_ready = true;
			}
		}

		scap_stats st;
		m_inspector->get_capture_stats(&st);

		g_log->information("sinsp_worker: Terminating. events=" + to_string(st.n_evts) + " dropped=" + to_string(st.n_drops + st.n_drops_buffer));
	}

	atomic<bool> m_ready;
private:
	security_mgr *m_mgr;
	sinsp *m_inspector;
	bool m_load_v1_policies;
	std::string m_baselines_file;
	std::string m_policies_file;
	bool m_policies_loaded;
};
}

bool check_output_fields(map<string,string> &received, map<string,string> &expected)
{
	// the following fields *may* be unknown in the unit tests, so if they aren't in the expected set
	// they are removed before the check
	std::set<string> unknowns = {"container.id", "proc.name", "proc.cmdline", "fd.cip", "fd.sip", "fd.cport"};
	for(const auto &u : unknowns)
	{
		if(expected.find(u) == expected.end())
		{
			received.erase(u);
		}
	}

	// in recent versions, glibc open use openat
	if(received.find("evt.type") != received.end() && received["evt.type"] == "openat" &&
	   expected.find("evt.type") != expected.end() && expected["evt.type"] == "open")
	{
		received["evt.type"] = "open";
	}

	return received.size() == expected.size()
		&& std::equal(received.begin(), received.end(),
			      expected.begin());
}

std::ostream &operator<<(std::ostream &os, const map<string, string> &map)
{
	os << "[";

	for(auto &pair : map)
	{
		os << "(" << pair.first << "," << pair.second <<  ") ";
	}

	os << "]";

	return os;
}

class security_policies_test : public testing::Test
{
	// With the 10k packet size and our relatively slow
	// reading of responses, we need a bigger than normal
	// queue length.
	const uint32_t DEFAULT_QUEUE_LEN = 1000;
public:
	/* path to the cointerface unix socket domain */
	security_policies_test() :
	    m_flush_queue(DEFAULT_QUEUE_LEN),
	    m_transmit_queue(DEFAULT_QUEUE_LEN),
	    m_data_handler(m_transmit_queue),
	    m_mgr("./resources", m_data_handler)
	{
	}


protected:

	virtual std::string policies_file()
	{
		return string("./resources/security_policies_messages/all_policy_v2_types.txt");
	}

	void SetUpTest(bool delayed_reports=false)
	{
		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL, false);
		dragent_configuration::m_terminate = false;

		m_configuration.m_capture_dragent_events  = true;
		m_configuration.m_memdump_enabled = false;
		security_config::set_enabled(true);
		m_configuration.m_max_sysdig_captures = 10;
		m_configuration.m_autodrop_enabled = false;
		security_config::set_policies_file("./resources/security_policies_messages/all_policy_types.txt");
		security_config::set_baselines_file("./resources/security_policies_messages/baseline.txt");
		security_config::set_policies_v2_file(policies_file());
		m_configuration.m_falco_engine_sampling_multiplier = 0;
		m_configuration.m_containers_labels_max_len = 100;
		if(delayed_reports)
		{
			security_config::set_throttled_report_interval_ns(1000000000);
			security_config::set_report_interval_ns(15000000000);
		}

		// The (global) logger only needs to be set up once
		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));

			// To enable debug logging, change the tailing -1 to Message::Priority::PRIO_DEBUG
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new Poco::NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = std::unique_ptr<common_logger>(new common_logger(&nullc, &loggerc));
		}

		m_inspector = new sinsp();
		m_internal_metrics = std::make_shared<internal_metrics>();
		m_analyzer = new sinsp_analyzer(m_inspector,
		                                "/opt/draios",
		                                m_internal_metrics,
		                                g_audit_handler,
		                                g_secure_handler,
		                                &m_flush_queue);

		m_inspector->m_analyzer = m_analyzer;
		m_analyzer->get_configuration()->set_machine_id(m_configuration.machine_id());
		m_analyzer->set_containers_labels_max_len(m_configuration.m_containers_labels_max_len);

		m_inspector->set_debug_mode(true);
		m_inspector->set_internal_events_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_inspector->open("");

		// Note that capture job handler is NULL. So no actions that perform captures.
		m_mgr.init(m_inspector, m_analyzer, NULL, &m_configuration, m_internal_metrics);
		std::string policies_file = (m_load_v1_policies
				? security_config::get_policies_file()
				: security_config::get_policies_v2_file());
		m_sinsp_worker = new test_sinsp_worker(m_inspector,
		                                       &m_mgr,
		                                       m_load_v1_policies,
		                                       security_config::get_baselines_file(),
		                                       policies_file);

		Poco::ErrorHandler::set(&m_error_handler);

		ThreadPool::defaultPool().start(*m_sinsp_worker, "test_sinsp_worker");

		// Wait for the test_sinsp_worker to be ready.
		while(!m_sinsp_worker->m_ready)
		{
			Poco::Thread::sleep(100);
		}
	}

	void createFile(const char *path)
	{
		fstream fs;
		fs.open(path, ios::out);
		fs.close();
	}

	void initFiles()
	{
		// create files/dirs used to test fs policies
		createFile("/tmp/sample-sensitive-file-1.txt");
		createFile("/tmp/sample-sensitive-file-2.txt");
		createFile("/tmp/sample-sensitive-file-3.txt");
		createFile("/tmp/matchlist-order.txt");
		createFile("/tmp/matchlist-order-2.txt");
		createFile("/tmp/overall-order-1.txt");
		createFile("/tmp/overall-order-2.txt");
		createFile("/tmp/overall-order-3.txt");
		mkdir("/tmp/one", 0777);
		mkdir("/tmp/one/two", 0777);
		mkdir("/tmp/one/two/three", 0777);
		mkdir("/tmp/two", 0777);
		mkdir("/tmp/two/three", 0777);
		createFile("/tmp/second");
		createFile("/tmp/third");
	}

	virtual void SetUp()
	{
		initFiles();

		m_load_v1_policies = true;

		SetUpTest();
	}

	void TearDownTest()
	{
		dragent_configuration::m_terminate = true;

		ThreadPool::defaultPool().joinAll();
		ThreadPool::defaultPool().stopAll();

		delete m_sinsp_worker;
		delete m_inspector;
		delete m_analyzer;
	}

	virtual void TearDown()
	{
		TearDownTest();

		remove("/tmp/sample-sensitive-file-1.txt");
		remove("/tmp/sample-sensitive-file-2.txt");
		remove("/tmp/sample-sensitive-file-3.txt");
		remove("/tmp/matchlist-order.txt");
		remove("/tmp/matchlist-order-2.txt");
		remove("/tmp/overall-order-1.txt");
		remove("/tmp/overall-order-2.txt");
		remove("/tmp/overall-order-3.txt");
		rmdir("/tmp/one/two/three");
		rmdir("/tmp/one/two");
		rmdir("/tmp/one");
		rmdir("/tmp/two/three");
		rmdir("/tmp/two");
		remove("/tmp/second");
		remove("/tmp/third");
	}

public:
	struct expected_policy_event
	{
		typedef enum {
			HOST_OR_CONTAINER = 0,
			CONTAINER_ONLY,
			HOST_ONLY
		} event_scope_t;

		expected_policy_event(uint64_t p,
				      draiosproto::policy_type ot,
				      map<string,string> ofk)
			: policy_id(p),
			  output_type(ot),
			  output_fields(ofk),
			  baseline_id(""),
			  event_scope(HOST_OR_CONTAINER)
			{
			}
		expected_policy_event(uint64_t p,
				      draiosproto::policy_type ot,
				      map<string,string> ofk,
				      string b_id)
			: policy_id(p),
			  output_type(ot),
			  output_fields(ofk),
			  baseline_id(b_id),
			  event_scope(HOST_OR_CONTAINER)
			{
			}
		expected_policy_event(uint64_t p,
				      draiosproto::policy_type ot,
				      map<string,string> ofk,
				      event_scope_t scope)
			: policy_id(p),
			  output_type(ot),
			  output_fields(ofk),
			  baseline_id(""),
			  event_scope(scope)
			{
			}
		expected_policy_event(uint64_t p,
				      draiosproto::policy_type ot,
				      map<string,string> ofk,
				      string b_id,
				      event_scope_t scope)
			: policy_id(p),
			  output_type(ot),
			  output_fields(ofk),
			  baseline_id(b_id),
			  event_scope(scope)
			{
			}
		uint64_t policy_id;
		draiosproto::policy_type output_type;
		map<string,string> output_fields;
		string baseline_id;
		event_scope_t event_scope;
	};

	void check_policy_events(std::vector<expected_policy_event> &expected)
	{
		std::vector<bool> seen;
		seen.assign(expected.size(), false);

		for(uint32_t attempts=0; attempts<50; attempts++)
		{
			draiosproto::message_type mtype;
			unique_ptr<::google::protobuf::Message> msg = NULL;
			draiosproto::policy_events *pe;

			get_next_msg(100, mtype, msg);
			if(msg == NULL)
			{
				continue;
			}

			ASSERT_EQ(mtype, draiosproto::message_type::POLICY_EVENTS);
			pe = (draiosproto::policy_events *) msg.get();

			for(auto &evt : pe->events())
			{
				const draiosproto::output_event_detail &details = evt.event_details().output_details();
				map<string,string> evt_output_fields;

				for(auto &pair : details.output_fields())
				{
					evt_output_fields.insert(pair);
				}

				bool matched_any = false;
				for(uint32_t i=0; i<expected.size(); i++)
				{
					// The scope of the event must match
					if(expected[i].event_scope == expected_policy_event::CONTAINER_ONLY &&
					   (!evt.has_container_id() || evt.container_id() == ""))
					{
						FAIL() << "Policy event occurred not in container but expected scope was only containers: "
						       << evt.DebugString();
					}

					if(expected[i].event_scope == expected_policy_event::HOST_ONLY &&
					   (evt.has_container_id() && evt.container_id() != ""))
					{
						FAIL() << "Policy event occurred in container but expected scope was only hosts: "
						       << evt.DebugString();
					}

					if(evt.policy_id() == expected[i].policy_id &&
					   details.output_type() == expected[i].output_type &&
					   check_output_fields(evt_output_fields, expected[i].output_fields))
					{
						bool has_bl_details = evt.event_details().has_baseline_details();
						string bl_id = has_bl_details ? evt.event_details().baseline_details().id() : "";
						if(((!has_bl_details && expected[i].baseline_id.empty()) ||
						    (has_bl_details && expected[i].baseline_id == bl_id)))
						{
							seen[i] = true;
							matched_any = true;
						}
					}
				}

				if(!matched_any)
				{
					FAIL() << "Policy event not in expected set: " << evt.DebugString();
				}
			}


			if(std::find(std::begin(seen), std::end(seen), false) == std::end(seen))
			{
				// Found all expected messages, we can stop immediately
				break;
			}
		}

		for(uint32_t i=0; i<expected.size(); i++)
		{
			if(!seen[i])
			{
				FAIL() << "Did not see expected event: "
					<< " policy_id: " << expected[i].policy_id
					<< " output_type: " << draiosproto::policy_type_Name(expected[i].output_type)
					<< " output_fields: " << expected[i].output_fields;
			}
		}
	}

	struct expected_internal_metric
	{
		enum {CMP_EQ, CMP_GE} op;
		uint64_t value;

		std::string to_string()
		{
			std::string str;
			str = (op == CMP_EQ ? "==" : ">=") +
				std::string(" ") + std::to_string(value);

			return str;
		}
	};

 	std::string expected_as_string(std::map<string,expected_internal_metric> &expected)
	{
		string str;
		for(auto &pair : expected)
		{
			str += pair.first + pair.second.to_string();
		}

		return str;
	}

	void check_expected_internal_metrics(std::map<std::string,expected_internal_metric> &expected)
	{
		draiosproto::statsd_info statsd_info;
		uint32_t num_match = 0;

		test_helper::send_all(*m_internal_metrics, &statsd_info);

		for(auto &metric : statsd_info.statsd_metrics())
		{
			auto it = expected.find(metric.name());
			if(it != expected.end())
			{
				if(it->second.op == expected_internal_metric::CMP_EQ)
				{
					ASSERT_EQ(metric.value(), it->second.value) << "Different values for " << it->first
										    << ": expected " << it->second.to_string()
										    << ", actual " << metric.value();
				}
				else if (it->second.op == expected_internal_metric::CMP_GE)
				{
					ASSERT_GE(metric.value(), it->second.value) << "Different values for " << it->first
										    << ": expected " << it->second.to_string()
										    << ", actual " << metric.value();
				}
				num_match++;
			}
		}

		ASSERT_EQ(num_match, expected.size()) << "Not all expected metrics were found with actual values. Actual Metrics: " << statsd_info.DebugString()
						      << "Expected Metrics: " << expected_as_string(expected);
	}

	void get_next_msg(uint64_t delay_ms,
	                  draiosproto::message_type &mtype,
	                  unique_ptr<::google::protobuf::Message> &msg)
	{
		shared_ptr<serialized_buffer> item = nullptr;
		dragent_protocol_header_v4 *hdr;
		const uint8_t *buf;
		uint32_t size;

		msg = NULL;

		do
		{
			if (!m_transmit_queue.get(&item, delay_ms))
			{
				return;
			}
		} while (item == nullptr);

		hdr = (dragent_protocol_header_v4*) item->buffer.data();
		buf = (const uint8_t *) (item->buffer.data() + sizeof(dragent_protocol_header_v4));
		size = ntohl(hdr->len) - sizeof(dragent_protocol_header_v4);

		g_log->debug("Got message type=" + to_string(hdr->messagetype));
		mtype = (draiosproto::message_type) hdr->messagetype;

		draiosproto::throttled_policy_events *tpe;
		draiosproto::policy_events *pe;
		switch (hdr->messagetype)
		{
		case draiosproto::message_type::THROTTLED_POLICY_EVENTS:
			tpe = new draiosproto::throttled_policy_events();
			dragent_protocol::buffer_to_protobuf(buf, size, tpe);
			msg.reset(tpe);
			break;

		case draiosproto::message_type::POLICY_EVENTS:
			pe = new draiosproto::policy_events();
			dragent_protocol::buffer_to_protobuf(buf, size, pe);
			msg.reset(pe);
			break;

		default:
			FAIL() << "Received unknown message " << to_string(hdr->messagetype);
		}
	}

	void get_policy_evts_msg(unique_ptr<draiosproto::policy_events> &pe)
	{
		draiosproto::message_type mtype;
		unique_ptr<::google::protobuf::Message> msg = NULL;

		get_next_msg(5000, mtype, msg);
		ASSERT_TRUE((msg != NULL));
		ASSERT_EQ(mtype, draiosproto::message_type::POLICY_EVENTS);
		pe.reset((draiosproto::policy_events *) (msg.release()));
	}

protected:

	// Helper used by several test cases that have a similar test setup/validation.
	void multiple_falco_files_test(std::string policies_file, std::string expected_output, bool v1_metrics)
	{
		string errstr;

		if(v1_metrics)
		{
			ASSERT_TRUE(m_mgr.load_policies_file(policies_file.c_str(), errstr));
		}
		else
		{
			ASSERT_TRUE(m_mgr.load_policies_v2_file(policies_file.c_str(), errstr));
		}
		ASSERT_STREQ(errstr.c_str(), "");

		int fd = open("/tmp/sample-sensitive-file-2.txt", O_RDONLY);
		close(fd);

		// Not using check_policy_events for this, as it is checking keys only
		unique_ptr<draiosproto::policy_events> pe;
		get_policy_evts_msg(pe);
		ASSERT_EQ(pe->events_size(), 1);
		ASSERT_EQ(pe->events(0).policy_id(), 1u);
		ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 3);
		ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "read_sensitive_file");
		ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);
		ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);

		ASSERT_EQ(pe->events(0).event_details().output_details().output(), expected_output);

		std::map<string,expected_internal_metric> metrics;

		if(v1_metrics)
		{
			metrics = {{"security.falco.match.deny", {expected_internal_metric::CMP_EQ, 1}},
				   {"security.falco.match.accept", {expected_internal_metric::CMP_EQ, 0}},
				   {"security.falco.match.next", {expected_internal_metric::CMP_EQ, 0}}};
		}
		else
		{
			metrics = {{"security.falco.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
				   {"security.falco.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
		}

		check_expected_internal_metrics(metrics);
	}


	sinsp_analyzer::flush_queue m_flush_queue;
	protocol_queue m_transmit_queue;
	bool m_load_v1_policies = true;
	sinsp *m_inspector;
	sinsp_analyzer *m_analyzer;
	internal_metrics::sptr_t m_internal_metrics;
	protocol_handler m_data_handler;
	security_mgr m_mgr;
	test_sinsp_worker *m_sinsp_worker;
	dragent_configuration m_configuration;
	security_policy_error_handler m_error_handler;
};

class security_policies_test_delayed_reports : public security_policies_test
{
protected:

	virtual void SetUp()
	{
		createFile("/tmp/sample-sensitive-file-1.txt");

		bool delayed_reports = true;
		SetUpTest(delayed_reports);
	}

	virtual void TearDown()
	{
		TearDownTest();

		remove("/tmp/sample-sensitive-file-1.txt");
	}
};

class security_policies_test_cointerface : public security_policies_test
{
protected:

	virtual void SetUp()
	{
		string cointerface_sock = "./resources/run/cointerface.sock";

		Process::Args args{"-sock", cointerface_sock,
				"-use_json=false",
				"-modules_dir=./resources/modules_dir"
				};

		// Start a cointerface process to act as the
		// server. Capture its output and log everything at
		// debug level.
		m_colog = make_shared<Pipe>();
		m_cointerface = make_shared<ProcessHandle>(Process::launch("./resources/cointerface", args, NULL, m_colog.get(), NULL));

		thread log_reader = thread([] (shared_ptr<Pipe> colog) {
			PipeInputStream cologstr(*colog);
			string line;

			while (std::getline(cologstr, line))
			{
				g_log->information(line);
			}
		}, m_colog);

		log_reader.detach();

		// Wait for the process in a sub-thread so it
		// is reaped as soon as it exits. This is
		// necessary as Process::isRunning returns
		// true for zombie processes.
		thread waiter = thread([this] () {
			int status;
			waitpid(m_cointerface->id(), &status, 0);
		});

		waiter.detach();

		Thread::sleep(500);

		if (!Process::isRunning(*m_cointerface))
		{
			FAIL() << "cointerface process not running after 1 second";
		}

		SetUpTest();

		int ret = -1;

		for (int i = 0; ret != 0 && i < 20; i++)
		{
			ret = system("curl -I localhost:7765/k8s_audit > /dev/null 2>&1");
			if (ret != 0)
			{
				Thread::sleep(500);
			}
		}

		if (ret != 0)
		{
			FAIL() << "localhost:7765/k8s_audit is not responding after 10 seconds";
		}
	}

	virtual void TearDown()
	{
		if(m_cointerface)
		{
			Process::kill(*m_cointerface);
		}
		TearDownTest();
		g_log->information("TearDown() complete");
	}
private:
	shared_ptr<Pipe> m_colog;
	shared_ptr<ProcessHandle> m_cointerface;
};

class security_policies_v2_test_cointerface : public security_policies_test_cointerface
{
public:
	virtual void SetUp()
	{
		m_load_v1_policies = false;

		security_policies_test_cointerface::SetUp();
	}
};

class security_policies_v2_test : public security_policies_test
{
public:
	virtual void SetUp()
	{
		initFiles();

		m_load_v1_policies = false;

		SetUpTest();
	}
};


class security_policies_v2_dont_match_container_test : public security_policies_test
{
public:
        std::string policies_file()
	{
		return string("./resources/security_policies_messages/v2_policy_dont_match_container.txt");
	}

	virtual void SetUp()
	{
		m_load_v1_policies = false;

		SetUpTest();
	}
};

class security_policies_v2_dont_match_container_test_multi : public security_policies_test
{
public:
        std::string policies_file()
	{
		return string("./resources/security_policies_messages/v2_policy_dont_match_container_multi.txt");
	}

	virtual void SetUp()
	{
		m_load_v1_policies = false;

		SetUpTest();
	}
};

static void readonly_fs_test(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	// Note that these file opens, that are read-only, should only
	// match the readonly policy and not the readwrite policy.
	int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDONLY);
	close(fd);

	// This should not result in an event, as it runs in a container.
	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo '' > /tmp/sample-sensitive-file-1.txt || true; done' > /dev/null 2>&1"), 0);

	sleep(5);

	dutils_kill_container("sec_ut");

	fd = open("/tmp/sample-sensitive-file-3.txt", O_RDONLY);
	close(fd);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{2,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/sample-sensitive-file-1.txt"},
								{"evt.type", "open"}, {"proc.name", "tests"}}}};
	ptest->check_policy_events(expected);

	if(v1_metrics)
	{
		std::map<string,security_policies_test::expected_internal_metric> metrics =
			{{"security.files-readonly.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			 {"security.files-readonly.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			 {"security.files-readonly.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};

		ptest->check_expected_internal_metrics(metrics);
	}
	else
	{
		std::map<string,security_policies_test::expected_internal_metric> metrics =
			{{"security.files-readonly.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			 {"security.files-readonly.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};

		ptest->check_expected_internal_metrics(metrics);
	}
};

TEST_F(security_policies_test, readonly_fs_only)
{
	bool v1_metrics = true;
	return readonly_fs_test(this, v1_metrics);
}

TEST_F(security_policies_v2_test, readonly_fs_only)
{
	bool v1_metrics = false;
	return readonly_fs_test(this, v1_metrics);
}

static void readwrite_fs_test(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	// Note that these file opens, that are read-only, should only
	// match the readonly policy and not the readwrite policy.
	int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDWR);
	close(fd);

	fd = open("/tmp/sample-sensitive-file-3.txt", O_RDWR);
	close(fd);

	ASSERT_EQ(system("docker run -d --name sec_ut --rm busybox:latest sh -c 'while true; do echo '' > /tmp/sample-sensitive-file-3.txt || true; sleep 1; done' > /dev/null 2>&1"), 0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{3,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/sample-sensitive-file-3.txt"},
								{"evt.type", "open"}, {"proc.name", "tests"}}}};
	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;
	if(v1_metrics)
	{
		metrics = {{"security.files-readwrite.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.files-readwrite.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.files-readwrite.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};

	}
	else
	{
		metrics = {{"security.files-readwrite.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.files-readwrite.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test, readwrite_fs_only)
{
	bool v1_metrics = true;
	return readwrite_fs_test(this, v1_metrics);
};

TEST_F(security_policies_v2_test, readwrite_fs_only)
{
	bool v1_metrics = false;
	return readwrite_fs_test(this, v1_metrics);
};

TEST_F(security_policies_test, mixed_r_rw)
{
	// Try to open /tmp/matchlist-order.txt and
	// /tmp/matchlist-order-2 read-only. The first list only
	// matches read-write opens, so the open will fall to the
	// second list and result in a policy event.

	int fd = open("/tmp/matchlist-order.txt", O_RDONLY);
	close(fd);

	fd = open("/tmp/matchlist-order-2.txt", O_RDONLY);
	close(fd);

	std::vector<expected_policy_event> expected = {{9,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/matchlist-order.txt"}, {"evt.type", "open"}}},
						       {9,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/matchlist-order-2.txt"}, {"evt.type", "open"}}}};
	check_policy_events(expected);
};

static void fs_prefixes_test(security_policies_test *ptest, bool v1_metrics)
{
	int fd = open("/tmp/one", O_RDONLY);
	close(fd);

	fd = open("/tmp/one/two", O_RDONLY);
	close(fd);

	fd = open("/tmp/one/two/three", O_RDONLY);
	close(fd);

	fd = open("/tmp/two", O_RDONLY);
	close(fd);

	fd = open("/tmp/two/three", O_RDONLY);
	close(fd);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{12,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/one"}, {"evt.type", "open"}}},
		 {12,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/one/two"}, {"evt.type", "open"}}},
		 {12,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/one/two/three"}, {"evt.type", "open"}}},
		 {12,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/two"}, {"evt.type", "open"}}},
		 {12,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/two/three"}, {"evt.type", "open"}}}};

	ptest->check_policy_events(expected);
};

TEST_F(security_policies_test, fs_prefixes)
{
	bool v1_metrics = true;
	return fs_prefixes_test(this, v1_metrics);
};

TEST_F(security_policies_v2_test, fs_prefixes)
{
	bool v1_metrics = false;
	return fs_prefixes_test(this, v1_metrics);
};

static void fs_root_dir(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("fs-root-image");
	dutils_create_tag("busybox:test-root-writes", "busybox:latest");

	if(system("docker run -d --rm --name fs-root-image busybox:test-root-writes sh -c 'while true; do echo '' > /allowed-file-below-root && echo '' > /not-allowed; sleep 1; done' > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	sleep(5);

	dutils_kill_container("fs-root-image");

	dutils_kill_image("busybox:test-root-writes");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{19,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/not-allowed"}, {"evt.type", "open"}}}};

	ptest->check_policy_events(expected);
};

TEST_F(security_policies_test, fs_root_dir)
{
	bool v1_metrics = true;
	return fs_root_dir(this, v1_metrics);
};

TEST_F(security_policies_v2_test, fs_root_dir)
{
	bool v1_metrics = false;
	return fs_root_dir(this, v1_metrics);
};

static void tcp_listenport_only(security_policies_test *ptest, bool v1_metrics)
{
	int rc;
	int sock = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in localhost;

	localhost.sin_family = AF_INET;
	localhost.sin_port = htons(1234);
	inet_aton("127.0.0.1", &(localhost.sin_addr));

	if((rc = bind(sock, (struct sockaddr *) &localhost, sizeof(localhost))) != 0)
	{
		fprintf(stderr, "Could not bind listening socket to localhost: %s\n", strerror(errno));
		return;
	}

	listen(sock, 1);

	close(sock);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{4,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "1234"}, {"fd.sip", "127.0.0.1"}, {"fd.l4proto", "tcp"}}}};

	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.listenports-tcp.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.listenports-tcp.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.listenports-tcp.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.listenports-tcp.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.listenports-tcp.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, tcp_listenport_only)
{
	bool v1_metrics = true;
	return tcp_listenport_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, tcp_listenport_only)
{
	bool v1_metrics = false;
	return tcp_listenport_only(this, v1_metrics);
};

static void udp_listenport_only(security_policies_test *ptest, bool v1_metrics)
{
	int rc;
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in localhost;

	localhost.sin_family = AF_INET;
	localhost.sin_port = htons(12345);
	inet_aton("127.0.0.1", &(localhost.sin_addr));

	if((rc = bind(sock, (struct sockaddr *) &localhost, sizeof(localhost))) != 0)
	{
		fprintf(stderr, "Could not bind listening socket to localhost: %s\n", strerror(errno));
		return;
	}

	struct timeval read_timeout;
	read_timeout.tv_sec = 0;
	read_timeout.tv_usec = 10;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

	char buffer;
	recvfrom(sock, &buffer, 1, 0, NULL, NULL);

	close(sock);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{5,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "12345"}, {"fd.sip", "127.0.0.1"}, {"fd.l4proto", "udp"}}}};
	ptest->check_policy_events(expected);


	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.listenports-udp.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.listenports-udp.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.listenports-udp.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.listenports-udp.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.listenports-udp.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, udp_listenport_only)
{
	bool v1_metrics = true;
	return udp_listenport_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, udp_listenport_only)
{
	bool v1_metrics = false;
	return udp_listenport_only(this, v1_metrics);
};

TEST_F(security_policies_test, matchlist_order)
{
	// Try to open /tmp/matchlist-order.txt for reading and
	// /tmp/matchlist-order-2 read-write. The first list for the
	// relevant policy has an EFFECT_ALLOW action for
	// /tmp/matchlist-order.txt, so there should be *no* policy
	// for matchlist-order.txt, only matchlist-order-2.txt

	int fd = open("/tmp/matchlist-order.txt", O_RDWR);
	close(fd);

	fd = open("/tmp/matchlist-order-2.txt", O_RDONLY);
	close(fd);

	std::vector<expected_policy_event> expected = {{9,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/matchlist-order-2.txt"}, {"evt.type", "open"}}}};
	check_policy_events(expected);

	std::map<string,expected_internal_metric> metrics = {{"security.files-readonly.match.deny", {expected_internal_metric::CMP_EQ, 1}},
							     {"security.files-readonly.match.accept", {expected_internal_metric::CMP_EQ, 0}},
							     {"security.files-readonly.match.next", {expected_internal_metric::CMP_EQ, 0}},
							     {"security.files-readwrite.match.deny", {expected_internal_metric::CMP_EQ, 0}},
							     {"security.files-readwrite.match.accept", {expected_internal_metric::CMP_EQ, 1}},
							     {"security.files-readwrite.match.next", {expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, overall_order)
{
	// Try to open /tmp/overall-order-{123}.txt for reading. An
	// initial policy accepts all 3, but each file is also listed
	// in a subsequent list, subsequent policy, or subsequent
	// falco rule. There should be *no* policy events.

	int fd = open("/tmp/overall-order-1.txt", O_RDONLY);
	close(fd);

	fd = open("/tmp/overall-order-2.txt", O_RDONLY);
	close(fd);

	fd = open("/tmp/overall-order-3.txt", O_RDONLY);
	close(fd);

	unique_ptr<::google::protobuf::Message> msg = NULL;
	draiosproto::message_type mtype;
	get_next_msg(5000, mtype, msg);
	ASSERT_TRUE((msg == NULL));

	std::map<string,expected_internal_metric> metrics = {{"security.files-readonly.match.deny", {expected_internal_metric::CMP_EQ, 0}},
							     {"security.files-readonly.match.accept", {expected_internal_metric::CMP_EQ, 3}},
							     {"security.files-readonly.match.next", {expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

static void syscall_only(security_policies_test *ptest, bool v1_metrics)
{
	// It doesn't matter that the quotactl fails, just that it attempts
	struct dqblk quota;
	quotactl(Q_GETQUOTA, "/no/such/file", 0, (caddr_t) &quota);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{6,draiosproto::policy_type::PTYPE_SYSCALL,{{"evt.type", "quotactl"}}}};

	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.syscalls.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.syscalls.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.syscalls.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.syscalls.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.syscalls.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, syscall_only)
{
	bool v1_metrics = true;
	return syscall_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, syscall_only)
{
	bool v1_metrics = false;
	return syscall_only(this, v1_metrics);
};

static void container_only(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_kill_image("blacklist-image-name");

	dutils_create_tag("blacklist-image-name", "busybox:1.27.2");
	dutils_kill_container("blacklisted_image");

	if(system("docker run --rm --name blacklisted_image blacklist-image-name sleep 5 > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	dutils_kill_image("blacklist-image-name");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{7,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "blacklist-image-name"},
							       {"container.name", "blacklisted_image"},
							       {"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};
	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.containers.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.containers.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.containers.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.containers.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.containers.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test, container_only)
{
	bool v1_metrics = true;
	return container_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, container_only)
{
	bool v1_metrics = false;
	return container_only(this, v1_metrics);
};

static void run_non_alpine_container(security_policies_test *ptest, bool both_policies_match)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_kill_container("non_alpine");

	if(system("docker run --rm --name non_alpine busybox:1.27.2 sleep 5 > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	std::vector<security_policies_test::expected_policy_event> expected =
		{{3001,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "busybox:1.27.2"},
							       {"container.name", "non_alpine"},
							       {"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};

	uint64_t num_matches = 1;
	if(both_policies_match)
	{
		num_matches = 2;

		expected.push_back(
			{3002,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "busybox:1.27.2"},
								       {"container.name", "non_alpine"},
								       {"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}});
	}

	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	metrics = {{"security.containers.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
		   {"security.containers.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, num_matches}}};

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_dont_match_container_test, container_dont_match)
{
	bool both_policies_match = false;
	return run_non_alpine_container(this, both_policies_match);
};

TEST_F(security_policies_v2_dont_match_container_test_multi, container_dont_match)
{
	bool both_policies_match = true;
	return run_non_alpine_container(this, both_policies_match);
};

TEST_F(security_policies_v2_test, container_match_multi_policies_one_rule)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_create_tag("busybox:some-tag", "busybox:1.27.2");
	dutils_kill_container("busybox_some_tag");

	if(system("docker run --rm --name busybox_some_tag busybox:some-tag sleep 5 > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	std::vector<security_policies_test::expected_policy_event> expected =
		{{31,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "busybox:some-tag"},
								  {"container.name", "busybox_some_tag"},
								  {"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}},
		 {32,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "busybox:some-tag"},
								  {"container.name", "busybox_some_tag"},
								  {"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};

	check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	metrics = {{"security.containers.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 2}},
		   {"security.containers.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, container_only_scope)
{
	if(!dutils_check_docker())
	{
		return;
	}

	// Only the activity in the container should result in policy
	// events. The command line differentiates between the
	// container and host activity.
	int fd = open("/tmp/second", O_RDWR);
	close(fd);

	dutils_kill_container("sec_ut");

	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo '' > /tmp/second; sleep 1; done' > /dev/null 2>&1"), 0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{33,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/second"},
									{"evt.type", "open"}},
		  expected_policy_event::CONTAINER_ONLY}};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, host_only_scope)
{
	if(!dutils_check_docker())
	{
		return;
	}

	// Only the activity in the container should result in policy
	// events. The command line differentiates between the
	// container and host activity.
	int fd = open("/tmp/third", O_RDWR);
	close(fd);

	dutils_kill_container("sec_ut");

	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo '' > /tmp/third; sleep 1; done' > /dev/null 2>&1"), 0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{34,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/third"},
								 {"evt.type", "open"}},
		  expected_policy_event::HOST_ONLY}};

	check_policy_events(expected);
}

static void process_only(security_policies_test *ptest, bool v1_metrics)
{
	ASSERT_EQ(system("ls > /dev/null 2>&1"), 0);

	std::vector<security_policies_test::expected_policy_event> expected =
		{{8,draiosproto::policy_type::PTYPE_PROCESS,{{"proc.name", "ls"}, {"proc.cmdline", "ls"}}}};

	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.processes.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.processes.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.processes.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.processes.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.processes.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test, process_only)
{
	bool v1_metrics = true;
	return process_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, process_only)
{
	bool v1_metrics = false;
	return process_only(this, v1_metrics);
};

static void falco_only(security_policies_test *ptest, bool v1_metrics)
{
	int fd = open("/tmp/sample-sensitive-file-2.txt", O_RDONLY);
	close(fd);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_NE(pe, nullptr);
	ASSERT_EQ(pe->events_size(), 1);
	ASSERT_EQ(pe->events(0).policy_id(), 1u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "read_sensitive_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"), "/tmp/sample-sensitive-file-2.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);

	string prefix = "tests read /tmp/sample-sensitive-file-*.txt";
	ASSERT_EQ(pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix), 0);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.falco.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.falco.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.falco.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, falco_only)
{
	bool v1_metrics = true;
	return falco_only(this, v1_metrics);
};

TEST_F(security_policies_v2_test, falco_only)
{
	bool v1_metrics = false;
	return falco_only(this, v1_metrics);
};

static void falco_no_evttype(security_policies_test *ptest, bool v1_metrics)
{
	int fd = open("/tmp/banned-file.txt", O_RDONLY);
	close(fd);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 26u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "anything_for_banned_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"), "/tmp/banned-file.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);

	string prefix = "some operation related to /tmp/banned-file.txt";
	ASSERT_EQ(pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix), 0);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.falco.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.falco.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.falco.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, falco_no_evttype)
{
	bool v1_metrics = true;
	return falco_no_evttype(this, v1_metrics);
};

TEST_F(security_policies_v2_test, falco_no_evttype)
{
	bool v1_metrics = false;
	return falco_no_evttype(this, v1_metrics);
};

static void falco_fqdn(security_policies_test *ptest, bool v1_metrics)
{
	ASSERT_EQ(system("echo 'ping' | timeout 2 nc github.com 80 > /dev/null 2>&1"), 0);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 27u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "contacted_blacklisted_host");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.sip.name"), "github.com");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("fd.name") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);

	string prefix = "tests contacted the blacklisted host github.com";
	ASSERT_EQ(pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix), 0);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics= {{"security.falco.match.deny", {security_policies_test::expected_internal_metric::CMP_GE, 1}},
			  {"security.falco.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			  {"security.falco.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.falco.match.match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test, DISABLED_falco_fqdn)
{
	bool v1_metrics = true;
	return falco_fqdn(this, v1_metrics);
};

TEST_F(security_policies_v2_test, DISABLED_falco_fqdn)
{
	bool v1_metrics = false;
	return falco_fqdn(this, v1_metrics);
};


TEST_F(security_policies_test, multiple_falco_variants)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_variants.txt", "v2 output", v1_metrics);
}

TEST_F(security_policies_v2_test, multiple_falco_variants)
{
	bool v1_metrics = false;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_variants_v2.txt", "v2 output", v1_metrics);
}

TEST_F(security_policies_test, multiple_falco_files)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_files.txt", "some output", v1_metrics);
}

TEST_F(security_policies_v2_test, multiple_falco_files)
{
	bool v1_metrics = false;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_files_v2.txt", "some output", v1_metrics);
}

TEST_F(security_policies_test, multiple_falco_files_override)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_files_override.txt", "some output", v1_metrics);
}

TEST_F(security_policies_v2_test, multiple_falco_files_override)
{
	bool v1_metrics = false;
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_files_override_v2.txt", "some output", v1_metrics);
}

TEST_F(security_policies_test, custom_falco_files)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/custom_falco_files.txt", "some output", v1_metrics);
}

TEST_F(security_policies_v2_test, custom_falco_files)
{
	bool v1_metrics = false;
	multiple_falco_files_test("./resources/security_policies_messages/custom_falco_files_v2.txt", "some output", v1_metrics);
}

TEST_F(security_policies_test, custom_falco_files_override)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/custom_falco_files_override.txt", "some output", v1_metrics);
}

TEST_F(security_policies_v2_test, custom_falco_files_override)
{
	bool v1_metrics = false;
	multiple_falco_files_test("./resources/security_policies_messages/custom_falco_files_override_v2.txt", "some output", v1_metrics);
}

TEST_F(security_policies_test, falco_old_rules_message)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/falco_old_rules_message.txt", "some old output", v1_metrics);
}

TEST_F(security_policies_test, falco_old_new_rules_message)
{
	bool v1_metrics = true;
	multiple_falco_files_test("./resources/security_policies_messages/falco_old_new_rules_message.txt", "some new output", v1_metrics);
}

static void falco_k8s_audit(security_policies_test_cointerface *ptest, bool v1_metrics)
{
	// send a single event (the first line of the file)
	ASSERT_EQ(system("timeout 2 curl -X POST localhost:7765/k8s_audit -d $(head -1 ./resources/k8s_audit_events.txt) > /dev/null 2>&1"), 0);

	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 28u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "k8s_deployment_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"), "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"), "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"), "nginx-deployment");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.namespace"), "default");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"), "minikube-user");

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.falco.match.deny", {security_policies_test::expected_internal_metric::CMP_GE, 1}},
			   {"security.falco.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.falco.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.falco.match.match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test_cointerface, falco_k8s_audit)
{
	bool v1_metrics = true;
	return falco_k8s_audit(this, v1_metrics);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit)
{
	bool v1_metrics = false;
	return falco_k8s_audit(this, v1_metrics);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_scope)
{
	// send a single event (the first line of the file)
	ASSERT_EQ(system("timeout 2 curl -X POST localhost:7765/k8s_audit -d $(head -1 ./resources/k8s_audit_create_namespace.txt) > /dev/null 2>&1"), 0);

	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() == 1);
	ASSERT_EQ(pe->events(0).policy_id(), 35u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 5);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "k8s_namespace_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"), "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"), "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"), "some-namespace");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"), "minikube-user");

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	metrics = {{"security.falco.match.match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.falco.match.not_match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};


static void falco_k8s_audit_multi_events(security_policies_test_cointerface *ptest, bool v1_metrics)
{
	// send a bunch of events (one per line of the file)
	ASSERT_EQ(system("timeout 2 xargs -0 -d '\n' -I{} curl -X POST localhost:7765/k8s_audit -d {} < ./resources/k8s_audit_events.txt > /dev/null 2>&1"), 0);

	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 28u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "k8s_deployment_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"), "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"), "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"), "nginx-deployment");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.namespace"), "default");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"), "minikube-user");

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.falco.match.deny", {security_policies_test::expected_internal_metric::CMP_GE, 1}},
			   {"security.falco.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.falco.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.falco.match.match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_test_cointerface, falco_k8s_audit_multi_events)
{
	bool v1_metrics = true;
	return falco_k8s_audit_multi_events(this, v1_metrics);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_multi_events)
{
	bool v1_metrics = false;
	return falco_k8s_audit_multi_events(this, v1_metrics);
};

TEST_F(security_policies_test_cointerface, falco_k8s_audit_messy_client)
{
	// Check for unsupported http methods (POST is the only method supported)
	ASSERT_EQ(system("curl -sX GET localhost:7765/k8s_audit | grep -qx 'Method GET not allowed' || false"), 0);
	// Don't test method HEAD, as curl just hangs...
	// ASSERT_EQ(system("curl -sX HEAD localhost:7765/k8s_audit | grep -qx 'Method HEAD not allowed' || false"), 0);
	ASSERT_EQ(system("curl -sX PUT localhost:7765/k8s_audit | grep -qx 'Method PUT not allowed' || false"), 0);
	ASSERT_EQ(system("curl -sX DELETE localhost:7765/k8s_audit | grep -qx 'Method DELETE not allowed' || false"), 0);
	ASSERT_EQ(system("curl -sX CONNECT localhost:7765/k8s_audit | grep -qx 'Method CONNECT not allowed' || false"), 0);
	ASSERT_EQ(system("curl -sX OPTIONS localhost:7765/k8s_audit | grep -qx 'Method OPTIONS not allowed' || false"), 0);
	ASSERT_EQ(system("curl -sX TRACE localhost:7765/k8s_audit | grep -qx 'Method TRACE not allowed' || false"), 0);

	// Hit wrong URIs
	ASSERT_EQ(system("curl -sX POST localhost:7765 -d @./resources/k8s_audit_events.txt | grep -qx '404 page not found' || false"), 0);
	ASSERT_EQ(system("curl -sX POST localhost:7765/this-is-not-the-good-door -d @./resources/k8s_audit_events.txt | grep -qx '404 page not found' || false"), 0);

	// Malformed JSONs
	ASSERT_EQ(system("curl -sX POST localhost:7765/k8s_audit -d '{\"this is\"} : clearly \"not\" a well formatted json' | grep -qx 'Malformed JSON' || false > /dev/null 2>&1"), 0);
}

TEST_F(security_policies_test, baseline_only)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("baseline-test");

	ASSERT_EQ(system("docker run -d --name baseline-test appropriate/nc /bin/sh -c \"while true; do timeout -t 1 nc -nl 9274 > /dev/null 2>&1; done\""), 0);

	sleep(5);

	dutils_kill_container("baseline-test");

	// This should not result in any policy events, as the
	// baseline for this image already captures all of its
	// behavior.

	unique_ptr<::google::protobuf::Message> msg = NULL;
	draiosproto::message_type mtype;
	get_next_msg(5000, mtype, msg);
	ASSERT_TRUE((msg == NULL));
}

TEST_F(security_policies_test, baseline_deviate_port)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("baseline-test");

	ASSERT_EQ(system("docker run -d --name baseline-test appropriate/nc /bin/sh -c \"while true; do timeout -t 1 nc -nl 8172 > /dev/null 2>&1; done\""), 0);

	sleep(5);

	dutils_kill_container("baseline-test");

	// The only policy event should denote the different listening
	// port
	std::vector<expected_policy_event> expected = {{13,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "8172"}, {"fd.sip", "0.0.0.0"}, {"fd.l4proto", "tcp"}}, "uuid-here"}};

	check_policy_events(expected);
}

TEST_F(security_policies_test, baseline_deviate_cat_dockerenv)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("baseline-test");

	ASSERT_EQ(system("docker run -d --name baseline-test appropriate/nc /bin/sh -c \"while true; do cat /.dockerenv > /dev/null 2>&1; sleep 1; done\""), 0);

	sleep(5);

	dutils_kill_container("baseline-test");

	// We want to see the following events:
	//  - a process event for invoking cat
	//  - a filesystem event for the read of '/.dockerenv'
	std::vector<expected_policy_event> expected = {{13,draiosproto::policy_type::PTYPE_PROCESS,{{"proc.name", "cat"}}, "uuid-here"},
						       {13,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/.dockerenv"}, {"evt.type", "open"}, {"proc.name", "cat"}}, "uuid-here"}};

	check_policy_events(expected);
}

static void container_prefixes(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("denyme");
	dutils_kill_image("my.domain.name/busybox:1.27.2");
	dutils_kill_image("my.other.domain.name:12345/cirros:0.3.3");
	dutils_kill_image("my.third.domain.name/tutum/curl:alpine");

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	ASSERT_EQ(system("docker pull cirros:0.3.3 > /dev/null 2>&1"), 0);
	ASSERT_EQ(system("docker pull tutum/curl:alpine > /dev/null 2>&1"), 0);

	dutils_create_tag("blacklist-image-name:0.0.1", "busybox:1.27.2");

	ASSERT_EQ(system("docker run --rm --name denyme blacklist-image-name:0.0.1 sleep 5 > /dev/null 2>&1"), 0);

	dutils_create_tag("my.domain.name/busybox:1.27.2", "busybox:1.27.2");

	ASSERT_EQ(system("docker run --rm --name denyme my.domain.name/busybox:1.27.2 sleep 5 > /dev/null 2>&1"), 0);

	dutils_kill_image("my.domain.name/busybox:1.27.2");

	dutils_create_tag("my.other.domain.name:12345/cirros:0.3.3", "cirros:0.3.3");

	ASSERT_EQ(system("docker run --rm --name denyme my.other.domain.name:12345/cirros:0.3.3 /bin/sh -c 'sleep 5' > /dev/null 2>&1"), 0);

	dutils_kill_image("my.other.domain.name:12345/cirros:0.3.3");

	dutils_create_tag("my.third.domain.name/cirros:0.3.3", "cirros:0.3.3");

	ASSERT_EQ(system("docker run --rm --name denyme my.third.domain.name/cirros:0.3.3 /bin/sh -c 'sleep 5' > /dev/null 2>&1"), 0);

	dutils_kill_image("my.third.domain.name/cirros:0.3.3");
	dutils_create_tag("my.third.domain.name/tutum/curl:alpine", "tutum/curl:alpine");

	ASSERT_EQ(system("docker run --rm --name denyme my.third.domain.name/tutum/curl:alpine sleep 5 > /dev/null 2>&1"), 0);

	dutils_kill_image("my.third.domain.name/tutum/curl:alpine");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{07,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "blacklist-image-name:0.0.1"},
								{"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"},
								{"container.name", "denyme"}}},
		 {14,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "my.domain.name/busybox:1.27.2"},
								{"container.image.id", "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"},
								{"container.name", "denyme"}}},
		 {15,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "my.other.domain.name:12345/cirros:0.3.3"},
								{"container.image.id", "231974f01f06befaa720909c29baadb586d6e6708e386190873a0d4cc5af033a"},
								{"container.name", "denyme"}}},
		 {16,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "my.third.domain.name/cirros:0.3.3"},
								{"container.image.id", "231974f01f06befaa720909c29baadb586d6e6708e386190873a0d4cc5af033a"},
								{"container.name", "denyme"}}},
		 {17,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "my.third.domain.name/tutum/curl:alpine"},
								{"container.image.id", "b91cd13456bbd3d65f00d0a0be24c95b802ad1f9cd0dc2b8889c4c7fbb599fef"},
								{"container.name", "denyme"}}}};
	ptest->check_policy_events(expected);
}

TEST_F(security_policies_test, container_prefixes)
{
	bool v1_metrics = true;
	return container_prefixes(this, v1_metrics);
};

TEST_F(security_policies_v2_test, container_prefixes)
{
	bool v1_metrics = false;
	return container_prefixes(this, v1_metrics);
};

static void net_inbound_outbound_tcp(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl > /dev/null 2>&1"), 0);

	dutils_kill_container("inout_test");
	dutils_create_tag("curl:inout_test", "tutum/curl");
	ASSERT_EQ(system("docker run -d --name inout_test --rm curl:inout_test bash -c 'while true; do (timeout 5 nc -l -p 22222 -q0 &) && sleep 2 && (timeout 5 nc $(hostname -I | cut -f 1 -d \" \") 22222); sleep 1; done' > /dev/null 2>&1"), 0);

	sleep(5);
	dutils_kill_container("inout_test");
	dutils_kill_image("curl:inout_test");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"fd.sip", "0.0.0.0"},
							      {"fd.l4proto", "tcp"},
							      {"proc.name", "nc"}}}, // listen
		 {18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"fd.l4proto", "tcp"},
							      {"proc.name", "nc"}}}, // connect
		 {18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"fd.l4proto", "tcp"},
							      {"proc.name", "nc"}}}  // accept
		};

	ptest->check_policy_events(expected);
}

TEST_F(security_policies_test, net_inbound_outbound_tcp)
{
	bool v1_metrics = true;
	return net_inbound_outbound_tcp(this, v1_metrics);
};

TEST_F(security_policies_v2_test, net_inbound_outbound_tcp)
{
	bool v1_metrics = false;
	return net_inbound_outbound_tcp(this, v1_metrics);
};

static void net_inbound_outbound_udp(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl > /dev/null 2>&1"), 0);

	dutils_kill_container("inout_test");
	dutils_create_tag("curl:inout_test", "tutum/curl");
	ASSERT_EQ(system("docker run -d --name inout_test --rm curl:inout_test bash -c 'ln -s `which nc` /bin/ncserver; while true; do (timeout 5 ncserver -ul -p 22222 -q0 &) && sleep 2 && (echo ping | timeout 5 nc -u $(hostname -I | cut -f 1 -d \" \") 22222 -w 1); sleep 1; done' > /dev/null 2>&1"), 0);

	sleep(5);
	dutils_kill_container("inout_test");
	dutils_kill_image("curl:inout_test");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"proc.name", "nc"},
							      {"fd.l4proto", "udp"}}}, // connect
		 {18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"proc.name", "ncserver"},
							      {"fd.l4proto", "udp"}}}, // recvfrom
		 {18,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sport", "22222"},
							      {"proc.name", "ncserver"},
							      {"fd.l4proto", "udp"}}}  // connect, used internally during libc getaddrinfo to lookup the local address via getsockname
	};

	ptest->check_policy_events(expected);
}

TEST_F(security_policies_test, net_inbound_outbound_udp)
{
	bool v1_metrics = true;
	return net_inbound_outbound_udp(this, v1_metrics);
};

TEST_F(security_policies_v2_test, net_inbound_outbound_udp)
{
	bool v1_metrics = false;
	return net_inbound_outbound_udp(this, v1_metrics);
};

TEST_F(security_policies_test, baseline_without_syscalls)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker run -d --name baseline-test --rm alpine /bin/sh -c \"while true; do echo '' > /bin/test; sleep 1; done\""), 0);

	sleep(5);

	dutils_kill_container("baseline-test");

	// Syscall aren't enforced, so no policy events
	// about the syscall made by touch even if they
	// aren't in the baseline whitelist
	// Filesystem is instead enforced by the baseline
	std::vector<expected_policy_event> expected = {{20,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/bin/test"},{"proc.name", "sh"}, {"evt.type", "open"}}, "uuid-2-here"}};
	check_policy_events(expected);
}

static void fs_usecase(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("fs_usecase");
	dutils_create_tag("busybox:fs_usecase", "busybox:latest");

	ASSERT_EQ(system("docker run -d --rm --name fs_usecase busybox:fs_usecase sh -c 'while true; do touch /home/allowed && cat /etc/passwd /home/allowed /etc/hostname > /bin/not-allowed; sleep 1; done'"),0);

	sleep(5);

	dutils_kill_container("fs_usecase");
	dutils_kill_image("busybox:fs_usecase");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{21,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/etc/passwd"}, {"evt.type", "open"}}},
		 {21,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/bin/not-allowed"}, {"evt.type", "open"}}}};

	ptest->check_policy_events(expected);
};

TEST_F(security_policies_test, fs_usecase)
{
	bool v1_metrics = true;
	return fs_usecase(this, v1_metrics);
};

TEST_F(security_policies_v2_test, fs_usecase)
{
	bool v1_metrics = false;
	return fs_usecase(this, v1_metrics);
};


TEST_F(security_policies_test, image_name_priority)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl:alpine > /dev/null 2>&1"), 0);

	dutils_kill_container("mycurl");
	dutils_create_tag("tutum/mycurl", "tutum/curl:alpine");
	ASSERT_EQ(system("docker run --rm --name mycurl tutum/mycurl sleep 5"), 0);

	dutils_kill_image("tutum/mycurl");

	// between policies 22 and 23 only the latter will trigger
	// because the order of the policy matchlists it's different
	std::vector<expected_policy_event> expected = {{23,draiosproto::policy_type::PTYPE_CONTAINER,{{"container.image", "tutum/mycurl"},
												      {"container.name", "mycurl"},
												      {"container.image.id", "b91cd13456bbd3d65f00d0a0be24c95b802ad1f9cd0dc2b8889c4c7fbb599fef"}}}};
	check_policy_events(expected);
};

TEST_F(security_policies_test, overlapping_syscall)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl > /dev/null 2>&1"), 0);

	dutils_kill_container("overlap_test");
	dutils_create_tag("curl:overlap_test", "tutum/curl");

	ASSERT_EQ(system("docker run -d --rm --name overlap_test curl:overlap_test bash -c 'while true; do (timeout 5 nc -l -p 12345 -q0 &) && sleep 2 && (timeout 5 nc $(hostname -I | cut -f 1 -d \" \") 12345); sleep 1; done'"),0);

	sleep(5);

	dutils_kill_container("overlap_test");
	dutils_kill_image("curl:overlap_test");

	// Policy 23 match both for syscalls and network, but network
	// take precedence (rule type order is hard-coded by us)
	std::vector<expected_policy_event> expected = {{24,draiosproto::policy_type::PTYPE_NETWORK,{{"fd.sip", "0.0.0.0"}, {"fd.sport", "12345"}, {"fd.l4proto", "tcp"}}}};
						       //{23,draiosproto::policy_type::PTYPE_SYSCALL,{{"evt.type", "listen"}}}
	check_policy_events(expected);
};

static void nofd_operations(security_policies_test *ptest, bool v1_metrics)
{
	DIR *dirp;

	mkdir("/tmp/test_nofd_ops/", 0777);
	dirp = opendir("/tmp/test_nofd_ops/");

	mkdirat(dirfd(dirp), "./one", 0777);
	mkdirat(dirfd(dirp), "./two", 0777);

	unlinkat(dirfd(dirp), "./one", AT_REMOVEDIR);
	renameat(dirfd(dirp), "./two", dirfd(dirp), "./three");

	rename("/tmp/test_nofd_ops/three", "/tmp/test_nofd_ops/four");

	ASSERT_EQ(system("touch /tmp/test_nofd_ops/file"), 0);
	unlink("/tmp/test_nofd_ops/file");

	closedir(dirp);

	rmdir("/tmp/test_nofd_ops/four");
	rmdir("/tmp/test_nofd_ops");

	std::vector<security_policies_test::expected_policy_event> expected =
		{{25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.arg[1]", "/tmp/test_nofd_ops/"}, {"evt.type", "mkdir"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.abspath", "/tmp/test_nofd_ops/one"}, {"evt.type", "mkdirat"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.abspath", "/tmp/test_nofd_ops/two"}, {"evt.type", "mkdirat"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.abspath", "/tmp/test_nofd_ops/one"}, {"evt.type", "unlinkat"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.abspath", "/tmp/test_nofd_ops/two"}, {"evt.abspath.dst", "/tmp/test_nofd_ops/three"}, {"evt.type", "renameat"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.arg[1]", "/tmp/test_nofd_ops/three"}, {"evt.arg[2]", "/tmp/test_nofd_ops/four"}, {"evt.type", "rename"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"fd.name", "/tmp/test_nofd_ops/file"}, {"evt.type", "open"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.arg[1]", "/tmp/test_nofd_ops/file"}, {"evt.type", "unlink"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.arg[1]", "/tmp/test_nofd_ops/four"}, {"evt.type", "rmdir"}}},
		 {25,draiosproto::policy_type::PTYPE_FILESYSTEM,{{"evt.arg[1]", "/tmp/test_nofd_ops"}, {"evt.type", "rmdir"}}}};

	ptest->check_policy_events(expected);

	std::map<string,security_policies_test::expected_internal_metric> metrics;

	if(v1_metrics)
	{
		metrics = {{"security.files-readwrite.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.files-readwrite-nofd.match.deny", {security_policies_test::expected_internal_metric::CMP_EQ, 9}},
			   {"security.files-readwrite.match.accept", {security_policies_test::expected_internal_metric::CMP_EQ, 0}},
			   {"security.files-readwrite.match.next", {security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}
	else
	{
		metrics = {{"security.files-readwrite.match.match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.files-readwrite-nofd.match.match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 9}},
			   {"security.files-readwrite.match.not_match_items", {security_policies_test::security_policies_test::expected_internal_metric::CMP_EQ, 0}}};
	}

	ptest->check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_test, nofd_operations)
{
	bool v1_metrics = true;
	return nofd_operations(this, v1_metrics);
};

TEST_F(security_policies_v2_test, nofd_operations)
{
	bool v1_metrics = false;
	return nofd_operations(this, v1_metrics);
};

static void events_flood(security_policies_test *ptest, bool v1_metrics)
{
	shared_ptr<serialized_buffer> item;

	// Repeatedly try to read /tmp/sample-sensitive-file-1.txt. This will result in a flood of policy events.

	// What we want to see is the following:
	//  - 1 policy event message, containing all the policy events that make it through the token bucket.
	//  - Between 8-12 throttled policy event messages. These should be sent
	//    every second while the opens are occurring.
	//  - The total count of events across both messages should equal the number of reads we did.
	//  - There should be a steady stream of metrics events without any big delays.

	g_log->debug("Reading /tmp/sample-sensitive-file-1.txt 1000 times");
	for(uint32_t i = 0; i < 1000; i++)
	{
		int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDONLY);
		close(fd);

		Poco::Thread::sleep(10);
	}

	int32_t policy_event_count = 0;
	int32_t throttled_policy_event_count = 0;
	int32_t event_count = 0;

	// We'll stop when the queue is empty. This way we'll get all
	// metrics and policy event messages sent while the above
	// opens were occurring.
	draiosproto::message_type mtype;
	draiosproto::throttled_policy_events *tpe;
	draiosproto::policy_events *pe;

	// Read events for up to 10 seconds trying to read all
	// events/policy_events/throttled_policy_events messages.
	for(uint32_t attempts=0; attempts<100; attempts++)
	{
		unique_ptr<::google::protobuf::Message> msg;

		ptest->get_next_msg(100, mtype, msg);

		if(msg == NULL)
		{
			continue;
		}

		switch (mtype)
		{

		case draiosproto::message_type::THROTTLED_POLICY_EVENTS:
			throttled_policy_event_count++;
			tpe = (draiosproto::throttled_policy_events *) msg.get();

			event_count += tpe->events(0).count();

			break;

		case draiosproto::message_type::POLICY_EVENTS:
			pe = (draiosproto::policy_events *) msg.get();
			g_log->debug("Read policy event with " + to_string(pe->events_size()) + " events");
			policy_event_count++;
			event_count += pe->events_size();

			break;

		default:
			FAIL() << "Received unknown message " << mtype;
		}

		if(policy_event_count == 1 &&
		   throttled_policy_event_count >= 8 &&
		   throttled_policy_event_count <= 13 &&
		   event_count == 1000)
		{
			break;
		}
	}

	g_log->debug("Num policy_event messages:"  + to_string(policy_event_count));
	g_log->debug("Num throttled_policy_event messages: " + to_string(throttled_policy_event_count));
	g_log->debug("Num events: " + to_string(event_count));

	ASSERT_EQ(policy_event_count, 1);
	ASSERT_GE(throttled_policy_event_count, 8);
	ASSERT_LE(throttled_policy_event_count, 13);
	ASSERT_EQ(event_count, 1000);
}

TEST_F(security_policies_test, DISABLED_events_flood)
{
	bool v1_metrics = true;
	return events_flood(this, v1_metrics);
};

TEST_F(security_policies_v2_test, DISABLED_events_flood)
{
	bool v1_metrics = false;
	return events_flood(this, v1_metrics);
};

static void docker_swarm(security_policies_test *ptest, bool v1_metrics)
{
	if(!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("(docker swarm leave --force || true) > /dev/null 2>&1"), 0);

	ASSERT_EQ(system("docker pull alpine > /dev/null 2>&1"), 0);
	dutils_create_tag("swarm_service_ut_image", "alpine");

	ASSERT_EQ(system("(docker swarm init && docker service create --replicas 1 --name helloworld swarm_service_ut_image /bin/sh -c \"while true; do echo touch; rm -f /tmp/sample-sensitive-file-2.txt; touch /tmp/sample-sensitive-file-2.txt; sleep 1; done\") > /dev/null 2>&1"), 0);

	sleep(5);

	ASSERT_EQ(system("docker swarm leave --force > /dev/null 2>&1"), 0);

	dutils_kill_image("swarm_service_ut_image");

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe.get() != NULL);
	ASSERT_GE(pe->events_size(), 1);
	ASSERT_EQ(pe->events(0).policy_id(), 29u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"), "read_sensitive_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"), "/tmp/sample-sensitive-file-2.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);
}

TEST_F(security_policies_test, docker_swarm)
{
	bool v1_metrics = true;
	return docker_swarm(this, v1_metrics);
};

TEST_F(security_policies_v2_test, docker_swarm)
{
	bool v1_metrics = false;
	return docker_swarm(this, v1_metrics);
};
