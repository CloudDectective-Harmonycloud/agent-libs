#include "sinsp_mock.h"
#include "event_builder.h"
#include "sinsp_evt_wrapper.h"
#include <analyzer.h>
#include <unistd.h>

namespace
{
void msleep(uint32_t milliseconds)
{
	struct timespec ts =
	{
		.tv_sec = milliseconds / 1000,
		.tv_nsec = (milliseconds % 1000) * 1000000,
	};
	nanosleep(&ts, NULL);
}
}

namespace test_helpers
{

sinsp_mock::sinsp_mock() :
	sinsp(),
	m_network_interfaces(this)
{
	m_scap_stats = {};

	m_mock_machine_info.num_cpus = 4;
	m_mock_machine_info.memory_size_bytes = 64ULL * 1024ULL * 1024ULL * 1024ULL; /*64GB*/
	m_mock_machine_info.max_pid = 0x1FFFFFFFFFFFFFFF;
	strcpy(m_mock_machine_info.hostname, "draios-unit-test-host");
}

sinsp_mock::~sinsp_mock()
{

}

thread_builder sinsp_mock::build_thread()
{
	// Create a thread builder that will commit into this class
	return thread_builder(this,
			      std::bind(&sinsp_mock::commit_thread,
					this,
					std::placeholders::_1));
}

void sinsp_mock::commit_thread(sinsp_threadinfo *thread_info)
{
	thread_info->m_inspector = this;
	m_temporary_threadinfo_list.push_back(thread_info_ptr(thread_info));
}

container_builder sinsp_mock::build_container(sinsp_threadinfo& tinfo)
{
	// Create a container builder that will commit into this class
	return container_builder(tinfo,
				 std::bind(&sinsp_mock::commit_container,
					   this,
					   std::placeholders::_1,
					   std::placeholders::_2));
}

void sinsp_mock::commit_container(sinsp_container_info::ptr_t container,
				  sinsp_threadinfo& tinfo)
{
	m_container_manager.add_container(container, &tinfo);
}

event_builder sinsp_mock::build_event(sinsp_threadinfo& tinfo)
{
	// Create an event builder that will commit into this class
	return event_builder(tinfo,
			     std::bind(&sinsp_mock::commit_event,
				       this,
				       std::placeholders::_1,
				       std::placeholders::_2));
}

void sinsp_mock::commit_event(const sinsp_evt_wrapper::ptr& event, unsigned int count)
{
	event->get()->inspector(this);
	m_events.push_back(event_and_count(event, count));
}

void sinsp_mock::open(uint32_t timeout_ms) /*override*/
{
	set_mode(SCAP_MODE_LIVE);
	inject_machine_info(&m_mock_machine_info);
	sinsp_network_interfaces *interfaces = new sinsp_network_interfaces(this);
	*interfaces = m_network_interfaces;
	inject_network_interfaces(interfaces);

	if(m_analyzer) {
		m_analyzer->on_capture_start();
	}

	// Pass ownership of the threads to the thread_manager
	while (!m_temporary_threadinfo_list.empty())
	{
		add_thread(m_temporary_threadinfo_list.front().release());
		m_temporary_threadinfo_list.pop_front();
	}
}

int32_t sinsp_mock::next(sinsp_evt **evt) /*override*/
{
	// If the filename is set then we are loading events from an scap file
	// and the baseclass can handle this.
	if(!get_input_filename().empty())
	{
		return sinsp::next(evt);
	}

	if(m_events.empty())
	{
		return SCAP_EOF;
	}

	event_and_count &element = m_events.front();

	*evt = element.event->get();
	--element.count;
	++m_scap_stats.n_evts;
	(*evt)->m_evtnum = m_scap_stats.n_evts;

	if(!element.count)
	{
		// We pass the raw pointer of the event back to the client, so we can't
		// just pop the event and let it die. We have to save it off.
		m_completed_events.push_back(element);
		m_events.pop_front();
	}

	if(m_analyzer)
	{
		m_analyzer->process_event(*evt, analyzer_emitter::DF_NONE);
	}

	return SCAP_SUCCESS;
}


void sinsp_mock::get_capture_stats(scap_stats *stats) const /*override*/
{
	*stats = m_scap_stats;
}

}
