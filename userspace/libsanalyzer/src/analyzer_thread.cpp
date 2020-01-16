#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <cstring>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "metrics.h"
#undef min
#undef max
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_thread.h"
#include "proc_config.h"
#include "audit_tap.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_procinfo implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_procinfo::clear()
{
	m_exclude_from_sample = true;
	m_proc_metrics.clear();
	m_proc_transaction_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_fd_usage_pct = 0;
	m_syscall_errors.clear();
	m_capacity_score = 0;
	m_cpuload = 0;
	m_vmsize_kb = 0;
	m_vmrss_kb = 0;
	m_vmswap_kb = 0;
	m_pfmajor = 0;
	m_pfminor = 0;
	m_n_transaction_threads = 0;

	std::vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		*it = 0;
	}

	m_program_pids.clear();

	m_external_transaction_metrics.clear();

	m_syscall_errors.clear();

	std::vector<std::vector<sinsp_trlist_entry>>::iterator sts;
	for(sts = m_server_transactions_per_cpu.begin(); 
		sts != m_server_transactions_per_cpu.end(); sts++)
	{
		sts->clear();
	}

	for(sts = m_client_transactions_per_cpu.begin(); 
		sts != m_client_transactions_per_cpu.end(); sts++)
	{
		sts->clear();
	}

	m_protostate.clear();
	m_files_stat.clear();
	m_devs_stat.clear();
	m_fd_count = 0;
	m_start_count = 0;
	m_proc_count = 0;
	m_threads_count = 0;
}

uint64_t sinsp_procinfo::get_tot_cputime()
{
	uint64_t res = 0;

	std::vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		res += *it;
	}

	return res;
}

void main_thread_analyzer_info::hash_environment(sinsp_threadinfo *tinfo, const env_hash::regex_list_t& blacklist)
{
	m_env_hash.update(tinfo, blacklist);
}

///////////////////////////////////////////////////////////////////////////////
// thread_analyzer_info implementation
///////////////////////////////////////////////////////////////////////////////

thread_analyzer_info::thread_analyzer_info()
	: m_procinfo(nullptr),
	  m_prom_check_found(false),
	  m_last_port_scan(time_point_t::min()),
	  m_last_procfs_port_scan(time_point_t::min())
{
}

thread_analyzer_info::~thread_analyzer_info()
{
	if (m_procinfo)
	{
		delete m_procinfo;
	}
	m_procinfo = nullptr;
	m_listening_ports.reset();
}

void thread_analyzer_info::init(sinsp_analyzer* analyzer,
								sinsp *inspector,
								sinsp_threadinfo* tinfo)
{
	m_analyzer = analyzer;
	m_inspector = inspector;
	m_tinfo = tinfo;
	m_th_analysis_flags = AF_PARTIAL_METRIC;
	clear_found_app_checks();
	clear_found_prom_check();
	m_procinfo = NULL;
	m_connection_queue_usage_pct = 0;
	m_old_proc_jiffies = -1;
	m_cpuload = 0;
	m_old_pfmajor = 0;
	m_old_pfminor = 0;
	m_last_wait_duration_ns = 0;
	m_last_wait_end_time_ns = 0;
	ASSERT(m_inspector->get_machine_info() != NULL);
	m_syscall_errors.clear();
	m_called_execve = false;
	m_last_cmdline_sync_ns = 0;
	if(m_percentiles.size())
	{
		// all the threads that belong to a process will share the
		// same percentile store allocated for the main thread
		auto main_thread = m_tinfo->get_main_thread();
		auto mt_ainfo = (main_thread != nullptr) ? main_thread->m_ainfo : nullptr;
		bool share_store = ((mt_ainfo != nullptr) && (this != mt_ainfo));
		m_metrics.set_percentiles(m_percentiles,
			share_store ? &(mt_ainfo->m_metrics) : nullptr);
		m_transaction_metrics.set_percentiles(m_percentiles,
			share_store ? &(mt_ainfo->m_transaction_metrics) : nullptr);
		m_external_transaction_metrics.set_percentiles(m_percentiles,
			share_store ? &(mt_ainfo->m_external_transaction_metrics) : nullptr);
	}

	if (m_analyzer->is_tracking_environment()) {
		if (m_tinfo->is_main_thread()) {
			auto mt_ainfo = main_thread_ainfo();
			mt_ainfo->hash_environment(m_tinfo, m_analyzer->get_environment_blacklist());
		}
	}
}

const sinsp_counters* thread_analyzer_info::get_metrics()
{
	return &m_metrics;
}

void thread_analyzer_info::allocate_procinfo_if_not_present()
{
	if(m_procinfo == NULL)
	{
		m_procinfo = new sinsp_procinfo();

		m_procinfo->m_server_transactions_per_cpu.resize(m_inspector->get_machine_info()->num_cpus);
		m_procinfo->m_client_transactions_per_cpu.resize(m_inspector->get_machine_info()->num_cpus);

		m_procinfo->clear();
		if(m_percentiles.size())
		{
			m_procinfo->m_protostate.set_percentiles(m_percentiles);
			m_procinfo->m_proc_metrics.set_percentiles(m_percentiles);
			m_procinfo->m_proc_transaction_metrics.set_percentiles(m_percentiles);
			m_procinfo->m_external_transaction_metrics.set_percentiles(m_percentiles);
		}
	}
}

void thread_analyzer_info::propagate_flag(flags flags, thread_analyzer_info* other)
{
	if(other->m_th_analysis_flags & flags)
	{
		m_th_analysis_flags |= (other->m_th_analysis_flags & flags);
	}
}

void thread_analyzer_info::propagate_flag_bidirectional(flags flag, thread_analyzer_info* other)
{
	m_th_analysis_flags |= other->m_th_analysis_flags & flag;
	other->m_th_analysis_flags |= m_th_analysis_flags & flag;
}

void thread_analyzer_info::add_all_metrics(thread_analyzer_info* other)
{
	uint32_t j;

	allocate_procinfo_if_not_present();

	sinsp_counter_time ttot;
	other->m_metrics.get_total(&ttot);

	if(ttot.m_count != 0)
	{
		m_procinfo->m_proc_metrics.add(&other->m_metrics);
		m_procinfo->m_proc_transaction_metrics.add(&other->m_transaction_metrics);
	}

	if(other->m_tinfo->get_fd_usage_pct() > m_procinfo->m_fd_usage_pct)
	{
		m_procinfo->m_fd_usage_pct = (uint32_t)other->m_tinfo->get_fd_usage_pct();
	}

	if(other->m_connection_queue_usage_pct > m_procinfo->m_connection_queue_usage_pct)
	{
		m_procinfo->m_connection_queue_usage_pct = other->m_connection_queue_usage_pct;
	}

	if(other->m_cpuload >= 0)
	{
		m_procinfo->m_cpuload += other->m_cpuload;
	}

	//
	// The memory is just per-process, so we sum it into the parent program
	// just if this is not a child thread
	//
	if(other->m_tinfo->is_main_thread())
	{
		m_procinfo->m_vmsize_kb += other->m_tinfo->m_vmsize_kb;
		m_procinfo->m_vmrss_kb += other->m_tinfo->m_vmrss_kb;
		m_procinfo->m_vmswap_kb += other->m_tinfo->m_vmswap_kb;
	}

	m_procinfo->m_pfmajor += (other->m_tinfo->m_pfmajor - other->m_old_pfmajor);
	m_procinfo->m_pfminor += (other->m_tinfo->m_pfminor - other->m_old_pfminor);

	//
	// Propagate client-server flags
	//
	propagate_flag_bidirectional((thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | 
		thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER | 
		thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT | 
		thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT), other);
	propagate_flag_bidirectional((thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_UNIX_SERVER | 
		thread_analyzer_info::AF_IS_UNIX_CLIENT), other);

	//
	// Propagate the CPU times vector
	//
	uint32_t oc = other->m_cpu_time_ns.size();
	if(oc != 0)
	{
		if(m_procinfo->m_cpu_time_ns.size() != oc)
		{
			ASSERT(m_procinfo->m_cpu_time_ns.size() == 0)
			m_procinfo->m_cpu_time_ns.resize(oc);
		}

		for(uint32_t j = 0; j < oc; j++)
		{
			m_procinfo->m_cpu_time_ns[j] += other->m_cpu_time_ns[j];
		}
	}

	//
	// If we are returning programs to the backend, add the child pid to the
	// m_program_pids list
	//
	ASSERT(other->m_tinfo != NULL);

	m_procinfo->m_program_pids.insert(other->m_tinfo->m_pid);
	m_procinfo->m_program_uids.insert(other->m_tinfo->m_uid);

	if(other->m_transaction_metrics.get_counter()->m_count_in != 0)
	{
		m_procinfo->m_n_transaction_threads++;
	}

	m_procinfo->m_external_transaction_metrics.add(&other->m_external_transaction_metrics);

	m_procinfo->m_syscall_errors.add(&other->m_syscall_errors);

	if(other->m_main_thread_ainfo)
	{
		ASSERT(other->m_main_thread_ainfo->m_server_transactions_per_cpu.size() == m_procinfo->m_server_transactions_per_cpu.size());
		for(j = 0; j < m_procinfo->m_server_transactions_per_cpu.size(); j++)
		{
			m_procinfo->m_server_transactions_per_cpu[j].insert(m_procinfo->m_server_transactions_per_cpu[j].end(),
																other->m_main_thread_ainfo->m_server_transactions_per_cpu[j].begin(),
																other->m_main_thread_ainfo->m_server_transactions_per_cpu[j].end());
		}

		ASSERT(other->m_main_thread_ainfo->m_client_transactions_per_cpu.size() == m_procinfo->m_client_transactions_per_cpu.size());
		for(j = 0; j < m_procinfo->m_client_transactions_per_cpu.size(); j++)
		{
			m_procinfo->m_client_transactions_per_cpu[j].insert(m_procinfo->m_client_transactions_per_cpu[j].end(),
																other->m_main_thread_ainfo->m_client_transactions_per_cpu[j].begin(),
																other->m_main_thread_ainfo->m_client_transactions_per_cpu[j].end());
		}

		m_procinfo->m_protostate.add(&other->m_main_thread_ainfo->m_protostate);
		m_procinfo->m_files_stat.add(other->m_main_thread_ainfo->m_files_stat);
		m_procinfo->m_devs_stat.add(other->m_main_thread_ainfo->m_devs_stat);
	}

	m_procinfo->m_fd_count += other->m_tinfo->m_fdtable.size();

	if(other->m_called_execve)
	{
		m_procinfo->m_start_count += 1;
	}

	if(other->m_tinfo->is_main_thread())
	{
		m_procinfo->m_proc_count++;
	}
	++m_procinfo->m_threads_count;
}

void thread_analyzer_info::clear_all_metrics()
{
	ASSERT(m_tinfo != NULL);

	if(m_procinfo != NULL)
	{
		m_procinfo->clear();
	}

	m_metrics.clear();
	m_transaction_metrics.clear();
	m_external_transaction_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_cpuload = 0;
	m_old_pfmajor = m_tinfo->m_pfmajor;
	m_old_pfminor = m_tinfo->m_pfminor;

	std::vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); ++it)
	{
		*it = 0;
	}

	m_syscall_errors.clear();

	if(m_main_thread_ainfo)
	{
		std::vector<std::vector<sinsp_trlist_entry>>::iterator sts;
		for(sts = m_main_thread_ainfo->m_server_transactions_per_cpu.begin();
			sts != m_main_thread_ainfo->m_server_transactions_per_cpu.end(); sts++)
		{
			sts->clear();
		}

		std::vector<std::vector<sinsp_trlist_entry>>::iterator cts;
		for(cts = m_main_thread_ainfo->m_client_transactions_per_cpu.begin();
			cts != m_main_thread_ainfo->m_client_transactions_per_cpu.end(); cts++)
		{
			cts->clear();
		}

		m_main_thread_ainfo->m_protostate.clear();
		m_main_thread_ainfo->m_files_stat.clear();
		m_main_thread_ainfo->m_devs_stat.clear();
	}
	m_called_execve = false;
	clear_found_app_checks();
	clear_found_prom_check();
}

void thread_analyzer_info::clear_role_flags()
{
	m_th_analysis_flags &= ~(AF_IS_LOCAL_IPV4_SERVER | AF_IS_REMOTE_IPV4_SERVER |
		AF_IS_UNIX_SERVER | AF_IS_LOCAL_IPV4_CLIENT | AF_IS_REMOTE_IPV4_CLIENT | AF_IS_UNIX_CLIENT);
}

void thread_analyzer_info::scan_listening_ports(bool scan_procfs, uint32_t procfs_scan_interval)
{
	time_point_t now = time_point_t::min();

	// If this pid has a lot of open fds, only rescan
	// every RESCAN_PORT_INTERVAL_SECS
	if (m_listening_ports && (m_tinfo->get_fd_opencount() >= LISTENING_PORT_SCAN_FDLIMIT))
	{
		now = time_point_t::clock::now();
		auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_port_scan).count();
		if((m_last_port_scan != time_point_t::min()) &&
			(elapsed_secs < RESCAN_PORT_INTERVAL_SECS))
		{
			return;
		}
	}

	m_listening_ports = make_unique<std::set<uint16_t>>();
	auto fd_table = m_tinfo->get_fd_table();
	for(const auto& fd : fd_table->m_table)
	{
		if(fd.second.m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			m_listening_ports->insert(fd.second.m_sockinfo.m_ipv4serverinfo.m_port);
		}
		if(fd.second.m_type == SCAP_FD_IPV6_SERVSOCK)
		{
			m_listening_ports->insert(fd.second.m_sockinfo.m_ipv6serverinfo.m_port);
		}
	}

	m_last_port_scan = time_point_t::clock::now();

	// Only scan procfs every procfs_scan_interval
	if (scan_procfs) {
		if (now == time_point_t::min())
			now = time_point_t::clock::now();

		auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_procfs_port_scan).count();
		if((m_last_procfs_port_scan == time_point_t::min()) ||
			(elapsed_secs >= procfs_scan_interval))
		{
			int prev_size = m_procfs_found_ports.size();
			m_procfs_found_ports.clear();

			sinsp_procfs_parser::read_process_serverports(m_tinfo->m_pid, *m_listening_ports, m_procfs_found_ports);
			m_last_procfs_port_scan = now;

			if (m_procfs_found_ports.size() != prev_size)
			{
				g_logger.format(sinsp_logger::SEV_INFO, "Updated list of listening ports for pid %" PRIi64 ", %s. Found %d new ports: %s", m_tinfo->m_pid, m_tinfo->m_comm.c_str(), m_procfs_found_ports.size() - prev_size, ports_to_string(m_procfs_found_ports).c_str());
			}
		}
	}

	for (auto port : m_procfs_found_ports)
	{
		m_listening_ports->insert(port);
	}
}

//
// Emit all the transactions that are still inactive after timeout_ns nanoseconds
//
void thread_analyzer_info::flush_inactive_transactions(uint64_t sample_end_time, uint64_t timeout_ns, bool is_subsampling)
{
	sinsp_fdtable* fdtable = m_tinfo->get_fd_table();
	bool has_thread_exited = (m_tinfo->m_flags & PPM_CL_CLOSED) != 0;

	if(fdtable == &m_tinfo->m_fdtable)
	{
		std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

		for(it = m_tinfo->m_fdtable.m_table.begin(); it != m_tinfo->m_fdtable.m_table.end(); it++)
		{
			uint64_t endtime = sample_end_time;

			if(it->second.is_transaction())
			{
				if((it->second.is_role_server() && it->second.m_usrstate->m_direction == sinsp_partial_transaction::DIR_OUT) ||
					(it->second.is_role_client() && it->second.m_usrstate->m_direction == sinsp_partial_transaction::DIR_IN))
				{
					if(it->second.m_usrstate->m_end_time >= endtime)
					{
						//
						// This happens when the sample-generating event is a read or write on a transaction FD.
						// No big deal, we're sure that this transaction doesn't need to be flushed yet
						//
						return;
					}

					//
					// Note: if the thread has exited, we don't care about the timeout and we flush the connection
					//       no matter what. We can safely assume it's ended.
					//
					if(has_thread_exited || (endtime - it->second.m_usrstate->m_end_time > timeout_ns))
					{
						sinsp_connection *connection;

						if(it->second.is_ipv4_socket())
						{
							connection = m_analyzer->get_connection(it->second.m_sockinfo.m_ipv4info, 
								endtime);

							ASSERT(connection || m_analyzer->get_num_dropped_ipv4_connections() != 0);
						}
						else if(it->second.is_unix_socket())
						{
							return;
						}
						else
						{
							ASSERT(false);
							return;
						}

						if(connection != NULL)
						{
							sinsp_partial_transaction *trinfo = it->second.m_usrstate;

							trinfo->update(m_analyzer,
								m_tinfo,
								&it->second,
								connection,
								0, 
								0,
								-1,
								sinsp_partial_transaction::DIR_CLOSE,
#if _DEBUG
								NULL,
								0,
#endif
								NULL,
								0,
								0);

							trinfo->m_bytes_in = 0;
							trinfo->m_bytes_out = 0;
						}
					}
				}

				if(is_subsampling)
				{
					sinsp_partial_transaction *trinfo = it->second.m_usrstate;
					trinfo->reset();
				}
			}
		}
	}
}

//
// Helper function to add a server transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_server_transaction(sinsp_partial_transaction* tr, bool isexternal)
{
	sinsp_trlist_entry::flags flags = (isexternal)?sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	main_thread_ainfo()->m_server_transactions_per_cpu[tr->m_cpuid].push_back(
		sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, tr->m_prev_end_time, flags));
}

const proc_config& thread_analyzer_info::get_proc_config()
{
	static const auto SYSDIG_AGENT_CONF = "SYSDIG_AGENT_CONF";
	if(!m_proc_config)
	{
		// 1. some processes (eg. redis) wipe their env
		// try to grab the env from it up to its parent (within the same container)
		auto conf = m_tinfo->get_env(SYSDIG_AGENT_CONF);
		sinsp_threadinfo::visitor_func_t visitor = [&conf, this] (sinsp_threadinfo *ptinfo)
		{
			if(!conf.empty() || ptinfo->m_container_id != this->m_tinfo->m_container_id)
			{
				return false;
			}

			conf = ptinfo->get_env(SYSDIG_AGENT_CONF);
			return true;
		};

		m_tinfo->traverse_parent_state(visitor);

		// 2. As last chance, use the Env coming from Docker
		if(conf.empty() && !m_tinfo->m_container_id.empty())
		{
			const auto container_info =
				m_inspector->m_container_manager.get_container(m_tinfo->m_container_id);
			if(container_info)
			{
				conf = container_info->m_sysdig_agent_conf;
			}
		}

		if(!conf.empty())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Found process %ld with custom conf, SYSDIG_AGENT_CONF=%s", m_tinfo->m_pid, conf.c_str());
		}
		m_proc_config = make_unique<proc_config>(conf);
	}
	return *m_proc_config;
}

//
// Helper function to add a client transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_client_transaction(sinsp_partial_transaction* tr, bool isexternal)
{
	sinsp_trlist_entry::flags flags = (isexternal)?sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	main_thread_ainfo()->m_client_transactions_per_cpu[tr->m_cpuid].push_back(
		sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, 
		tr->m_prev_end_time, flags));
}

bool thread_analyzer_info::found_app_check_by_fnmatch(const std::string& pattern)
{
#ifndef CYGWING_AGENT
	for (const auto& ac_found : m_app_checks_found)
	{
		if (!fnmatch(pattern.c_str(), ac_found.c_str(), FNM_EXTMATCH))
			return true;
	}
#else
	throw sinsp_exception("thread_analyzer_info::found_app_check_by_fnmatch not implemented on Windows");
	ASSERT(false);
#endif
	return false;
}

std::string thread_analyzer_info::ports_to_string(const std::set<uint16_t> &ports)
{
	std::string ret;
	for(auto port : ports)
	{
		ret += std::to_string(port) + ", ";
	}
	return ret.substr(0, ret.size() - 2);
}

///////////////////////////////////////////////////////////////////////////////
// analyzer_threadtable_listener implementation
///////////////////////////////////////////////////////////////////////////////
analyzer_threadtable_listener::analyzer_threadtable_listener(
		sinsp* const inspector,
		sinsp_analyzer& analyzer):
	m_inspector(inspector),
	m_analyzer(analyzer),
	m_tap(nullptr)

{ }

void analyzer_threadtable_listener::on_thread_created(sinsp_threadinfo* tinfo)
{
	void *buffer = tinfo->get_private_state(m_analyzer.get_thread_memory_id());

	std::memset(buffer, 0, sizeof(thread_analyzer_info));

	tinfo->m_ainfo = new (buffer) thread_analyzer_info(); // placement new
	tinfo->m_ainfo->m_percentiles = m_analyzer.get_configuration_read_only()->get_percentiles();
	tinfo->m_ainfo->init(&m_analyzer, m_inspector, tinfo);
}

void analyzer_threadtable_listener::on_thread_destroyed(sinsp_threadinfo* const tinfo)
{
	if(tinfo->is_main_thread() && m_tap != nullptr)
	{
		m_tap->on_exit(tinfo->m_pid);
	}
	if(tinfo->m_ainfo)
	{
		tinfo->m_ainfo->~thread_analyzer_info();
	}
}

void analyzer_threadtable_listener::set_audit_tap(const std::shared_ptr<audit_tap> &tap)
{
	m_tap = tap;
}

///////////////////////////////////////////////////////////////////////////////
// Support for thread sorting
///////////////////////////////////////////////////////////////////////////////
bool threadinfo_cmp_cpu(sinsp_threadinfo* src , sinsp_threadinfo* dst)
{
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_cpuload > 
		dst->m_ainfo->m_procinfo->m_cpuload); 
}

bool threadinfo_cmp_memory(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_vmrss_kb > 
		dst->m_ainfo->m_procinfo->m_vmrss_kb); 
}

bool threadinfo_cmp_io(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 
		dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes()); 
}

bool threadinfo_cmp_net(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 
		dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes()); 
}

bool threadinfo_cmp_transactions(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() > 
		dst->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count()); 
}

bool threadinfo_cmp_evtcnt(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	sinsp_counter_time tot;
	src->m_ainfo->m_procinfo->m_proc_metrics.get_total(&tot);
	uint64_t srctot = tot.m_count;
	tot.clear();
	dst->m_ainfo->m_procinfo->m_proc_metrics.get_total(&tot);
	uint64_t dsttot = tot.m_count;

	return (srctot > dsttot); 
}

bool threadinfo_cmp_cpu_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst)
{
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	double s = src->m_ainfo->m_procinfo->m_cpuload * (is_src_server * 1000);
	double d = dst->m_ainfo->m_procinfo->m_cpuload * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_memory_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_vmrss_kb * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_vmrss_kb * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_io_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_net_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_transactions_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() * (is_dst_server * 1000);

	return (s > d); 
}
