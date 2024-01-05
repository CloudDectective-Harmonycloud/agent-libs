/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <iostream>
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <chrono>
#include "util.h"

using namespace std;

static bool g_interrupted;
static const uint8_t g_backoff_timeout_secs = 2; 

static void sigint_handler(int signum)
{
    g_interrupted = true;
}

static void usage()
{
    string usage = R"(Usage: sinsp-example [options]

Options:
  -h, --help                    Print this page
  -f <filter>                   Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields)
)";
    cout << usage << endl;
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
// 
void testPagefault(sinsp *inspector){
	//uint32_t threadcount = inspector->m_thread_manager->get_thread_count();
	threadinfo_map_t *threadmap = inspector->m_thread_manager->get_threads();
    unordered_map<int64_t, threadinfo_map_t::ptr_t> threadstable = threadmap->getThreadsTable();
    unordered_map<int64_t, int64_t> maj_mp, min_mp; //from pid to maj or min value

    //1. test initialization of therads table.
    cout << "total number of threads initialized is " << threadstable.size() << "...\n";
	for(auto e: threadstable){
		sinsp_threadinfo* tmp = e.second.get();
        if(tmp->m_pid == tmp->m_tid) continue;
        maj_mp[tmp->m_pid] += tmp->m_pfmajor;
        min_mp[tmp->m_pid] += tmp->m_pfminor;
		//cout << "pid is " << tmp->m_pid << " & tid is " << tmp->m_tid << " maj_flt: " << tmp->m_pfmajor << "\tmin_flt: " << tmp->m_pfminor << '\n';
	}
    for(auto e: min_mp){
        auto tmp = threadstable.find(e.first);
        sinsp_threadinfo* temp = inspector->build_threadinfo();
        temp->m_pid = temp->m_tid = e.first;
        temp->m_pfminor = tmp->second->m_pfminor - e.second;
        temp->m_pfmajor = tmp->second->m_pfmajor - maj_mp[e.first];
        threadstable[temp->m_tid] = threadinfo_map_t::ptr_t(temp);
    }
    for(auto e: threadstable){
		sinsp_threadinfo* tmp = e.second.get();
		cout << "pid is " << tmp->m_pid << " & tid is " << tmp->m_tid << ": maj_flt: " << tmp->m_pfmajor << "\tmin_flt: " << tmp->m_pfminor << '\n';

	}

    //2. test eBPF pagefault_map
    uint64_t last_time = 0;
    pagefault_data *results = new pagefault_data[101000];
    int32_t maxlen = 65535;
    int counts = 0;
    for(int i = 0;i < 5;i++){
        chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds>(
		    std::chrono::system_clock::now().time_since_epoch()
	    );
        uint64_t cur = ns.count();
        inspector->get_page_faults_from_map(last_time, cur, results, &counts, maxlen);
        last_time = cur;
        cout << "curtime: " << cur << "---catch " << counts << " pagefaults from 2 seconds before." << endl;
        for(int j = 0; j < counts;j++){
            cout << "pid: " << results[j].pid << " tid: " << results[j].tid << " major: " << results[j].maj_flt << " minor: " << results[j].min_flt
                 << " vmsize: " << results[j].vm_size << " vmrss: " << results[j].vm_rss << " vmswap: " << results[j].vm_swap << " timestamp: " << results[j].timestamp << endl << endl;
        }
        sleep(2);
    }
    
    delete []results;
}

int main(int argc, char **argv)
{
    sinsp inspector;

    // Parse configuration options.
    static struct option long_options[] = {
            {"help",      no_argument, 0, 'h'},
            {0,   0,         0,  0}
    };

    int op;
    int long_index = 0;
    string filter_string;
    while((op = getopt_long(argc, argv,
                            "hr:s:f:",
                            long_options, &long_index)) != -1)
    {
        switch(op)
        {
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'f':
                filter_string = optarg;
                break;
            default:
                break;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, sigint_handler);

    inspector.open();
    inspector.enable_page_faults();

    
    if(!filter_string.empty())
    {
        try
        {
            inspector.set_filter(filter_string);
        }
        catch(const sinsp_exception &e) {
            cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
        }
    }

    testPagefault(&inspector);
    
    while(!g_interrupted)
    {
        sinsp_evt* ev = NULL;
        int32_t res = inspector.next(&ev);

        if(SCAP_TIMEOUT == res)
        {
            continue;
        }
        else if(res != SCAP_SUCCESS)
        {
            cout << "[ERROR] " << inspector.getlasterr() << endl;
            sleep(g_backoff_timeout_secs);
	        continue;
        }

        sinsp_threadinfo* thread = ev->get_thread_info();
        if(thread)
        {
            string cmdline;
            sinsp_threadinfo::populate_cmdline(cmdline, thread);

            if(ev->get_type() == PPME_PAGE_FAULT_E)
            {
                 cout << "[PAGEFAULTS]:[PID=" << thread->m_pid << "]:"
                    << "[TID=" << thread->m_tid << "]:"
                    << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
                    << "[EXE=" << thread->get_exepath() << "]:"
                    << "[CMD=" << cmdline << "]"
                    << "[PAGE_FAULT_MAJOR=" << *((uint64_t *) (ev->get_param(0)->m_val)) << "]:"
                    << "[PAGE_FAULT_MINOR=" << *((uint64_t *) (ev->get_param(1)->m_val)) << "]"
                    << "[VMSIZE=" << *((uint32_t *) (ev->get_param(2)->m_val)) << "]"
                    << "[VMRSS=" << *((uint32_t *) (ev->get_param(3)->m_val)) << "]"
                    << "[VMSWAP=" << *((uint32_t *) (ev->get_param(4)->m_val)) << "]"
                    << endl << endl;     
            }

            if(thread->is_main_thread())
            { 
                string date_time;
                sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

                bool is_host_proc = thread->m_container_id.empty();
                cout << "[" << date_time << "]:["  
			              << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

                cout << "[CAT=";

                if(ev->get_category() == EC_PROCESS)
                {
                    cout << "PROCESS]:";
                }
                else if(ev->get_category() == EC_NET)
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                    sinsp_fdinfo_t* fd_info = ev->get_fd_info();

                    // event subcategory should contain SC_NET if ipv4/ipv6
                    if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
                    {
                        cout << "[" << fd_info->tostring() << "]:";
                    }
                }
                else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                    
                    sinsp_fdinfo_t* fd_info = ev->get_fd_info();
                    if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
                    {
                        cout << "[" << fd_info->tostring() << "]:";
                    }
                }
                else
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                }

                sinsp_threadinfo *p_thr = thread->get_parent_thread();
                int64_t parent_pid;
                if(nullptr != p_thr)
                {
                    parent_pid = p_thr->m_pid;
                }
                cout << "[PPID=" << parent_pid << "]:"
                          << "[PID=" << thread->m_pid << "]:"
                          << "[TID=" << thread->m_tid << "]:"
                          << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
                          << "[EXE=" << thread->get_exepath() << "]:"
                          << "[CMD=" << cmdline << "]"
                          << endl << endl;
            }
        }
        else
        {
            cout << "[EVENT]:[" << get_event_category(ev->get_category()) << "]:"
                      << ev->get_name() << endl;
        }
    }

    return 0;
}
