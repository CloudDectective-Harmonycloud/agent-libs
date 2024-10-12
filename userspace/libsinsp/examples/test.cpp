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
#include <memory>
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "util.h"
#include "unordered_set"
#include "eventformatter.h"
#include <arpa/inet.h>


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
    inspector.set_bpf_probe("../../../driver/bpf/probe.o");
    inspector.open();
    inspector.enable_page_faults();

    //添加filter
    std::unique_ptr<set<uint32_t>> evttypes (new set<uint32_t>());
    std::unique_ptr<set<uint32_t>> syscalls (new set<uint32_t>());
    //	evttypes->insert(PPME_TCP_CONNECT_E);
    //	evttypes->insert(PPME_SYSCALL_CLONE_11_X);
    //	evttypes->insert(PPME_SYSCALL_CLONE_16_X);
    //	evttypes->insert(PPME_SYSCALL_CLONE_17_X);
    //	evttypes->insert(PPME_SYSCALL_CLONE_20_X);
    //	evttypes->insert(PPME_SYSCALL_CLONE_11_E);
    //	evttypes->insert(PPME_TCP_CONNECT_X);

//    string filter_name = "open";
//    set<string> filter_tags = {"a"};
//    inspector.add_evttype_filter(filter_name,*evttypes,*syscalls,filter_tags,NULL);
//    inspector.m_filter =NULL;
//    if(inspector.m_evttype_filter){
//    	inspector.m_evttype_filter->enable(filter_name, true,0);
//    	std::cout<<"开启筛选"<<std::endl;
//    }

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
	///fd 开关测试
	bool fd_test = true;
	if(fd_test){

		static int flag = 1;
		if(flag){
			auto kt_map = inspector.get_all_kt();
			flag = 0;
			for(auto item : kt_map){
				cout <<"name:"+item.first<<" id:" <<item.second<<endl;
			}
			{
				string close_event_name = "raw_tracepoint/sys_exit";
				inspector.mark_kt_of_interest(kt_map[close_event_name], false);
			}
			{
				string close_event_name = "raw_tracepoint/sys_enter";
				inspector.mark_kt_of_interest(kt_map[close_event_name], false);
			}
			{
				string close_event_name = "raw_tracepoint/page_fault_kernel";
				inspector.mark_kt_of_interest(kt_map[close_event_name], false);
			}
			{
				string close_event_name = "raw_tracepoint/page_fault_user";
				inspector.mark_kt_of_interest(kt_map[close_event_name], false);
			}
			{
				string close_event_name = "raw_tracepoint/sched_switch";
				inspector.mark_kt_of_interest(kt_map[close_event_name], false);
			}
//			{
//				string close_event_name = "raw_tracepoint/page_fault_user";
//				inspector.mark_kt_of_interest(kt_map[close_event_name], true);
//			}
//			char cmd[200];

//			size_t pos = close_event_name.rfind('/');
//			if(pos != std::string::npos){
//				snprintf(cmd,sizeof cmd,"sudo bpftool perf|grep %s",close_event_name.substr(pos+1).c_str());
//				system(cmd);
////			}
//                      2265 - 2388 = 124
//			for(auto item : kt_map){
//				inspector.mark_kt_of_interest(item.second, false);
//			}
//			//2265 - 2364 = 100
//			sleep(10);
////			inspector.mark_kt_of_interest(kt_map[close_event_name], true);
//			for(auto item : kt_map){
//				inspector.mark_kt_of_interest(item.second, true);
//			}
//			inspector.get_all_kt();
//			puts("123");
//			inspector.mark_kt_of_interest(kt_map[close_event_name], false);
//			inspector.mark_kt_of_interest(kt_map[close_event_name], true);
		}

	}
        //新增
        ///打印所有系统事件
        bool print_sysevt = true;
        if(print_sysevt){
            string line;
            string output_format =
                "*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name "
                "(%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";
            auto formatter = new sinsp_evt_formatter(&inspector, output_format);
            if (formatter->tostring(ev, &line)) {
                cout << line << endl;
            }
        }

        ///打印kfree_skb_reason事件
        bool print_kfree_skb_reson = false;
        if(ev->get_type()==PPME_TCP_CONNECT_X&&print_kfree_skb_reson){

            //				string line;
            //				string output_format ="%evt.info";
            //				auto formatter = new sinsp_evt_formatter(&inspector, output_format);
            //				if (formatter->tostring(ev, &line))
            //					cout << line << endl;

            char* reason;
            for(int i=0; i<ev->get_num_params();i++){
                auto info = ev->get_param_info(i);
                auto param = ev->get_param(i);
                auto payload =  param->m_val;

                auto payload_len = param->m_len;
                if(i==0)reason=payload;
                if(payload_len == 1 + 4 + 2 + 4 + 2)
                {

                    ipv4tuple addr;
                    struct in_addr addr_ip_s={0};
                    struct in_addr addr_ip_d={0};
                    addr.m_fields.m_sip = *(uint32_t*)(payload + 1);
                    addr.m_fields.m_sport = *(uint16_t*)(payload+5);
                    addr.m_fields.m_dip = *(uint32_t*)(payload + 7);
                    addr.m_fields.m_dport = *(uint16_t*)(payload+11);
//					if(addr.m_fields.m_dip == 3480357386 ||addr.m_fields.m_dip==0||*(unsigned long *)reason==0)continue;
                    //					if(*(unsigned long *)reason==0)continue;
                    std::cout<<"reason:"<<*(unsigned long *)reason<<std::endl;
                    addr_ip_s.s_addr = htonl(addr.m_fields.m_sip);  // 将主机字节序转换为网络字节序
                    char* ip_str_s = inet_ntoa(addr_ip_s);
                    std::cout<<"sip:"<< ip_str_s;
                    addr_ip_d.s_addr = htonl(addr.m_fields.m_dip);  // 将主机字节序转换为网络字节序
                    char* ip_str_d = inet_ntoa(addr_ip_d);
                    std::cout<<"     dip:"<<ip_str_d<<"   sport:"<<addr.m_fields.m_sport<<"  dport:"<<addr.m_fields.m_dport;
                    puts("");
                }

                //			std::cout<<ev->get_param(i);
            }

        }

#ifdef GATHER_INTERNAL_STATS
        static int count = 0;
        count++;
        ///打印stats信息
        bool print_stats = false;
        if(print_stats && count > 100000){
            count=0;
            inspector.m_thread_manager->get_metric_val();
            inspector.get_stats();
            auto stats = &inspector.m_stats;
            std::cout<<"    Removed threads:"<<inspector.m_thread_manager->metric_table.val_removed_threads;
            std::cout<<"    Number of added threads:"<<inspector.m_thread_manager->metric_table.val_added_threads;
            std::cout<<"    Non cached thread lookups:"<<inspector.m_thread_manager->metric_table.val_non_cached_lookups;
            std::cout<<"    Cached thread lookups:"<<inspector.m_thread_manager->metric_table.val_cached_lookups;
            std::cout<<"    Failed thread lookups:"<<inspector.m_thread_manager->metric_table.val_failed_lookups<<std::endl;
            printf("evts seen by driver: %" PRIu64 "\n", stats->m_n_seen_evts);
            printf("drops: %" PRIu64 "\n", stats->m_n_drops);
            printf("preemptions: %" PRIu64 "\n", stats->m_n_preemptions);
            printf("fd lookups: %" PRIu64 "(%" PRIu64 " cached %" PRIu64 " noncached)\n",
                   stats->m_n_noncached_fd_lookups + stats->m_n_cached_fd_lookups,
                   stats->m_n_cached_fd_lookups,
                   stats->m_n_noncached_fd_lookups);
            printf("failed fd lookups: %" PRIu64 "\n", stats->m_n_failed_fd_lookups);
            printf("n. threads: %" PRIu64 "\n", stats->m_n_threads);
            printf("n. fds: %" PRIu64 "\n", stats->m_n_fds);
            printf("added fds: %" PRIu64 "\n", stats->m_n_added_fds);
            printf("removed fds: %" PRIu64 "\n", stats->m_n_removed_fds);
            printf("stored evts: %" PRIu64 "\n", stats->m_n_stored_evts);
            printf("store drops: %" PRIu64 "\n", stats->m_n_store_drops);
            printf("retrieved evts: %" PRIu64 "\n", stats->m_n_retrieved_evts);
            printf("retrieve drops: %" PRIu64 "\n", stats->m_n_retrieve_drops);
            for(auto it :stats->m_n_retrieve_list){
                std::cout<<"  "<<it.first<<": "<<it.second;
            }
            puts("");
        }
#endif

        //	if(s.find(get_event_type(ev->get_type()))==s.end()){
        //		std::cout<<get_event_type(ev->get_type())<<" params  num :"<<ev->get_num_params()<<std::endl;
        ////		s.insert(get_event_type(ev->get_type()));
        ////		for(int i=0; i<ev->get_num_params();i++){
        ////			auto info = ev->get_param_info(i);
        ////
        ////			std::cout<<"                  "<<ev->get_param_name(i)<<":"<<info->type;
        ////			if(info->name=="length")std::cout<<ev->get_param(i).;
        ////		}
        ////		puts("");
        //		string line;
        //		string output_format =
        //			"*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name "
        //			"(%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";
        //		auto formatter = new sinsp_evt_formatter(&inspector, output_format);
        //		if (formatter->tostring(ev, &line)) {
        //			cout << line << endl;
        //		}
        //	}
        continue;

        //新增

        //	if(ev->get_type()==PPME_TCP_CONNECT_X){
        //		std::cout<<ev->get_type()<<endl;
        //		string line;
        //		string output_format =
        //			"*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name "
        //			"(%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";
        //		auto formatter = new sinsp_evt_formatter(&inspector, output_format);
        //		if (formatter->tostring(ev, &line))
        //			cout << line << endl;
        //	}
        continue;

        sinsp_threadinfo* thread = ev->get_thread_info();
        if(thread)
        {
            string cmdline;
            sinsp_threadinfo::populate_cmdline(cmdline, thread);

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
                          << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
                          << "[EXE=" << thread->get_exepath() << "]:"
                          << "[CMD=" << cmdline << "]"
                          << endl;
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
