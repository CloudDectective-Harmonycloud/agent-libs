#include "subprocesses_logger.h"
#include "logger.h"
#include "utils.h"

pipe_manager::pipe_manager()
{
	// Create pipes
	int ret = pipe(m_inpipe);
	ASSERT(ret == 0);
	ret = pipe(m_outpipe);
	ASSERT(ret == 0);
	ret = pipe(m_errpipe);
	ASSERT(ret == 0);

	// transform to FILE*
	m_input_fd = fdopen(m_inpipe[PIPE_WRITE], "w");
	m_output_fd = fdopen(m_outpipe[PIPE_READ], "r");
	m_error_fd = fdopen(m_errpipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_outpipe[PIPE_READ]);
	enable_nonblocking(m_errpipe[PIPE_READ]);
	enable_nonblocking(m_inpipe[PIPE_WRITE]);
}

pipe_manager::~pipe_manager()
{
	close(m_inpipe[PIPE_READ]);
	fclose(m_input_fd);
	close(m_outpipe[PIPE_WRITE]);
	fclose(m_output_fd);
	close(m_errpipe[PIPE_WRITE]);
	fclose(m_error_fd);
}

void pipe_manager::attach_child_stdio()
{
	dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
	dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
	dup2(m_inpipe[PIPE_READ], STDIN_FILENO);
	// Close the other part of the pipes
	fclose(m_input_fd);
	fclose(m_output_fd);
	fclose(m_error_fd);
}

void pipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

void sdjagent_parser::operator()(const string& data)
{
	// Parse log level and use it
	Json::Value sdjagent_log;
	bool parsing_ok = m_json_reader.parse(data, sdjagent_log, false);
	if(parsing_ok)
	{
		string log_level = sdjagent_log["level"].asString();
		string log_message = "sdjagent, " + sdjagent_log["message"].asString();
		if(log_level == "SEVERE")
		{
			g_log->error(log_message);
		}
		else if(log_level == "WARNING")
		{
			g_log->warning(log_message);
		}
		else if(log_level == "INFO")
		{
			g_log->information(log_message);
		}
		else
		{
			g_log->debug(log_message);
		}
	}
	else
	{
		g_log->error("Cannot parse Log from sdjagent: " + data);
	}
}

subprocesses_logger::subprocesses_logger(dragent_configuration *configuration, log_reporter* reporter) :
		m_configuration(configuration),
		m_log_reporter(reporter),
		m_max_fd(0),
		m_last_loop_ns(0)
{
	FD_ZERO(&m_readset);
	memset(&m_timeout, 0, sizeof(struct timeval));
	m_timeout.tv_sec = 1;
}

void subprocesses_logger::run()
{
	m_pthread_id = pthread_self();
	g_log->information("subprocesses_logger: Starting");

	while(!dragent_configuration::m_terminate)
	{
		m_last_loop_ns = sinsp_utils::get_current_time_ns();
		fd_set readset_w;
		memcpy(&readset_w, &m_readset, sizeof(fd_set));
		struct timeval timeout_w;
		memcpy(&timeout_w, &m_timeout, sizeof(timeval));

		int result = select(m_max_fd+1, &readset_w, NULL, NULL, &timeout_w);

		if(result > 0 )
		{
			for(const auto& fds : m_error_fds)
			{
				if(FD_ISSET(fileno(fds.first), &readset_w))
				{
					string data;
					auto available_stream = fds.first;
					static const int READ_BUFFER_SIZE = 1024;
					char buffer[READ_BUFFER_SIZE] = "";
					char* fgets_res = fgets(buffer, READ_BUFFER_SIZE, available_stream);
					while(fgets_res != NULL && strstr(buffer, "\n") == NULL)
					{
						data.append(buffer);
						fgets_res = fgets(buffer, READ_BUFFER_SIZE, available_stream);
					}
					data.append(buffer);
					fds.second(data);
				}
			}
		}

		if(dragent_configuration::m_send_log_report)
		{
			m_log_reporter->send_report();
			dragent_configuration::m_send_log_report = false;
		}
	}
	g_log->information("subprocesses_logger terminating");
}
