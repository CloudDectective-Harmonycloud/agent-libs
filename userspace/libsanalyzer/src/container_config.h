#pragma once

#include "type_config.h"

extern type_config<int64_t> c_cri_timeout_ms;
extern type_config<bool> c_cri_extra_queries;
extern type_config<std::vector<std::string>> c_cri_known_socket_paths;
extern type_config<std::string>::ptr c_cri_socket_path;

