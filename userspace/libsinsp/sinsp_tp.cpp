//
// Created by zhaoxiangyu on 24-4-2.
//
#include <sinsp.h>
#include "scap-int.h"
#include "unordered_map"

std::unordered_map<string, int> sinsp::get_all_kt()
{
	std::unordered_map<string, int> ppm_kt_map;
	for(uint32_t kt = 0; kt < m_h->m_bpf_prog_real_size; kt++)
	{
		auto index = m_h->kt_indices[kt];
		if(strstr(index.name,"/filler/") == nullptr)
		{
			ppm_kt_map[index.name] = kt;
		}
	}

	return ppm_kt_map;
}

static void update_ktindex(scap_t* m_h){
	static std::unordered_map<string, int> ppm_kt_map;
	if(ppm_kt_map.empty()){
		for(uint32_t kt = 0; kt < m_h->m_bpf_prog_real_size; kt++)
		{
			auto index = m_h->kt_indices[kt];
			ppm_kt_map[index.name] = kt;
		}
	}
	for(int i = 0; i < m_h->m_bpf_prog_cnt;i++){
		auto name = m_h->m_bpf_progs[i].name;
		m_h->kt_indices[ppm_kt_map[name]].index = i;
	}
}
void sinsp::mark_kt_of_interest(uint32_t tp, bool enable)
{
	/* This API must be used only after the initialization phase. */
	if (!is_live())
	{
		throw sinsp_exception("you cannot use this method before opening the inspector or if the running mode isn't BPF!");
	}
	int ret = scap_set_ktmask(m_h, tp, enable);
	update_ktindex(m_h);

	if (ret != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}
