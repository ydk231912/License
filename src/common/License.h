#pragma once
#ifndef __SNFACTORY_H__
#define __SNFACTORY_H__

// ANSC C/C++
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
 
#define MAX_LICENSE_SIZE 32

namespace seeder {

class CLicense
{
public:
	CLicense();
	CLicense(const CLicense& other);
	bool operator !=(const CLicense& other);
	bool operator ==(const CLicense& other);
 
	bool Create();
	bool encrypt_handle();
	bool serialize_source_handle(const char* str_file, bool b_storing);
	std::string to_strings() const;
	bool serialize_encrypt_handle(const char* str_file, bool b_storing);
	std::string to_string() const;
	void set_macaddr_type(int mMacType){is_mac_type = mMacType;} // 设置取物理地址类型
private:
	bool string_divide(std::vector<std::string> &_str_list, const std::string src, const std::string div);
protected:
	bool source_flag;
	char sz_macaddress[128];
	unsigned char addr[6];
	unsigned char by_macaddr_len;
	char m_sz_license[MAX_LICENSE_SIZE];
	int get_hdsn(char * szSN, int n);
	int is_mac_type;
}; // class CLicense
} // namespace seeder

 
#endif  /*__SNFACTORY_H__*/