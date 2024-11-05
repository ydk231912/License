#pragma once
#ifndef __OSTYPE_HH__
#define __OSTYPE_HH__
 
#ifdef _WIN32
#define __WINDOWS__
#else
#define __LINUX__
#endif
 
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
 
#ifdef __WINDOWS__
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <afx.h>
#include <time.h>
#include <shlwapi.h>
#include <windows.h>
#include <cryptopp/rsa.h>
#include <cryptopp/randpool.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#define MAX_COMMAND_SIZE 10000 // 命令行输出缓冲大小
#define CMD _T("wmic csproduct get UUID") // 获取BIOS命令行
#define SEARCH_STR _T("UUID") // 主板序列号的前导信息
#pragma comment(lib, "wbemuuid.lib")
#endif
 
#ifdef __LINUX__
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cryptopp/rsa.h>
#include <cryptopp/randpool.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <ctime>
#define MAX_COMMAND_SIZE 1024 // 命令行输出缓冲大小
#define CMD "dmidecode -s system-uuid" // 获取BIOS命令行
#define SEARCH_STR "System UUID: " // 主板序列号的前导信息
#define _atoi64(val) strtoll(val, NULL, 10)
#endif
 
#define _COMMONITOR
#define _BACK
 
typedef long long				INT64;
typedef unsigned long long		UINT64;
typedef unsigned char			BYTE;
typedef unsigned short			WORD;
typedef long					LONG;
typedef unsigned long			DWORD;
typedef int						BOOL;
typedef unsigned int			UINT;
 
#ifndef NULL
#define NULL 0
#endif
 
#ifndef TRUE
#define TRUE true
#endif
 
#ifndef FALSE
#define FALSE false
#endif
 
#ifdef UNICODE
typedef std::wstring XString;
#else
typedef std::string XString;
#endif
 
using namespace std;
 
#endif  /* __EXX_HH__ */