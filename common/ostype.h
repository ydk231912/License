#pragma once
#ifndef __OSTYPE_HH__
#define __OSTYPE_HH__
 
#ifdef _WIN32
#include <afx.h>
#define __WINDOWS__
#else
#define __LINUX__
#endif
 
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
 
#include <string>
#include <list>
#include <vector>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <string.h>
#include <time.h>
#include <assert.h>
 
#ifdef __WINDOWS__
#include <sys/timeb.h>
#include <WinSock2.h>
#endif
 
#ifdef __LINUX__
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
 
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
 
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
//#include <sys/io.h>
#include <errno.h>
//#include <linux/if.h>
#include <net/if.h>
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