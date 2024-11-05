#include "License.h"
#include "ostype.h"
 
#ifdef _WIN32
/*增加硬盘序列码*/
#include <Windows.h>
#include <winioctl.h>
#define SMART_GET_VERSION       CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
#include <Iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#else
// linux
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
 
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>  // socket
#include <arpa/inet.h>
#include <sys/times.h>  // time
#include <sys/select.h> 
#include <sys/ioctl.h>
#include <net/if.h>
//#include <net/if_arp.h>
#include <linux/hdreg.h> //Drive specific defs
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdexcept>
#endif
 
namespace seeder {

/*取硬盘序列码*/
static unsigned short get_license(unsigned char* byData,unsigned short wLen)
{
	static const unsigned short crc_table[256] = 
	{
		0x0000,0x365e,0x6cbc,0x5ae2,0xd978,0xef26,0xb5c4,0x839a,0xff89,0xc9d7,0x9335,0xa56b,0x26f1,0x10af,0x4a4d,0x7c13,
		0xb26b,0x8435,0xded7,0xe889,0x6b13,0x5d4d,0x07af,0x31f1,0x4de2,0x7bbc,0x215e,0x1700,0x949a,0xa2c4,0xf826,0xce78,
		0x29af,0x1ff1,0x4513,0x734d,0xf0d7,0xc689,0x9c6b,0xaa35,0xd626,0xe078,0xba9a,0x8cc4,0x0f5e,0x3900,0x63e2,0x55bc,
		0x9bc4,0xad9a,0xf778,0xc126,0x42bc,0x74e2,0x2e00,0x185e,0x644d,0x5213,0x08f1,0x3eaf,0xbd35,0x8b6b,0xd189,0xe7d7,
		0x535e,0x6500,0x3fe2,0x09bc,0x8a26,0xbc78,0xe69a,0xd0c4,0xacd7,0x9a89,0xc06b,0xf635,0x75af,0x43f1,0x1913,0x2f4d,
		0xe135,0xd76b,0x8d89,0xbbd7,0x384d,0x0e13,0x54f1,0x62af,0x1ebc,0x28e2,0x7200,0x445e,0xc7c4,0xf19a,0xab78,0x9d26,
		0x7af1,0x4caf,0x164d,0x2013,0xa389,0x95d7,0xcf35,0xf96b,0x8578,0xb326,0xe9c4,0xdf9a,0x5c00,0x6a5e,0x30bc,0x06e2,
		0xc89a,0xfec4,0xa426,0x9278,0x11e2,0x27bc,0x7d5e,0x4b00,0x3713,0x014d,0x5baf,0x6df1,0xee6b,0xd835,0x82d7,0xb489,
		0xa6bc,0x90e2,0xca00,0xfc5e,0x7fc4,0x499a,0x1378,0x2526,0x5935,0x6f6b,0x3589,0x03d7,0x804d,0xb613,0xecf1,0xdaaf,
		0x14d7,0x2289,0x786b,0x4e35,0xcdaf,0xfbf1,0xa113,0x974d,0xeb5e,0xdd00,0x87e2,0xb1bc,0x3226,0x0478,0x5e9a,0x68C4,
		0x8f13,0xb94d,0xe3af,0xd5f1,0x566b,0x6035,0x3ad7,0x0c89,0x709a,0x46c4,0x1c26,0x2a78,0xa9e2,0x9fbc,0xc55e,0xf300,
		0x3d78,0x0b26,0x51c4,0x679a,0xe400,0xd25e,0x88bc,0xbee2,0xc2f1,0xf4af,0xae4d,0x9813,0x1b89,0x2dd7,0x7735,0x416b,
		0xf5e2,0xc3bc,0x995e,0xaf00,0x2c9a,0x1ac4,0x4026,0x7678,0x0a6b,0x3c35,0x66d7,0x5089,0xd313,0xe54d,0xbfaf,0x89f1,
		0x4789,0x71d7,0x2b35,0x1d6b,0x9ef1,0xa8af,0xf24d,0xc413,0xb800,0x8e5e,0xd4bc,0xe2e2,0x6178,0x5726,0x0dc4,0x3b9a,
		0xdc4d,0xea13,0xb0f1,0x86af,0x0535,0x336b,0x6989,0x5fd7,0x23c4,0x159a,0x4f78,0x7926,0xfabc,0xcce2,0x9600,0xa05e,
		0x6e26,0x5878,0x029a,0x34c4,0xb75e,0x8100,0xdbe2,0xedbc,0x91af,0xa7f1,0xfd13,0xcb4d,0x48d7,0x7e89,0x246b,0x1235
	};
 
	unsigned short store_crc = 0;
	for (unsigned short i = 0; i < wLen; i++) {
		store_crc = (store_crc / 256) ^ (crc_table[(store_crc % 256) ^ byData[i]]);
	}
	return (store_crc ^ 0xffff);
}

CLicense::CLicense()
{
	source_flag = false;
	memset(sz_macaddress, '\0', 128);
	memset(addr, '\0', 6);
	by_macaddr_len = 0;
	memset(m_sz_license, '\0', MAX_LICENSE_SIZE);
	is_mac_type = 0; // 缺省为取网卡地址
}

CLicense::CLicense(const CLicense& other) {
 
}
 
bool CLicense::operator !=(const CLicense& other)
{
	bool b = strcmp(m_sz_license, other.m_sz_license) != 0;
	return b;
}

bool CLicense::operator ==(const CLicense& other)
{
	printf("%s==%s\n", m_sz_license, other.m_sz_license);
	bool b = strcmp(m_sz_license, other.m_sz_license) == 0;
	return b;
}
 
/*获取网卡或磁盘信息*/
bool CLicense::Create()
{
	source_flag = false;
 
#ifdef _WIN32
if (is_mac_type == 0) // 取网卡地址 
{
	DWORD m_dwNetCardCount = 0;
	PIP_ADAPTER_INFO m_pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
 
	DWORD dwRetVal = GetAdaptersInfo(m_pAdapterInfo, &ulOutBufLen);
	if (dwRetVal == ERROR_BUFFER_OVERFLOW)
	{
		free(m_pAdapterInfo);
		m_pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		dwRetVal = GetAdaptersInfo(m_pAdapterInfo, &ulOutBufLen);
	}
 
	if (dwRetVal == NO_ERROR)
	{
		PIP_ADAPTER_INFO pAdapter = m_pAdapterInfo;
		while (pAdapter)
		{
			TRACE("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			TRACE("\tAdapter Desc: \t%s\n", pAdapter->Description);
			TRACE("\tAdapter Addr: \t%ld\n", pAdapter->Address);
			TRACE("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
			TRACE("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);
 
			TRACE("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
			TRACE("\t***\n");
			if (pAdapter->DhcpEnabled)
			{
				TRACE("\tDHCP Enabled: Yes\n");
				TRACE("\t\tDHCP Server: \t%s\n", pAdapter->DhcpServer.IpAddress.String);
				TRACE("\tLease Obtained: %ld\n", pAdapter->LeaseObtained);
			}
			else
				TRACE("\tDHCP Enabled: No\n");
 
			if (pAdapter->HaveWins)
			{
				TRACE("\tHave Wins: Yes\n");
				TRACE("\t\tPrimary Wins Server: \t%s\n", pAdapter->PrimaryWinsServer.IpAddress.String);
				TRACE("\t\tSecondary Wins Server: \t%s\n", pAdapter->SecondaryWinsServer.IpAddress.String);
			}
			else
				TRACE("\tHave Wins: No\n");
 
			pAdapter = pAdapter->Next;
			m_dwNetCardCount++;
		}
	}
	else
	{
		free(m_pAdapterInfo);
		m_pAdapterInfo = NULL;
	}
 
	PIP_ADAPTER_INFO pAdapter = m_pAdapterInfo;
	while (pAdapter)
	{
		sprintf(sz_macaddress, "%02X-%02X-%02X-%02X-%02X-%02X", 
			pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2], 
			pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
 
		addr[0] = pAdapter->Address[0];
		addr[1] = pAdapter->Address[1];
		addr[2] = pAdapter->Address[2];
		addr[3] = pAdapter->Address[3];
		addr[4] = pAdapter->Address[4];
		addr[5] = pAdapter->Address[5];
 
		pAdapter = pAdapter->Next;
 
		source_flag = true;
		break;
	}
}
else // 取磁盘码 
{
	for (int i=0; i<5; i++)
	{
		memset(sz_macaddress,0x00,sizeof(sz_macaddress));
		if ((by_macaddr_len=get_hdsn(sz_macaddress,i))>0)
		{
			source_flag = true;
			break;
		}
	}
}
#else
	/* implementation for Linux */
	int fd;
	if (is_mac_type == 0)	// 取网卡序列号
	{
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		printf("socket fd is %d!\n",fd);
		if (fd == -1) {
			return source_flag;
		}
 
		char buf[1024];
		struct ifconf ifc;
		int ok = 0;
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = buf;
		ioctl(fd, SIOCGIFCONF, &ifc);
 
		struct ifreq *IFR = ifc.ifc_req;
		struct ifreq ifr;
 
		for (int i = ifc.ifc_len/sizeof(struct ifreq); --i >= 0; IFR++)
		{
			strcpy(ifr.ifr_name, IFR->ifr_name);
			if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) 
			{
				if (!(ifr.ifr_flags & IFF_LOOPBACK) && (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0))
				{
					ok = 1;
					break;
				}
			}
		}
		close(fd);
		if (ok)
		{
			bcopy(ifr.ifr_hwaddr.sa_data, addr, 6);
			source_flag = true;
		}else{
			printf("ifr.ifr_hwaddr.sa_data is NULL!\n");
		}
	}
	else	// 取磁盘码
	{
		struct hd_driveid hd;
		int ok = 0;
		memset(sz_macaddress,0x00,sizeof(sz_macaddress));
		bool openf = true;
		if ((fd = open("/dev/hdc", O_RDONLY|O_NONBLOCK)) < 0
			&& (fd = open("/dev/hdb", O_RDONLY|O_NONBLOCK)) < 0
			&& (fd = open("/dev/sda", O_RDONLY|O_NONBLOCK)) < 0
			&& (fd = open("/dev/sdb", O_RDONLY|O_NONBLOCK)) < 0) 
		{
			printf("open /dev/hdc fail!\n");
			return source_flag;
		}
		
		if (!ioctl(fd, HDIO_GET_IDENTITY, &hd)) {
			printf("Hard Disk Model: %.40s\n", hd.model);
			printf("  Serial Number: %.20s\n", hd.serial_no);
			ok = 1;
		}
		if (ok)
		{
			sprintf(sz_macaddress,"%.20s",hd.serial_no);
			by_macaddr_len = strlen(sz_macaddress);
			source_flag = true;
		}else{
			printf("sz_macaddress is NULL!\n");
		}
	}
#endif
	return source_flag;
}

/*加密*/
bool CLicense::encrypt_handle()
{
	if (!source_flag) {
		return false;
	}

	// 1. 网卡地址加密
	if (is_mac_type == 0) 
	{
		// 1.1 将网卡地址格式化为字符串
		sprintf(sz_macaddress, "%0X-%0X-%0X-%0X-%0X-%0X\n", 
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]); 

		// 1.2 对网卡地址进行异或操作
		for (unsigned char b = 0; b < 6; b++) {
			addr[b] ^= 2 * (b + 1) + 0x88;
		}

		// 1.3 计算网卡地址的CRC32校验码
		unsigned long dwCRC = get_license(&addr[0], 2) + (get_license(&addr[2], 4) << 16);

		// 1.4 将CRC32校验码格式化为字符串
		sprintf(m_sz_license, "%lu", dwCRC);

		// 1.5 对生成的字符串进行字符替换
		for (unsigned int i = 0; i < strlen(m_sz_license); i++) {
			if (m_sz_license[i] <= '5') {
				m_sz_license[i] = m_sz_license[i] - '0' + 'A';
			} else {
				m_sz_license[i] = m_sz_license[i] - '6' + '0';
			}
		}
	}
	else // 2. 硬盘序列码加密
	{
		char buf[128] = { '\0' };

		// 2.1 对硬盘序列号进行加密
		for (int i = 0; i < by_macaddr_len && i < sizeof(m_sz_license); i++) {
			// 2.1 计算硬盘序列的CRC32校验码
			m_sz_license[i] = (u_char)get_license((u_char *)&sz_macaddress[i], by_macaddr_len - i);

			// 2.2 对加密后的字符进行字符替换
			if (m_sz_license[i] <= '5') {
				m_sz_license[i] = m_sz_license[i] - '0' + 'A';
			} else {
				m_sz_license[i] = m_sz_license[i] - '6' + '0';
			}
			
			// 2.3 将字符转换为十六进制字符串	
			char tmp[3] = { '\0' };
			sprintf(tmp, "%02X", (u_char)m_sz_license[i]);
			strncat(buf, tmp, strlen(tmp));
		}

		// 2.4 将生成的十六进制字符串复制到 m_sz_license
		strncpy(m_sz_license, buf, (strlen(buf) >= MAX_LICENSE_SIZE) ? (MAX_LICENSE_SIZE - 1) : strlen(buf));
	}
	printf("mac address %s ==> %s\n", sz_macaddress, m_sz_license);
	return true;
};
 
/*分割字符串*/
bool CLicense::string_divide(std::vector<std::string> &_str_list, const std::string src, const std::string div)
{
	std::string _src = src;
	// 查找分隔符的位置
	std::string::size_type _pos = _src.find(div);

	// 分割字符串
	while (std::string::npos != _pos)
	{
		std::string _buf = ""; // 存储当前找到的子字符串
		_buf = _src.substr(0, _pos);
		_str_list.push_back(_buf);
		_src = _src.erase(0, _pos + div.size());
		_pos = _src.find(div.c_str());
	}

	// 处理剩余的字符串
	if (!_src.empty()) {
		_str_list.push_back(_src);
	}
	return true;
};

/*处理序列源*/
bool CLicense::serialize_source_handle(const char* str_file, bool b_storing)
{
	if (b_storing) {
		// 保存
		if (strlen(sz_macaddress) > 0) {
			std::ofstream f_license(str_file);
			f_license.write(sz_macaddress, strlen(sz_macaddress));
			return true;
		}
	} else {
		// 读取
		std::ifstream f_license(str_file);
		f_license.read(sz_macaddress, MAX_LICENSE_SIZE);
		by_macaddr_len = static_cast<unsigned char>(strlen(sz_macaddress));
		bool read_flag = by_macaddr_len > 0 ? true : false;
		bool map_flag = false;

		// 解析网卡地址
		if (0 == is_mac_type) {
			std::vector<std::string> _str_list;

			// 分割字符串
			if (string_divide(_str_list,std::string(sz_macaddress),"-")) {
				try
				{
					// 解析子字符串
					if (6 == _str_list.size()) {
						for (int index = 0; index < 6; index++) {
							int n = 0;
							for (int i = 0; i < 2; i++) {
								// 十六进制还要判断他是不是在A-F或者a-f之间a=10
								if (_str_list.at(index)[i] >= 'A' && _str_list.at(index)[i] <= 'F') {
									n = _str_list.at(index)[i] - 'A' + 10;
								} else if (_str_list.at(index)[i] >= 'a' && _str_list.at(index)[i] <= 'f') {
									n = _str_list.at(index)[i] - 'a' + 10;
								} else {
									n = _str_list.at(index)[i] - '0';
								}
								addr[index] = addr[index] * 16 + n;
							}
						}
						map_flag = true;
					} else {
						#ifdef WIN32
						throw std::exception("MacAddress be split by \'-\' and size isn't 6");
						#else
						throw std::logic_error("MacAddress be split by \'-\' and size isn't 6");
						#endif
					}
				}
				catch (const std::exception& e) {
					printf("error(%s) for serialize_source_handle\r\n",e.what());
				}
			}
		}
		else {
			map_flag = true;
		}
		source_flag = read_flag && map_flag;
		return read_flag;
	}
	return false;
};

std::string CLicense::to_strings() const
{
	std::string strName = sz_macaddress;
	return strName;
};
 
/*处理加密序列*/
bool CLicense::serialize_encrypt_handle(const char* str_file, bool b_storing)
{
	if (b_storing) {
		// save
		if (strlen(m_sz_license) > 0) {
			std::ofstream f_license(str_file);
			f_license.write(m_sz_license, strlen(m_sz_license));
			return true;
		}
	} else {
		// read
		std::ifstream f_license(str_file);
		f_license.read(m_sz_license, MAX_LICENSE_SIZE);
		return strlen(m_sz_license) > 0;
	}
	return false;
}
 

std::string CLicense::to_string() const
{
	std::string strName = m_sz_license;
	return strName;
}
 
/*取硬盘序列码*/
int CLicense::get_hdsn(char * szSN, int n) 
{
	//int done = -1;
	int ret = 0;
#ifdef _WIN32
	{
		char szHDName[512];
		sprintf_s(szHDName, "\\\\.\\PhysicalDrive%d", n);
		HANDLE hPhysicalDriveIOCTL = 0;
		hPhysicalDriveIOCTL = CreateFile (szHDName,
			GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, 0, NULL);
		if (hPhysicalDriveIOCTL == INVALID_HANDLE_VALUE)
		{
			TRACE("\tCreateFile Ret : INVALID_HANDLE_VALUE\n");
			printf("CreateFile Return(INVALID_HANDLE_VALUE) and error(%d)\n", GetLastError());
		}
		else
		{
			GETVERSIONINPARAMS GetVersionParams;
			DWORD cbBytesReturned = 0;
			memset ((void*) & GetVersionParams, 0, sizeof(GetVersionParams));
			if ( ! DeviceIoControl (hPhysicalDriveIOCTL, SMART_GET_VERSION,
				NULL, 
				0,
				&GetVersionParams, sizeof (GETVERSIONINPARAMS),
				&cbBytesReturned, NULL) )
			{         
				;
			}
			else
			{
				ULONG CommandSize = sizeof(SENDCMDINPARAMS) + IDENTIFY_BUFFER_SIZE;
				PSENDCMDINPARAMS Command = (PSENDCMDINPARAMS) malloc (CommandSize);
				//#define ID_CMD          0xEC            // Returns ID sector for ATA
				Command -> irDriveRegs.bCommandReg = 0xEC; //ID_CMD;
				DWORD BytesReturned = 0;
				if ( ! DeviceIoControl (hPhysicalDriveIOCTL,
					SMART_RCV_DRIVE_DATA, Command, sizeof(SENDCMDINPARAMS),
					Command, CommandSize,
					&BytesReturned, NULL) )
				{
					;
				} 
				else
				{
					DWORD diskdata [256];
					USHORT *pIdSector = (USHORT *)
						/*(PIDENTIFY_DATA)*/ ((PSENDCMDOUTPARAMS) Command) -> bBuffer;
					printf("disk data:\n");
					for (int ijk = 0; ijk < 256; ijk++) {
						diskdata[ijk] = pIdSector[ijk];
						//printf("%ld ", diskdata[ijk]);
					}
					printf("\n");
					if(szSN)
					{
						int index = 0;
						int position = 0;
						for (index = 10; index <= 19; index++)
						{
							szSN [position++] = (char) (diskdata [index] / 256);
							szSN [position++] = (char) (diskdata [index] % 256);
						}
						szSN[position] = '\0';
						for (index = position - 1; index > 0 && isspace(szSN [index]); index--)
							szSN [index] = '\0';
					}
					//done = TRUE;
				}
				CloseHandle (hPhysicalDriveIOCTL);
				free (Command);
				Command = NULL;
			}
		}
	}
	ret = static_cast<int>(strlen(szSN));
#else
;
#endif
	return ret;
}
} // namespace seeder