#include "../common/License.h"

/*软件License测试*/
int main(int argc, char *argv[])
{
	printf("Run ...\n");
	int license_mode=0;
	int encrypt_mode = 0;
	if (argc > 1) {
		sscanf(argv[1],"%d",&license_mode);
	}
	if (argc > 2) {
		sscanf(argv[2], "%d", &encrypt_mode);
	}
	printf("License mode is %s\n",(license_mode==0)?"NetCard":"Disk");
	
	seeder::CLicense sn;
	sn.set_macaddr_type(license_mode);
	switch (encrypt_mode)
	{
		case 0: //获取硬件信息
		{
			//获取
			if(!sn.Create()) {
				printf("CLicense Create fail!\n");
			}
			//打印输出
			std::string strSn = sn.to_strings();
			printf("strSn:%s\n", strSn.c_str());
			//向文件写入硬件信息
			sn.serialize_source_handle("sc.txt", true);
		}
		break;
		case 11: //根据硬件信息生成License
		{
			//从文件读取硬件信息
			sn.serialize_source_handle("sc.txt", false);
			//生成算法
			sn.encrypt_handle();
			//打印输出
			std::string strSn = sn.to_string();
			printf("str_sn:%s\n", strSn.c_str());
			//向文件写入License
			sn.serialize_encrypt_handle("sn.txt", true);
		}
		break;
		default:
			printf("encrypt_mode is NULL\n");
		break;
	}
	return 0;
}