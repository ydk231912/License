#include "../common/License.h"

namespace seeder {

bool license_check()
{
	bool _license_check = false;
#ifdef DEBUG //不做校对
	_license_check = false;
#else
	_license_check = true;
#endif
	bool b_ret = !_license_check;
	if (!b_ret)
	{
		CLicense sn1;
		if (sn1.serialize_encrypt_handle("sn.txt", false))
		{
			// CLogger::createInstance()->Log(eTipMessage, "license:%s", sn1.to_string().c_str());

			CLicense sn;
			if (sn.Create() && sn.encrypt_handle()) {
				b_ret = (sn1 == sn);
			}
			if (!b_ret) {
				sn.set_macaddr_type(1);
				if (sn.Create()&&sn.encrypt_handle()) {
					b_ret = (sn1 == sn);
				}
			}
		}
	}
	return b_ret;
};
} // namespace seeder

 
int main(int argc, char* argv[])
{
   if (!seeder::license_check()) {
		printf("license is error, please make sure software instance is right first!");
		exit(true);
	}
	
   //Function code
}