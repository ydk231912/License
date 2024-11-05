#pragma once
#ifndef __SNFACTORY_H__
#define __SNFACTORY_H__

#ifdef _WIN32
#include "ostype.h"
#else
// linux
#include "ostype.h"
#endif
 
#define MAX_LICENSE_SIZE 32


namespace seeder {

class CLicense
{
public:
	CLicense();
    ~CLicense();

    std::string get_biosID();
    int32_t check_license();
	
private:
    int get_biosID_bycmd(char* lpszBaseBoard);
    CryptoPP::RandomPool& generate_rng();
    std::string rsa_decrypt_string(const char* privFilename, const char* ciphertext);
	
protected:
	
}; // class CLicense
} // namespace seeder

 
#endif  /*__SNFACTORY_H__*/