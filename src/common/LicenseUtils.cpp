#include "ostype.h"
#pragma warning(disable: 4668)
#include "LicenseUtils.h"
#include "../../../ThirdParty/crypto/include/Win64/rsa.h"
#include "../../../ThirdParty/crypto/include/Win64/randpool.h"
#include "../../../ThirdParty/crypto/include/Win64/base64.h"
#include "../../../ThirdParty/crypto/include/Win64/files.h"
#include "../../../ThirdParty/crypto/include/Win64/filters.h"
#include "Misc/Paths.h"
#include "Misc/FileHelper.h"
#include <string>
#include <windows.h>
#include "time.h"
#include <minwindef.h>
#include "iphlpapi.h"
#include "Utils/wmic.h"

/*使用 Windows API 创建一个管道来执行命令行命令，并读取命令行输出以获取 BIOS ID*/
BOOL GetBiosIDByCmd(char* lpszBaseBoard) {
	const long MAX_COMMAND_SIZE = 10000; // 命令行输出缓冲大小	

	WCHAR szFetCmd[] = L"wmic csproduct get UUID"; // 获取BOIS命令行	
	const std::string strEnSearch = "UUID"; // 主板序列号的前导信息

	BOOL   bret = FALSE;
	HANDLE hReadPipe = NULL; //读取管道
	HANDLE hWritePipe = NULL; //写入管道	
	PROCESS_INFORMATION pi; //进程信息	
	memset(&pi, 0, sizeof(pi));
	STARTUPINFO	si;	//控制命令行窗口信息
	memset(&si, 0, sizeof(si));
	SECURITY_ATTRIBUTES sa; //安全属性
	memset(&sa, 0, sizeof(sa));

	char szBuffer[MAX_COMMAND_SIZE + 1] = { 0 }; // 放置命令行结果的输出缓冲区
	std::string	strBuffer;
	unsigned long count = 0;
	long ipos = 0;

	pi.hProcess = NULL;
	pi.hThread = NULL;
	si.cb = sizeof(STARTUPINFO);
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	//1.创建管道
	bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if (!bret) {
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);

		return bret;
	}

	//2.设置命令行窗口的信息为指定的读写管道
	GetStartupInfo(&si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.wShowWindow = SW_HIDE; //隐藏命令行窗口
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	//3.创建获取命令行的进程
	bret = CreateProcess(NULL, szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!bret) {
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return bret;
	}

	//4.读取返回的数据
	WaitForSingleObject(pi.hProcess, 500);
	bret = ReadFile(hReadPipe, szBuffer, MAX_COMMAND_SIZE, &count, 0);
	if (!bret) {
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return bret;
	}

	//5.查找主板ID
	bret = FALSE;
	strBuffer = szBuffer;
	ipos = strBuffer.find(strEnSearch);

	if (ipos < 0) { // 没有找到
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return bret;
	}
	else {
		strBuffer = strBuffer.substr(ipos + strEnSearch.length());
	}

	memset(szBuffer, 0x00, sizeof(szBuffer));
	strcpy_s(szBuffer, strBuffer.c_str());

	//去掉中间的空格 \r \n
	int j = 0;
	for (int i = 0; i < strlen(szBuffer); i++) {
		if (szBuffer[i] != ' ' && szBuffer[i] != '\n' && szBuffer[i] != '\r') {
			lpszBaseBoard[j] = szBuffer[i];
			j++;
		}
	}

	CloseHandle(hWritePipe);
	CloseHandle(hReadPipe);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;
}

FString GetBiosID() {
	char a[1024] = { 0 };
	GetBiosIDByCmd(a);
	std::string b = a;
	return b.c_str();
}

CryptoPP::RandomPool& GlobalRNG()
{
	static CryptoPP::RandomPool randomPool;
	return randomPool;
}
// 解密
std::string RSADecryptString(const char* privFilename, const char* ciphertext)
{
	CryptoPP::FileSource privFile(privFilename, true, new CryptoPP::Base64Decoder);
	CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privFile);

	std::string result;
	CryptoPP::StringSource(ciphertext, true, new CryptoPP::Base64Decoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv, new CryptoPP::StringSink(result))));
	return result;
}


int32 checkLicense() {
	//check license
	int32 dur = -1;
	FString PluginBaseDir = IPluginManager::Get().FindPlugin("SeederPlugin")->GetBaseDir();
	FString PluginLicenseDir = FPaths::Combine(PluginBaseDir, "License");
	FString LicensePath = FPaths::Combine(PluginLicenseDir, "LICENSE");
	FString PivPath = FPaths::Combine(PluginLicenseDir, "priKey");
	LicensePath = FPaths::ConvertRelativePathToFull(LicensePath);
	if (FPlatformFileManager::Get().GetPlatformFile().FileExists(*LicensePath))
	{
		FString TextData;
		FFileHelper::LoadFileToString(TextData, *LicensePath);
		std::string ciphertext = TCHAR_TO_UTF8(*TextData);
		if (ciphertext.empty())
		{
			return -1;
		}
		std::string decode = RSADecryptString(TCHAR_TO_ANSI(*PivPath), ciphertext.data());
		FString fDecode = decode.c_str();
		if (fDecode.IsEmpty())
		{
			return -1;
		}
		TArray<FString> arr;
		fDecode.ParseIntoArray(arr, TEXT("\r\n"), false);
		FString License_BiosID = arr[0];
		if (!GetBiosID().Equals(License_BiosID))
		{
			return -1;
		}
		FString License_Expires = arr[1];
		char *expireTimeChar = TCHAR_TO_UTF8(*License_Expires);
		int64 expiresTime = _atoi64(expireTimeChar);
		FDateTime Time = FDateTime::Now();
		int64 current = Time.ToUnixTimestamp()*1000;
		dur = (expiresTime - current) / 60 / 60 / 24 /1000 + 1;
	}
	return dur;
}
