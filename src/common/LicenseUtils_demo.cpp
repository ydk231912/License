#include "LicenseUtils_demo.h"

#ifdef _WIN32
/*使用 Windows API 创建一个管道来执行命令行命令，并读取命令行输出以获取 BIOS ID*/
bool get_biosID_bycmd(char* lpszBaseBoard) {
    const long MAX_COMMAND_SIZE = 10000; // 命令行输出缓冲大小
    WCHAR szFetCmd[] = L"wmic csproduct get UUID"; // 获取BIOS命令行
    const std::string strEnSearch = "UUID"; // 主板序列号的前导信息

    BOOL bret = FALSE;
    HANDLE hReadPipe = NULL; // 读取管道
    HANDLE hWritePipe = NULL; // 写入管道
    PROCESS_INFORMATION pi; // 进程信息
    memset(&pi, 0, sizeof(pi));
    STARTUPINFO si; // 控制命令行窗口信息
    memset(&si, 0, sizeof(si));
    SECURITY_ATTRIBUTES sa; // 安全属性
    memset(&sa, 0, sizeof(sa));

    char szBuffer[MAX_COMMAND_SIZE + 1] = { 0 }; // 放置命令行结果的输出缓冲区
    std::string strBuffer;
    unsigned long count = 0;
    long ipos = 0;

    pi.hProcess = NULL;
    pi.hThread = NULL;
    si.cb = sizeof(STARTUPINFO);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    // 1. 创建管道
    bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        return bret;
    }

    // 2. 设置命令行窗口的信息为指定的读写管道
    GetStartupInfo(&si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE; // 隐藏命令行窗口
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

    // 3. 创建获取命令行的进程
    bret = CreateProcess(NULL, (LPWSTR)szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return bret;
    }

    // 4. 读取返回的数据
    WaitForSingleObject(pi.hProcess, INFINITE);
    bret = ReadFile(hReadPipe, szBuffer, MAX_COMMAND_SIZE, &count, NULL);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return bret;
    }

    // 5. 查找主板ID
    bret = FALSE;
    strBuffer = szBuffer;
    ipos = strBuffer.find(strEnSearch);

    if (ipos == std::string::npos) { // 没有找到 < 0
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return bret;
    } else {
        strBuffer = strBuffer.substr(ipos + strEnSearch.length());
    }

    memset(szBuffer, 0x00, sizeof(szBuffer));
    strcpy_s(szBuffer, strBuffer.c_str());

    // 去掉中间的空格 \r \n
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

std::string get_biosID() {
    char a[1024] = { 0 };
    if (get_biosID_bycmd(a)) {
        return std::string(a);
    } else {
        return "";
    }
}

CryptoPP::RandomPool& generate_rng() {
    static CryptoPP::RandomPool randomPool;
    return randomPool;
}

std::string rsa_decrypt_string(const char* privFilename, const char* ciphertext) {
    CryptoPP::FileSource privFile(privFilename, true, new CryptoPP::Base64Decoder);
    CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privFile);

    std::string result;
    CryptoPP::StringSource(ciphertext, true, new CryptoPP::Base64Decoder(new CryptoPP::PK_DecryptorFilter(generate_rng(), priv, new CryptoPP::StringSink(result))));
    return result;
}

int32_t check_license() {
    int32_t dur = -1;
    std::string PluginBaseDir = "C:\\path\\to\\plugin\\base\\dir"; // 替换为实际路径
    std::string PluginLicenseDir = PluginBaseDir + "\\License";
    std::string LicensePath = PluginLicenseDir + "\\LICENSE";
    std::string PivPath = PluginLicenseDir + "\\priKey";
    /*
        FString PluginBaseDir = IPluginManager::Get().FindPlugin("SeederPlugin")->GetBaseDir();
        FString PluginLicenseDir = FPaths::Combine(PluginBaseDir, "License");
        FString LicensePath = FPaths::Combine(PluginLicenseDir, "LICENSE");
        FString PivPath = FPaths::Combine(PluginLicenseDir, "priKey");
        LicensePath = FPaths::ConvertRelativePathToFull(LicensePath);
    */

    if (PathFileExistsA(LicensePath.c_str())) {
        std::ifstream file(LicensePath);
        if (file.is_open()) {
            std::string ciphertext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            if (ciphertext.empty()) {
                return -1;
            }

            std::string decode = rsa_decrypt_string(PivPath.c_str(), ciphertext.c_str());
            if (decode.empty()) {
                return -1;
            }

            std::istringstream iss(decode);
            std::vector<std::string> arr;
            std::string line;
            while (std::getline(iss, line)) {
                arr.push_back(line);
            }

            if (arr.size() < 2 || get_biosID() != arr[0]) {
                return -1;
            }

            int64_t expiresTime = std::stoll(arr[1]);
            time_t current = time(0);
            int64_t currentMillis = current * 1000;
            dur = (expiresTime - currentMillis) / 60 / 60 / 24 / 1000 + 1;
        }
    }

    return dur;
}

FString get_biosID() {
	char a[1024] = { 0 };
	get_biosID_bycmd(a);
	std::string b = a;
	return b.c_str();
}

/*
int main() {
    TCHAR lpszBaseBoard[MAX_COMMAND_SIZE + 1] = { 0 };
    if (get_biosID_bycmd(lpszBaseBoard)) {
        _tprintf(_T("BIOS ID: %s\n"), lpszBaseBoard);
    } else {
        _tprintf(_T("Failed to get BIOS ID\n"));
    }
    return 0;
}
*/

#else
namespace seeder {
CLicense::CLicense() {}

CLicense::~CLicense() {}

std::string CLicense::get_biosID() {
    char a[MAX_COMMAND_SIZE] = { 0 };
    if (get_biosID_bycmd(a)) {
        return std::string(a);
    } else {
        return "";
    }
}


int CLicense::get_biosID_bycmd(char* lpszBaseBoard) {
    int pipefd[2]; // 管道文件描述符
    pid_t pid; // 子进程ID
    char szBuffer[MAX_COMMAND_SIZE + 1] = { 0 }; // 放置命令行结果的输出缓冲区
    char* strBuffer = szBuffer;
    ssize_t count = 0;
    long ipos = 0;

    // 1. 创建管道
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    // 2. 创建子进程
    pid = fork();
    if (pid == -1) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) { // 子进程
        // 关闭读端
        close(pipefd[0]);

        // 重定向标准输出到管道
        dup2(pipefd[1], STDOUT_FILENO);

        // 关闭写端
        close(pipefd[1]);

        // 执行命令
        execlp("/bin/sh", "sh", "-c", CMD, (char *)NULL);

        // 如果 execlp 失败，退出子进程
        _exit(EXIT_FAILURE);
    } else { // 父进程
        // 关闭写端
        close(pipefd[1]);

        // 3. 读取返回的数据
        waitpid(pid, NULL, 0); // 等待子进程结束
        count = read(pipefd[0], szBuffer, MAX_COMMAND_SIZE);
        if (count == -1) {
            perror("read");
            close(pipefd[0]);
            return -1;
        }

        // 4. 查找主板ID
        ipos = strstr(szBuffer, SEARCH_STR) - szBuffer;
        if (ipos < 0) { // 没有找到
            close(pipefd[0]);
            return -1;
        } else {
            strBuffer = szBuffer + ipos + strlen(SEARCH_STR);
        }

        // 5. 去掉中间的空格 \r \n
        int j = 0;
        for (int i = 0; i < strlen(strBuffer); i++) {
            if (strBuffer[i] != ' ' && strBuffer[i] != '\n' && strBuffer[i] != '\r') {
                lpszBaseBoard[j] = strBuffer[i];
                j++;
            }
        }

        // 结束字符串
        lpszBaseBoard[j] = '\0';

        // 关闭读端
        close(pipefd[0]);
    }

    return 0;
}

/*生成随机数*/
CryptoPP::RandomPool& CLicense::generate_rng() {
    static CryptoPP::RandomPool randomPool;
    return randomPool;
}

/*RSA 解密*/
std::string CLicense::rsa_decrypt_string(const char* privFilename, const char* ciphertext) {
    CryptoPP::FileSource privFile(privFilename, true, new CryptoPP::Base64Decoder);
    CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privFile);

    std::string result;
    CryptoPP::StringSource give_me_a_name(
        ciphertext, true,
        new CryptoPP::Base64Decoder(new CryptoPP::PK_DecryptorFilter(
            generate_rng(), priv, new CryptoPP::StringSink(result))));
    return result;
}

/*检查许可证*/
int32_t CLicense::check_license() {
    int32_t dur = -1;
    std::string PluginBaseDir = "/path/to/plugin/base/dir"; // 替换为实际路径
    std::string PluginLicenseDir = PluginBaseDir + "/License";
    std::string LicensePath = PluginLicenseDir + "/LICENSE";
    std::string PivPath = PluginLicenseDir + "/priKey";

    if (access(LicensePath.c_str(), F_OK) == 0) {
        std::ifstream file(LicensePath);
        if (file.is_open()) {
            std::string ciphertext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            if (ciphertext.empty()) {
                return -1;
            }

            std::string decode = rsa_decrypt_string(PivPath.c_str(), ciphertext.c_str());
            if (decode.empty()) {
                return -1;
            }

            std::istringstream iss(decode);
            std::vector<std::string> arr;
            std::string line;
            while (std::getline(iss, line)) {
                arr.push_back(line);
            }

            if (arr.size() < 2 || get_biosID() != arr[0]) {
                return -1;
            }

            int64_t expiresTime = std::stoll(arr[1]);
            time_t current = time(0);
            int64_t currentMillis = current * 1000;
            dur = (expiresTime - currentMillis) / 60 / 60 / 24 / 1000 + 1;
        }
    }

    return dur;
}

/*
int main() {
    std::string biosID = get_biosID();
    if (!biosID.empty()) {
        std::cout << "BIOS ID: " << biosID << std::endl;
    } else {
        std::cout << "Failed to get BIOS ID" << std::endl;
    }

    // 示例：使用全局随机数生成器
    CryptoPP::RandomPool& rng = generate_rng();
    byte randomByte = rng.GetByte();
    std::cout << "Random Byte: " << (int)randomByte << std::endl;

    return 0;
}
*/


#endif
} // namespace seeder