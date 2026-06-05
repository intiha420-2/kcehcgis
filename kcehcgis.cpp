#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <cmath>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

struct SigcheckContext {
    HANDLE hHeap;
    bool   bCalculateEntropy;
    bool   bShowHashes;
    std::wstring targetFilePath;
};

struct HashResult {
    std::wstring md5;
    std::wstring sha1;
    std::wstring sha256;
};

bool VerifyFileSignature(const std::wstring& filePath) {
    LONG lStatus;
    
    // set up the gud WinVerifyTrust stroctur tergets
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA trustData;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;               // no ui pop ep
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE; // supa speed verification
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    trustData.pFile = &fileInfo;

    // define the frikin authenticode verification action guid
    GUID v2PolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // call not dumb WinVerifyTrust out of the wintrust library
    lStatus = WinVerifyTrust(NULL, &v2PolicyGUID, &trustData);

    // fre the dum dum tracking state allocated during the call
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &v2PolicyGUID, &trustData);

    return (lStatus == ERROR_SUCCESS);
}

std::wstring GetCryptoHash(const std::wstring& filePath, ALG_ID algId) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"N/A";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::wstring hashStr = L"";

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
            BYTE buffer[4096];
            DWORD bytesRead = 0;
            
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }

            DWORD cbHashSize = 0;
            DWORD dwCount = sizeof(DWORD);
            if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0)) {
                std::vector<BYTE> hashBuffer(cbHashSize);
                if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuffer.data(), &cbHashSize, 0)) {
                    std::wstringstream wss;
                    for (DWORD i = 0; i < cbHashSize; ++i) {
                        wss << std::hex << std::setw(2) << std::setfill(L'0') << (int)hashBuffer[i];
                    }
                    hashStr = wss.str();
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return hashStr;
}

double CalculateFileEntropy(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0.0;

    std::vector<size_t> byteFrequencies(256, 0);
    size_t totalBytes = 0;
    BYTE buffer[4096];
    DWORD bytesRead = 0;

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; ++i) {
            byteFrequencies[buffer[i]]++;
        }
        totalBytes += bytesRead;
    }
    CloseHandle(hFile);

    if (totalBytes == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (byteFrequencies[i] > 0) {
            double p = static_cast<double>(byteFrequencies[i]) / totalBytes;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"stupid lil clone of sigcheck called kcehcgis\n";
    std::wcout << L"============================================\n\n";

    if (argc < 2) {
        std::wcout << L"Usage: kcehcgis.exe [-a] [-h] <file_path>\n";
        std::wcout << L"  -a   Calculate file entropy statistics\n";
        std::wcout << L"  -h   Show cryptographic hash parameters (MD5, SHA1, SHA256)\n";
        return 1;
    }

    HANDLE currentHeap = GetProcessHeap();
    SigcheckContext* context = reinterpret_cast<SigcheckContext*>(HeapAlloc(currentHeap, HEAP_ZERO_MEMORY, sizeof(SigcheckContext)));
    if (!context) return 1;
    
    context->hHeap = currentHeap;

    // Parse command line arguments loops
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-a") {
            context->bCalculateEntropy = true;
        } else if (arg == L"-h") {
            context->bShowHashes = true;
        } else {
            context->targetFilePath = argv[i];
        }
    }

    if (context->targetFilePath.empty()) {
        std::wcerr << L"[-] Error: Target file path must be specified.\n";
        HeapFree(context->hHeap, 0, context);
        return 1;
    }

    std::wcout << L"Target File: " << context->targetFilePath << L"\n";

    bool isSigned = VerifyFileSignature(context->targetFilePath);
    std::wcout << L"Verified:    " << (isSigned ? L"SIGNED" : L"UNSIGNED / INVALID SIGNATURE") << L"\n";

    if (context->bShowHashes) {
        std::wcout << L"MD5:         " << GetCryptoHash(context->targetFilePath, CALG_MD5) << L"\n";
        std::wcout << L"SHA1:        " << GetCryptoHash(context->targetFilePath, CALG_SHA1) << L"\n";
        std::wcout << L"SHA256:      " << GetCryptoHash(context->targetFilePath, CALG_SHA_256) << L"\n";
    }

    if (context->bCalculateEntropy) {
        double entropy = CalculateFileEntropy(context->targetFilePath);
        std::wcout << L"Entropy:     " << std::fixed << std::setprecision(3) << entropy << L" bits/byte\n";
    }

    HeapFree(context->hHeap, 0, context);
    return 0;
}