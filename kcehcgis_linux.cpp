#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <openssl/evp.h>

struct SigcheckContext {
    bool bCalculateEntropy = false;
    bool bShowHashes = false;
    std::string targetFilePath;
};

// good openssl generic hashing function replacing windows crypto api
std::string GetCryptoHash(const std::string& filePath, const EVP_MD* md) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "N/A";

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return "N/A";

    if (1 != EVP_DigestInit_ex(mdctx, md, nullptr)) {
        EVP_MD_CTX_free(mdctx);
        return "N/A";
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, file.gcount())) {
            EVP_MD_CTX_free(mdctx);
            return "N/A";
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen)) {
        EVP_MD_CTX_free(mdctx);
        return "N/A";
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

double CalculateFileEntropy(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return 0.0;

    std::vector<size_t> byteFrequencies(256, 0);
    size_t totalBytes = 0;
    char buffer[4096];

    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        std::streamsize bytesRead = file.gcount();
        for (std::streamsize i = 0; i < bytesRead; ++i) {
            byteFrequencies[static_cast<unsigned char>(buffer[i])]++;
        }
        totalBytes += bytesRead;
    }

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

int main(int argc, char* argv[]) {
    std::cout << "stupid lil clone of sigcheck called kcehcgis (Linux Edition)\n";
    std::cout << "=========================================================\n\n";

    if (argc < 2) {
        std::cout << "Usage: kcehcgis_linux [-a] [-h] <file_path>\n";
        std::cout << "  -a   Calculate file entropy statistics\n";
        std::cout << "  -h   Show cryptographic hash parameters (MD5, SHA1, SHA256)\n";
        return 1;
    }

    SigcheckContext context;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-a") {
            context.bCalculateEntropy = true;
        } else if (arg == "-h") {
            context.bShowHashes = true;
        } else {
            context.targetFilePath = argv[i];
        }
    }

    if (context.targetFilePath.empty()) {
        std::cerr << "[-] Error: Target file path must be specified.\n";
        return 1;
    }

    std::cout << "Target File: " << context.targetFilePath << "\n";
    
    // Note: linox handles digital signatures on ELF binaries completely differently (e.g., via IMA or something idfk)
    std::cout << "Verified:    N/A (Signature checks skipped on Linux port)\n";

    if (context.bShowHashes) {
        std::cout << "MD5:         " << GetCryptoHash(context.targetFilePath, EVP_md5()) << "\n";
        std::cout << "SHA1:        " << GetCryptoHash(context.targetFilePath, EVP_sha1()) << "\n";
        std::cout << "SHA256:      " << GetCryptoHash(context.targetFilePath, EVP_sha256()) << "\n";
    }

    if (context.bCalculateEntropy) {
        double entropy = CalculateFileEntropy(context.targetFilePath);
        std::cout << "Entropy:     " << std::fixed << std::setprecision(3) << entropy << " bits/byte\n";
    }

    return 0;
}
