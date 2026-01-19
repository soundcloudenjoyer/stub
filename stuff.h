#pragma once
#include <string>
#include <Windows.h>
#include <zlib.h>
#include <cstring>
#include <cstdio>
#include <winhttp.h>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define DOS_HEADER_SIZE sizeof(IMAGE_DOS_HEADER)
#define FILE_HEADER_SIZE sizeof(IMAGE_FILE_HEADER)
#define SIGNATURE_SIZE sizeof(DWORD)
#define SECTION_HEADER_SIZE sizeof(IMAGE_SECTION_HEADER)
#define OPT_HEADER_SIZE sizeof(IMAGE_OPTIONAL_HEADER64)
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPT_HEADER;
typedef _IMAGE_TLS_DIRECTORY64 TLS_DIRECTORY;
typedef DWORD(*EntryFn)();

namespace stuff {


    std::string DecryptAESKey(const BYTE* encryptedPayload, size_t keySize_inBytes);

    BOOL GZIPdecompress(const BYTE* inCompressedPayload, size_t inLen, BYTE* outDecompressedPayload, size_t *InOutDecompressedSize);

    static constexpr int SALT_LEN = 16;
    static constexpr int IV_LEN = 12;
    static constexpr int KEY_LEN = 32;
    static constexpr int TAG_LEN = 16;
    static constexpr int PBKDF2_ITER = 100000;

    static void print_openssl_error(const std::string &msg);
    static BOOL deriveKey(const std::string &password, const BYTE* salt, BYTE* outKey);

    BOOL decryptPayload(const std::string& password, const BYTE* encryptedPayload, size_t encryptedPayloadSize, BYTE* decryptedPayload, size_t* decryptedPayloadSize);
    BOOL readPE(const BYTE* payload, size_t payloadSize, IMAGE_DOS_HEADER* outMZ, DWORD* sig, IMAGE_FILE_HEADER* outFL, IMAGE_OPT_HEADER* outOPT, IMAGE_SECTION_HEADER** outSEC);
    BOOL LoadPEMain(const BYTE* payload, size_t payloadSize);
    BOOL loadPE(const BYTE* payload, IMAGE_DOS_HEADER* in_MZHeader, DWORD* in_Signature, IMAGE_FILE_HEADER* in_FILEHeader, IMAGE_OPT_HEADER* in_OPTHeader, IMAGE_SECTION_HEADER* in_SCHeader, LPVOID ImageBase);
    BOOL doImports(IMAGE_OPT_HEADER* inOPT, LPVOID ImageBase);
    BOOL doRelocs(IMAGE_OPT_HEADER *inOpt, LPVOID ImageBase);
    DWORD characteristicsToProtect(DWORD ch);
    BOOL changeProtection(IMAGE_SECTION_HEADER* sec, LPVOID ImageBase);
    BOOL callTLScallbacks(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase, DWORD dwReason);
    BOOL callEXE_EntryPoint(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase);
};