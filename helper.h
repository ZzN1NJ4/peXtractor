#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <Wincrypt.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define imp(msg, ...) printf("[#] " msg "\n", ##__VA_ARGS__)

#define BUFSIZE 1024
#define MD5LEN  16

VOID printHelp() {
    printf("\n[*] Usage: run.exe /path/to/exe [options]\n\n");
    printf(" Options:\n-v, /v    Enable verbose mode for detailed output (mainly for section / import data part).\n-h, /h	  Prints this help information\n\n");
    printf(" Description :\n	Extracts and displays information from a PE file, which includes\n	headers,section data, imports, and other metadata.\n");
}

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt) {
    size_t i = 0;
    PIMAGE_SECTION_HEADER pSecHdr;
    if (rva == 0) {
        return (rva);
    }
    pSecHdr = psh;
    for (i = 0; i < pnt->FileHeader.NumberOfSections; i++) {
        if (rva >= pSecHdr->VirtualAddress && rva < pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize) {
            break;
        }
        pSecHdr++;
    }
    return (rva - pSecHdr->VirtualAddress + pSecHdr->PointerToRawData);
}

CHAR* getVSVersion(unsigned int ver) {
    if (ver > 0xFD && ver <= 0x10F) return "Visual Studio 2015 14.00";
    else if (ver > 0xEB) return "Visual Studio 2013 12.10";
    else if (ver > 0xD9) return "Visual Studio 2013 12.00";
    else if (ver > 0xC7) return "Visual Studio 2012 11.00";
    else if (ver > 0xB5) return "Visual Studio 2010 10.10";
    else if (ver > 0x98) return "Visual Studio 2010 10.00";
    else if (ver > 0x83) return "Visual Studio 2008 09.00";
    else if (ver > 0x6D) return "Visual Studio 2005 08.00";
    else if (ver > 0x5A) return "Visual Studio 2003 07.10";
    if (ver == 1)
        return "Visual Studio";

    return "Unknown Version";

}




// From https://github.com/kirschju/richheader/blob/master/prodids.py 
const char* prodID[] = {
    "Unknown",
    "Import0",
    "Linker510",
    "Cvtomf510",
    "Linker600",
    "Cvtomf600",
    "Cvtres500",
    "Utc11_Basic",
    "Utc11_C",
    "Utc12_Basic",
    "Utc12_C",
    "Utc12_CPP",
    "AliasObj60",
    "VisualBasic60",
    "Masm613",
    "Masm710",
    "Linker511",
    "Cvtomf511",
    "Masm614",
    "Linker512",
    "Cvtomf512",
    "Utc12_C_Std",
    "Utc12_CPP_Std",
    "Utc12_C_Book",
    "Utc12_CPP_Book",
    "Implib700",
    "Cvtomf700",
    "Utc13_Basic",
    "Utc13_C",
    "Utc13_CPP",
    "Linker610",
    "Cvtomf610",
    "Linker601",
    "Cvtomf601",
    "Utc12_1_Basic",
    "Utc12_1_C",
    "Utc12_1_CPP",
    "Linker620",
    "Cvtomf620",
    "AliasObj70",
    "Linker621",
    "Cvtomf621",
    "Masm615",
    "Utc13_LTCG_C",
    "Utc13_LTCG_CPP",
    "Masm620",
    "ILAsm100",
    "Utc12_2_Basic",
    "Utc12_2_C",
    "Utc12_2_CPP",
    "Utc12_2_C_Std",
    "Utc12_2_CPP_Std",
    "Utc12_2_C_Book",
    "Utc12_2_CPP_Book",
    "Implib622",
    "Cvtomf622",
    "Cvtres501",
    "Utc13_C_Std",
    "Utc13_CPP_Std",
    "Cvtpgd1300",
    "Linker622",
    "Linker700",
    "Export622",
    "Export700",
    "Masm700",
    "Utc13_POGO_I_C",
    "Utc13_POGO_I_CPP",
    "Utc13_POGO_O_C",
    "Utc13_POGO_O_CPP",
    "Cvtres700",
    "Cvtres710p",
    "Linker710p",
    "Cvtomf710p",
    "Export710p",
    "Implib710p",
    "Masm710p",
    "Utc1310p_C",
    "Utc1310p_CPP",
    "Utc1310p_C_Std",
    "Utc1310p_CPP_Std",
    "Utc1310p_LTCG_C",
    "Utc1310p_LTCG_CPP",
    "Utc1310p_POGO_I_C",
    "Utc1310p_POGO_I_CPP",
    "Utc1310p_POGO_O_C",
    "Utc1310p_POGO_O_CPP",
    "Linker624",
    "Cvtomf624",
    "Export624",
    "Implib624",
    "Linker710",
    "Cvtomf710",
    "Export710",
    "Implib710",
    "Cvtres710",
    "Utc1310_C",
    "Utc1310_CPP",
    "Utc1310_C_Std",
    "Utc1310_CPP_Std",
    "Utc1310_LTCG_C",
    "Utc1310_LTCG_CPP",
    "Utc1310_POGO_I_C",
    "Utc1310_POGO_I_CPP",
    "Utc1310_POGO_O_C",
    "Utc1310_POGO_O_CPP",
    "AliasObj710",
    "AliasObj710p",
    "Cvtpgd1310",
    "Cvtpgd1310p",
    "Utc1400_C",
    "Utc1400_CPP",
    "Utc1400_C_Std",
    "Utc1400_CPP_Std",
    "Utc1400_LTCG_C",
    "Utc1400_LTCG_CPP",
    "Utc1400_POGO_I_C",
    "Utc1400_POGO_I_CPP",
    "Utc1400_POGO_O_C",
    "Utc1400_POGO_O_CPP",
    "Cvtpgd1400",
    "Linker800",
    "Cvtomf800",
    "Export800",
    "Implib800",
    "Cvtres800",
    "Masm800",
    "AliasObj800",
    "PhoenixPrerelease",
    "Utc1400_CVTCIL_C",
    "Utc1400_CVTCIL_CPP",
    "Utc1400_LTCG_MSIL",
    "Utc1500_C",
    "Utc1500_CPP",
    "Utc1500_C_Std",
    "Utc1500_CPP_Std",
    "Utc1500_CVTCIL_C",
    "Utc1500_CVTCIL_CPP",
    "Utc1500_LTCG_C",
    "Utc1500_LTCG_CPP",
    "Utc1500_LTCG_MSIL",
    "Utc1500_POGO_I_C",
    "Utc1500_POGO_I_CPP",
    "Utc1500_POGO_O_C",
    "Utc1500_POGO_O_CPP",
    "Cvtpgd1500",
    "Linker900",
    "Export900",
    "Implib900",
    "Cvtres900",
    "Masm900",
    "AliasObj900",
    "Resource",
    "AliasObj1000",
    "Cvtpgd1600",
    "Cvtres1000",
    "Export1000",
    "Implib1000",
    "Linker1000",
    "Masm1000",
    "Phx1600_C",
    "Phx1600_CPP",
    "Phx1600_CVTCIL_C",
    "Phx1600_CVTCIL_CPP",
    "Phx1600_LTCG_C",
    "Phx1600_LTCG_CPP",
    "Phx1600_LTCG_MSIL",
    "Phx1600_POGO_I_C",
    "Phx1600_POGO_I_CPP",
    "Phx1600_POGO_O_C",
    "Phx1600_POGO_O_CPP",
    "Utc1600_C",
    "Utc1600_CPP",
    "Utc1600_CVTCIL_C",
    "Utc1600_CVTCIL_CPP",
    "Utc1600_LTCG_C",
    "Utc1600_LTCG_CPP",
    "Utc1600_LTCG_MSIL",
    "Utc1600_POGO_I_C",
    "Utc1600_POGO_I_CPP",
    "Utc1600_POGO_O_C",
    "Utc1600_POGO_O_CPP",
    "AliasObj1010",
    "Cvtpgd1610",
    "Cvtres1010",
    "Export1010",
    "Implib1010",
    "Linker1010",
    "Masm1010",
    "Utc1610_C",
    "Utc1610_CPP",
    "Utc1610_CVTCIL_C",
    "Utc1610_CVTCIL_CPP",
    "Utc1610_LTCG_C",
    "Utc1610_LTCG_CPP",
    "Utc1610_LTCG_MSIL",
    "Utc1610_POGO_I_C",
    "Utc1610_POGO_I_CPP",
    "Utc1610_POGO_O_C",
    "Utc1610_POGO_O_CPP",
    "AliasObj1100",
    "Cvtpgd1700",
    "Cvtres1100",
    "Export1100",
    "Implib1100",
    "Linker1100",
    "Masm1100",
    "Utc1700_C",
    "Utc1700_CPP",
    "Utc1700_CVTCIL_C",
    "Utc1700_CVTCIL_CPP",
    "Utc1700_LTCG_C",
    "Utc1700_LTCG_CPP",
    "Utc1700_LTCG_MSIL",
    "Utc1700_POGO_I_C",
    "Utc1700_POGO_I_CPP",
    "Utc1700_POGO_O_C",
    "Utc1700_POGO_O_CPP",
    "AliasObj1200",
    "Cvtpgd1800",
    "Cvtres1200",
    "Export1200",
    "Implib1200",
    "Linker1200",
    "Masm1200",
    "Utc1800_C",
    "Utc1800_CPP",
    "Utc1800_CVTCIL_C",
    "Utc1800_CVTCIL_CPP",
    "Utc1800_LTCG_C",
    "Utc1800_LTCG_CPP",
    "Utc1800_LTCG_MSIL",
    "Utc1800_POGO_I_C",
    "Utc1800_POGO_I_CPP",
    "Utc1800_POGO_O_C",
    "Utc1800_POGO_O_CPP",
    "AliasObj1210",
    "Cvtpgd1810",
    "Cvtres1210",
    "Export1210",
    "Implib1210",
    "Linker1210",
    "Masm1210",
    "Utc1810_C",
    "Utc1810_CPP",
    "Utc1810_CVTCIL_C",
    "Utc1810_CVTCIL_CPP",
    "Utc1810_LTCG_C",
    "Utc1810_LTCG_CPP",
    "Utc1810_LTCG_MSIL",
    "Utc1810_POGO_I_C",
    "Utc1810_POGO_I_CPP",
    "Utc1810_POGO_O_C",
    "Utc1810_POGO_O_CPP",
    "AliasObj1400",
    "Cvtpgd1900",
    "Cvtres1400",
    "Export1400",
    "Implib1400",
    "Linker1400",
    "Masm1400",
    "Utc1900_C",
    "Utc1900_CPP",
    "Utc1900_CVTCIL_C",
    "Utc1900_CVTCIL_CPP",
    "Utc1900_LTCG_C",
    "Utc1900_LTCG_CPP",
    "Utc1900_LTCG_MSIL",
    "Utc1900_POGO_I_C",
    "Utc1900_POGO_I_CPP",
    "Utc1900_POGO_O_C",
    "Utc1900_POGO_O_CPP"
};

VOID compid_print(unsigned char compid[8], int i) {
    unsigned int compid_1 = (compid[1] << 8) | compid[0];
    unsigned int compid_2 = (compid[3] << 8) | compid[2];
    unsigned int compid_3 = (compid[5] << 8) | compid[4];
    const char* version = getVSVersion(compid_2);

    printf("\n[%d] Comp ID: 0x", i / 8);
    for (int t = 0; t < 8; t++) printf("%02X", compid[t]); // The last 3 bytes are generally null bytes
    printf("  :  %u.%u.%u", compid_1, compid_2, compid_3);
    printf(" : %-6u ", compid_1);
    printf(" : %-5u ", compid_3);
    printf(" : %s", prodID[compid_2]);
    printf(" :  %s", version);
}

BOOL parseRich(unsigned char* pFile, int offset, BOOL Verbose) {
    unsigned char rich_stub[] = { 0x52, 0x69, 0x63, 0x68 };
    unsigned char xor_key[4] = { 0x00 };
    unsigned char rich_start[4] = { 'D', 'a', 'n', 'S' };
    unsigned char checksum_padding[4] = { 0x00 };
    unsigned char compid[8] = { 0x00 };
    unsigned char rich_R = { 0x00 };

    size_t rSize = 0;
    size_t rich_dword = 0;
    size_t len = 250;
    BOOL found = FALSE, start = FALSE;

    for (; rSize < len; rSize++) {
        if (pFile[128 + rSize] == rich_stub[0]) {
            if (pFile[128 + rSize + 1] == rich_stub[1] && pFile[128 + rSize + 2] == rich_stub[2] && pFile[128 + rSize + 3] == rich_stub[3]) {
                found = TRUE;
                rich_dword = rSize;
                rSize += 4;
                xor_key[0] = pFile[128 + rSize];
                xor_key[1] = pFile[128 + rSize + 1];
                xor_key[2] = pFile[128 + rSize + 2];
                xor_key[3] = pFile[128 + rSize + 3];
                rSize += 4;
                // rSize + 4 Rich + 4 XOR key
                break;
            }
        }
    }
    printf("\n");
    if (found == FALSE) {
        return FALSE;
    }
    printf("##################      R I C H   H E A D E R      ##################\n\n");
    printf("[+] XOR Key: 0x");
    for (size_t i = 0; i < 4; i++) {
        printf("%X", xor_key[i]);
    }
    printf("\n");
    info("Rich Header Size : %d", rSize);

    if (!Verbose) { printf("\n"); goto noVerbose; }
    printf("[test] Comp ID  :  compid-hex  :  meaning  :  buildid  :  count  :  productid  :  version\n");

    unsigned char* rich_header = (pFile + offset);
    rich_R = rich_header[rich_dword];
    //info("RICH R at 0x%X", rich_R);

    for (size_t j = 0; j < rSize - 4; j++) {				// size - 4, since we dont have any need for XOR key / no need for "Rich" as well but for debugging purpose
        rich_header[j] = rich_header[j] ^ xor_key[j % 4];
        //printf("0x%X ", rich_header[j]); if ((j + 1) % 8 == 0) printf("\n");
    }
    //printf("\n");

    for (size_t i = 0; i < 4; i++) {
        if (rich_header[i] != rich_start[i]) {
            warn("Can't seem to compare Rich Header start");
            return FALSE;
        }
    } start = TRUE;

    compid[0] = rich_header[16];	// instead of if condition every loop, we do this
    int i = 1;
    for (; i < rSize - 24; i++) {   // (rSize - 8) until "Rich", minus the 16 we are adding
        compid[i % 8] = rich_header[16 + i];
        //if (i == 0) continue;
        if ((i + 1) % 8 == 0) {
            compid_print(compid, i);
        }
    } printf("\n\n");

    // Might not reach the case below, so no need for it
    //if (rich_R == 0x52) {
    //    return TRUE;
    //}
    //else {
    //    info("Rich Header may have been parsed incompletely, rich_header[%d] should be R, got : 0x%X", rSize - 8, rich_R);
    //    return FALSE;
    //}

noVerbose:
    return TRUE;

}

DWORD md5sum(HANDLE hFile) {
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    if (INVALID_HANDLE_VALUE == hFile) {
        dwStatus = GetLastError();
        warn("Invalid File Handle, LastError : %d", dwStatus);
        return dwStatus;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        warn("CryptAcquireContext failed: %d", dwStatus);
        CloseHandle(hFile);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        dwStatus = GetLastError();
        warn("CryptCreateHash failed: %d", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
        if (0 == cbRead) {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            dwStatus = GetLastError();
            warn("CryptHashData failed: %d", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult) {
        dwStatus = GetLastError();
        warn("ReadFile failed: %d", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        printf("[*] MD5 hash : ");
        for (DWORD i = 0; i < cbHash; i++) {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
        }
        printf("\n");
    }
    else {
        dwStatus = GetLastError();
        warn("CryptGetHashParam failed: %d", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return dwStatus;
}
