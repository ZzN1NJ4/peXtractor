#include "helper.h"
#include <stdint.h>


VOID printImports32(LPVOID pFile2, PIMAGE_NT_HEADERS32 pNTHdr, IMAGE_OPTIONAL_HEADER32 pOptHdr, PIMAGE_SECTION_HEADER pSecHdr, BOOL Verbose) {
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pFile2 + Rva2Offset(pOptHdr.DataDirectory[1].VirtualAddress, pSecHdr, pNTHdr));
	LPSTR library[256];
	DWORD bound = 0;
	size_t c = 0;

	info(" Libraries Used: \n");
	while (pImport->Name != NULL) {
		library[c] = (PCHAR)((DWORD_PTR)pFile2 + Rva2Offset(pImport->Name, pSecHdr, pNTHdr));
		printf("  %s\n", library[c]);
		pImport++;
		c++;
	}

}

VOID printImports(LPVOID pFile2, PIMAGE_NT_HEADERS pNTHdr, IMAGE_OPTIONAL_HEADER pOptHdr, PIMAGE_SECTION_HEADER pSecHdr, BOOL Verbose) {
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pFile2 + Rva2Offset(pOptHdr.DataDirectory[1].VirtualAddress, pSecHdr, pNTHdr));
	// TODO: Get Functions used from a DLL 
	//PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((DWORD_PTR)pFile2 + Rva2Offset(pImport->OriginalFirstThunk, pSecHdr, pNTHdr));

	LPSTR library[256];
	DWORD bound = 0;
	size_t c = 0;
	info(" Libraries Used : \n");
	while (pImport->Name != NULL) {
		library[c] = (PCHAR)((DWORD_PTR)pFile2 + Rva2Offset(pImport->Name, pSecHdr, pNTHdr));
		printf("  %s\n", library[c]);
		//printf("  +--");
		//while (pThunk->u1.AddressOfData) {
			//if(pThunk->u1.Ordinal) printf("  +-- %llu\n", IMAGE_ORDINAL64(pThunk->u1.Ordinal));
			//else {
				//PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pFile2 + Rva2Offset(pThunk->u1.AddressOfData, pSecHdr, pNTHdr));
				//printf("  +-- %s\n", pImportByName->Name);
			//}
			//pThunk++;
		//} 
		//printf("\n");
		pImport++;
		c++;
	}

}

BOOL peXtract(char* fileName, BOOL Verbose) {
	LONG fSize = 0;
	PIMAGE_DOS_HEADER pDOSHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	IMAGE_FILE_HEADER pFileHeader;
	IMAGE_OPTIONAL_HEADER pOptionalHeader;
	IMAGE_OPTIONAL_HEADER32 pOptionalHeader32;
	PIMAGE_SECTION_HEADER pSectionHeader;

	BOOL _CUSTOMIZED_DOS_HEADER = FALSE,
		_32_BIT = FALSE;
	SIZE_T dos_counter = 0,
		bytesRead = 0;

	unsigned char dos_stub[64] = {
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char* pe_dos_stub = 0x00;



	// READ THE FILE TO HEAP
	// Generally best for basic analysis
	FILE* fp = fopen(fileName, "rb");
	if (!fp) { warn("cant find the file"); exit(0); }

	fseek(fp, 0, SEEK_END);
	fSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	unsigned char* pFile = (unsigned char*)malloc(fSize);
	if (!pFile) { fclose(fp); return FALSE; }

	fread(pFile, 1, fSize, fp);
	fclose(fp);

	// Get Handle to the File and Allocate Memory using VirtualAlloc
	// This is required for analysing imports & stuff
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		warn("Error getting Handle to file : %d", GetLastError());
		exit(0);
	}
	//fSize = GetFileSize(hFile, NULL);
	LPVOID pFile2 = VirtualAlloc(NULL, fSize, MEM_COMMIT, PAGE_READWRITE);
	ReadFile(hFile, pFile2, fSize, &bytesRead, NULL);


	// PRINT BASIC INFORMATION
	if (pFile[0] == 0x4d && pFile[1] == 0x5a) {			// Since pFile is bytes, can't compare with strings "M" "Z", we can do typecasting probably but this feels better
		printf("\n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n\n");
		info("Magic Bytes: %c%c", pFile[0], pFile[1]);
	}
	else { warn("File is not a PE file (invalid magic bytes %c%c)", pFile[0], pFile[1]); exit(0); }

	info("File Size is %ld bytes", fSize);
	info("File Name: %s", fileName);
	md5sum(hFile);


	// GET THE HEADERS
	// We can also use pFile but just to keep it same everywhere
	pDOSHeader = (PIMAGE_DOS_HEADER)pFile2;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pFile2 + (DWORD_PTR)pDOSHeader->e_lfanew);
	pFileHeader = pNTHeader->FileHeader;
	pOptionalHeader = pNTHeader->OptionalHeader;
	pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

	if (pFileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
		pOptionalHeader32 = ((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader;
		_32_BIT = TRUE;
		info("32-Bit PE File \n");
	}
	else info("64-Bit PE File \n");

	printf("##################      D O S   H E A D E R      ##################\n\n");
	info("Magic Number			@-- 0x%X", pDOSHeader->e_magic);
	info("NT Header Offset			@-- 0x%X", pDOSHeader->e_lfanew);
	info("pe_start + 0x3C			@-- 0x%X (should be same as above)", *(LONG*)(pFile + 0x3C));	// pFile[60] will only print 1 byte, so we print a LONG from the offset
	info("Relocation Table			@-- 0x%X\n", pDOSHeader->e_lfarlc);
	if (Verbose) {
		info("Relocations		@-- 0x%X", pDOSHeader->e_crlc);
		info("Pages in File	@-- 0x%X", pDOSHeader->e_cp);
		info("Checksum		@-- 0x%X", pDOSHeader->e_csum);
	}

	if (pDOSHeader->e_lfanew > 0x80) {		// more than 128 (dos Header + dos Stub) , then possible Rich Header exists
		okay("Rich Header may be present\n");
	}

	for (; dos_counter < 64; dos_counter++) {
		pe_dos_stub = *(unsigned char*)(pFile + 64 + dos_counter);
		//printf("0x%X\n", dos_stub[dos_counter]);
		if (pe_dos_stub != dos_stub[dos_counter]) {
			imp("DOS Stub seems to be customized, skipping check for Rich Header");
			_CUSTOMIZED_DOS_HEADER = TRUE;
			goto noRich;
		}
	} // now pe_dos_stub is at the end of DOS stub (assuming default stub), the size will be 128

	if (_CUSTOMIZED_DOS_HEADER == FALSE) {
		if (&pFile[128] == (pFile + 0x3C)) {
			info("Rich Header absent");
			goto noRich;
		}
		parseRich(pFile, 128, Verbose);
	}

noRich:
	printf("##################       N T   H E A D E R       ##################\n\n");
	info("NT HEADER				@-- 0x%X", pNTHeader);
	info("Signature				@-- 0x%X", pNTHeader->Signature);

	printf("\n##################     F I L E   H E A D E R     ##################\n\n");
	info("FILE HEADER				@-- 0x%X", pFileHeader);
	info("Machine				@-- 0x%X", pFileHeader.Machine);
	info("No. of Sections			@-- %d", pFileHeader.NumberOfSections);
	info("No. of Symbols			@-- %d", pFileHeader.NumberOfSymbols);
	info("Pointer to Symbol Table		@-- 0x%X", pFileHeader.PointerToSymbolTable);
	info("Characteristics			@-- 0x%X", pFileHeader.Characteristics);
	info("Optional Header Size		@-- 0x%X", pFileHeader.SizeOfOptionalHeader);


	printf("\n#################  O P T I O N A L   H E A D E R  #################\n\n");
	info("OPTIONAL HEADER			@-- 0x%X", pOptionalHeader);
	info("Magic				@-- 0x%X", pOptionalHeader.Magic);
	info(".text Size				@-- 0x%X", pOptionalHeader.SizeOfCode);
	info(".text Offset			@-- 0x%X", pOptionalHeader.BaseOfCode);
	info("Entry Point				@-- 0x%X", pOptionalHeader.AddressOfEntryPoint);
	info("Base of Code			@-- 0x%X", pOptionalHeader.BaseOfCode);
	info("Image Base				@-- 0x%X", pOptionalHeader.ImageBase);
	if (pFileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) info("Base of Data			@-- 0x%X", pOptionalHeader32.BaseOfData);
	if (Verbose) {
		info("Rva & Sizes				@-- 0x%d", pOptionalHeader.NumberOfRvaAndSizes);
		info("MajorOSVersion			@-- 0x%X", pOptionalHeader.MajorOperatingSystemVersion);
		info("MinorOSVersion			@-- 0x%X", pOptionalHeader.MinorOperatingSystemVersion);
		info("MajorLinkerVersion			@-- 0x%X", pOptionalHeader.MajorLinkerVersion);
		info("MinorLinkerVersion			@-- 0x%X", pOptionalHeader.MinorLinkerVersion);
		info("MinorImageVersion			@-- 0x%X", pOptionalHeader.MajorImageVersion);
		info("MinorImageVersion			@-- 0x%X", pOptionalHeader.MinorImageVersion);
		info("Initialized Data Size		@-- 0x%X", pOptionalHeader.SizeOfInitializedData);
		info("Uninitialized Data Size		@-- 0x%X", pOptionalHeader.SizeOfUninitializedData);
		info("Size of Headers			@-- 0x%X", pOptionalHeader.SizeOfHeaders);
		info("Win32VersionValue			@-- 0x%X", pOptionalHeader.Win32VersionValue);
		info("Subsystem				@-- 0x%X", pOptionalHeader.Subsystem);
		info("Image Size				@-- 0x%X", pOptionalHeader.SizeOfImage);
		info("Checksum				@-- 0x%X", pOptionalHeader.CheckSum);
	}


	printf("\n#################         S E C T I O N S         #################\n");

	DWORD _character = 0x00;

	if (Verbose) {
		for (size_t i = 0; i < pFileHeader.NumberOfSections; i++) {
			printf("\n______________  %d: %s  ________________\n\n", i + 1, pSectionHeader[i].Name);
			info("Raw Addr:		0x%X", pSectionHeader[i].PointerToRawData);
			info("Raw Size:		0x%X", pSectionHeader[i].SizeOfRawData);
			info("Virtual Addr:	0x%X", pSectionHeader[i].VirtualAddress);
			info("Virtual Size:	0x%X", pSectionHeader[i].Misc.VirtualSize);
			info("Characteristics:	0x%X", pSectionHeader[i].Characteristics);

			printf("\n[$] Has ");

			_character = pSectionHeader[i].Characteristics;
			if (_character & IMAGE_SCN_CNT_CODE) printf("code; ");
			if (_character & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("Initialized data; ");
			if (_character & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("Uninitialized data; ");
			if (_character & IMAGE_SCN_MEM_READ) printf("Read access; ");
			if (_character & IMAGE_SCN_MEM_WRITE) printf(" Write access; ");
			if (_character & IMAGE_SCN_MEM_EXECUTE) printf(" Can be executed as code; ");
			if (_character & IMAGE_SCN_MEM_DISCARDABLE) printf("Discardable");
			printf("\n");
		}
	}
	else {
		printf("_______________________________________\n\n");
		for (size_t i = 0; i < pFileHeader.NumberOfSections; i++) {
			info("Section %d:  %s", i + 1, pSectionHeader[i].Name);
		}
	}
	printf("_______________________________________\n");

	printf("\n#################         I M P O R T S           #################\n\n");
	info("Data Directory			@-- 0x%X", pOptionalHeader.DataDirectory);
	if (!_32_BIT) {
		info("Export Table			@-- 0x%X | Size: %d", pOptionalHeader.DataDirectory[0].VirtualAddress, pOptionalHeader.DataDirectory[0].Size);
		info("Import Table			@-- 0x%X | Size: %d", pOptionalHeader.DataDirectory[1].VirtualAddress, pOptionalHeader.DataDirectory[1].Size);
		info("IAT					@-- 0x%X | Size: %d", pOptionalHeader.DataDirectory[12].VirtualAddress, pOptionalHeader.DataDirectory[12].Size);

		//if(Verbose) printImports(fileName, _32_BIT);
		printImports(pFile2, pNTHeader, pOptionalHeader, pSectionHeader, Verbose);

	}
	else {
		info("Export Table			@-- 0x%X | Size: %d", pOptionalHeader32.DataDirectory[0].VirtualAddress, pOptionalHeader32.DataDirectory[0].Size);
		info("Import Table			@-- 0x%X | Size: %d", pOptionalHeader32.DataDirectory[1].VirtualAddress, pOptionalHeader32.DataDirectory[1].Size);
		info("IAT					@-- 0x%X | Size: %d", pOptionalHeader32.DataDirectory[12].VirtualAddress, pOptionalHeader32.DataDirectory[12].Size);

		printImports32(pFile2, pNTHeader, pOptionalHeader32, pSectionHeader, Verbose);
	}

	printf("\n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n");

	CloseHandle(hFile);

	return TRUE;
}


int main(int argc, char* argv[]) {

	BOOL Verbose = FALSE;

	if (argc < 2) {
		printHelp();
		exit(0);
	}

	if (_strcmpi(argv[1], "/h") == 0 || _strcmpi(argv[1], "-h") == 0) {
		printHelp();
		exit(0);
	}

	else if (argc >= 3) {
		if (_strcmpi(argv[2], "/v") == 0 || _strcmpi(argv[2], "-v") == 0) {
			Verbose = TRUE;
		}
		if (_strcmpi(argv[2], "/h") == 0 || _strcmpi(argv[2], "-h") == 0) {
			printHelp();
			exit(0);
		}
	}

	peXtract(argv[1], Verbose);

	return 0;
}

