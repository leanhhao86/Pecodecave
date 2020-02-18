#include "PEParse.h"
#include "everything.h"

Binary::~Binary() {
	UnmapViewOfFile(pFile);
	//CloseHandle(hMap);
	CloseHandle(hFile);
}

bool Binary::initBinary(const char* filename) {
	strcpy_s(fileName, NAMESIZE, filename);
	hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		ReportError("Failed to create file handle", 1, true);
	}

	this->fileSize = GetFileSize(hFile, NULL);

	// Create file mapping object
	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fileSize, fileName);
	if (hMap == NULL) {
		ReportError("Failed to create mapping object", 1, true);
	}
	// Map the input file
	pFile = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pFile == NULL) {
		ReportError("Failed to get view of mapping object", 1, true);
	}
	return true;
}


void Binary::loadHeaders() {
	DOSHeader = (PIMAGE_DOS_HEADER)pFile;
	NTHeader = (PIMAGE_NT_HEADERS)(pFile + DOSHeader->e_lfanew);
	FileHeader = (PIMAGE_FILE_HEADER) & (NTHeader->FileHeader);
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (NTHeader->OptionalHeader);
	SectionHeaders = (PIMAGE_SECTION_HEADER)((DWORD)NTHeader + sizeof(DWORD) + (DWORD)sizeof(IMAGE_FILE_HEADER) + (DWORD)FileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY ImportDataDirectory = &(OptionalHeader->DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ImportDescriptors = PIMAGE_IMPORT_DESCRIPTOR(this->RVAtoRaw(ImportDataDirectory->VirtualAddress));
}

void Binary::displayHeaders() {
	if (DOSHeader == NULL) {
		ReportError("DOS Header not loaded properly", 0, true);
		return;
	}
	printf("*******\t DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", DOSHeader->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", DOSHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", DOSHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", DOSHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", DOSHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", DOSHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", DOSHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", DOSHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", DOSHeader->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", DOSHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", DOSHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", DOSHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", DOSHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", DOSHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", DOSHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", DOSHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", DOSHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", DOSHeader->e_lfanew);

	if (NTHeader == NULL) {
		ReportError("NT Header not loaded properly", 0, true);
		return;
	}
	printf("******\t NT HEADER ******\n");
	printf("\t0x%x\t\tSignature\n", NTHeader->Signature);
	printf("****** FILE HEADER ******\n");
	printf("\t0x%x\t\tMachine\n", FileHeader->Machine);
	printf("\t0x%x\t\tNumberOfSections\n", FileHeader->NumberOfSections);
	printf("\t0x%x\tTimeDateStamp\n", FileHeader->TimeDateStamp);
	printf("\t0x%x\t\tPointerToSymbolTable\n", FileHeader->PointerToSymbolTable);
	printf("\t0x%x\t\tNumberOfSymbols\n", FileHeader->NumberOfSymbols);
	printf("\t0x%x\t\tSizeOfOptionalHeader\n", FileHeader->SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", FileHeader->Characteristics);

	printf("******\t OPTIONAL HEADER ******\n");
	//
	// Standard fields.
	//

	printf("\t0x%x\t\tMagic\n", OptionalHeader->Magic);
	printf("\t0x%x\t\tMajorLinkerVersion\n", OptionalHeader->MajorLinkerVersion);
	printf("\t0x%x\t\tMinorLinkerVersion\n", OptionalHeader->MinorLinkerVersion);
	printf("\t0x%x\t\tSizeOfCode\n", OptionalHeader->SizeOfCode);
	printf("\t0x%x\t\tSizeOfInitializedData\n", OptionalHeader->SizeOfInitializedData);
	printf("\t0x%x\t\tSizeOfUninitializedData\n", OptionalHeader->SizeOfUninitializedData);
	printf("\t0x%x\t\tAddressOfEntryPoint\n", OptionalHeader->AddressOfEntryPoint);
	printf("\t0x%x\t\tBaseOfCode\n", OptionalHeader->BaseOfCode);
	printf("\t0x%x\t\tBaseOfData\n", OptionalHeader->BaseOfData);

	//
	// NT additional fields.
	//

	printf("\t0x%x\t\tImageBase\n", OptionalHeader->ImageBase);
	printf("\t0x%x\t\tSectionAlignment\n", OptionalHeader->SectionAlignment);
	printf("\t0x%x\t\tFileAlignment\n", OptionalHeader->FileAlignment);
	printf("\t0x%x\t\tMajorOperatingSystemVersion\n", OptionalHeader->MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinorOperatingSystemVersion\n", OptionalHeader->MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajorImageVersion\n", OptionalHeader->MajorImageVersion);
	printf("\t0x%x\t\tMinorImageVersion\n", OptionalHeader->MinorImageVersion);
	printf("\t0x%x\t\tMajorSubsystemVersion\n", OptionalHeader->MajorSubsystemVersion);
	printf("\t0x%x\t\tMinorSubsystemVersion\n", OptionalHeader->MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32VersionValue\n", OptionalHeader->Win32VersionValue);
	printf("\t0x%x\t\tSizeOfImage\n", OptionalHeader->SizeOfImage);
	printf("\t0x%x\t\tSizeOfHeaders\n", OptionalHeader->SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", OptionalHeader->CheckSum);
	printf("\t0x%x\t\tSubsystem\n", OptionalHeader->Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", OptionalHeader->DllCharacteristics);
	printf("\t0x%x\t\tSizeOfStackReserve\n", OptionalHeader->SizeOfStackReserve);
	printf("\t0x%x\t\tSizeOfStackCommit\n", OptionalHeader->SizeOfStackCommit);
	printf("\t0x%x\t\tSizeOfHeapReserve\n", OptionalHeader->SizeOfHeapReserve);
	printf("\t0x%x\t\tSizeOfHeapCommit\n", OptionalHeader->SizeOfHeapCommit);
	printf("\t0x%x\t\tLoaderFlags\n", OptionalHeader->LoaderFlags);
	printf("\t0x%x\t\tNumberOfRvaAndSizes\n", OptionalHeader->NumberOfRvaAndSizes);
}

void Binary::displayDataDirectories() {
	if (OptionalHeader == NULL) {
		ReportError("Optional Header not loaded properly", 0, true);
		return;
	}
	PIMAGE_DATA_DIRECTORY DataDirectories = (OptionalHeader->DataDirectory);
	printf("******\t DATA DIRECTORIES ******\n");
	printf("\tRVA\t\tSize\t\tName\n");
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		printf("\t0x%x\t\t0x%x\t\t%s\n", DataDirectories[i].VirtualAddress,
			DataDirectories[i].Size,
			DataDirectoryEntryNames[i]);
	}
}

void Binary::displaySections() {
	int i;
	if (SectionHeaders == NULL) {
		ReportError("Section Headers not loaded properly", 0, true);
		return;
	}
	printf("******\t SECTION HEADERS ******\n");
	printf("Name\tMisc\tVirtualAddress\tRawSize\tRawAddress\tRelocAddress\tLineNumbers\tRelocNumber\tNumberOfLinenumbers\tCharacteristics\n");
	for (i = 0; i < FileHeader->NumberOfSections; i++) {
		printf("%.*s\t0x%x\t0x%x\t\t0x%x\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t\t0x%x\n",
			IMAGE_SIZEOF_SHORT_NAME,
			SectionHeaders[i].Name,
			SectionHeaders[i].Misc,
			SectionHeaders[i].VirtualAddress,
			SectionHeaders[i].SizeOfRawData,
			SectionHeaders[i].PointerToRawData,
			SectionHeaders[i].PointerToRelocations,
			SectionHeaders[i].PointerToLinenumbers,
			SectionHeaders[i].NumberOfRelocations,
			SectionHeaders[i].NumberOfLinenumbers,
			SectionHeaders[i].Characteristics);
	}
}

DWORD Binary::RVAtoRaw(DWORD RVA) {
	PIMAGE_SECTION_HEADER ContainerSection = NULL;	// section that contains import descriptor table
	for (int i = 0; i < FileHeader->NumberOfSections; i++) {
		if (RVA >= SectionHeaders[i].VirtualAddress &&
			RVA <= (SectionHeaders[i].VirtualAddress +
				SectionHeaders[i].SizeOfRawData))
			ContainerSection = &SectionHeaders[i];
	}
	if (ContainerSection == NULL) return 0;
	return DWORD(pFile + RVA - ContainerSection->VirtualAddress + ContainerSection->PointerToRawData);
}

DWORD Binary::RawToRVA(DWORD Raw) {
	PIMAGE_SECTION_HEADER currentSection;
	for (DWORD idx = 0; idx < FileHeader->NumberOfSections; idx++) {
		currentSection = &SectionHeaders[idx];
		if (Raw > currentSection->PointerToRawData&&
			Raw < currentSection->PointerToRawData + currentSection->SizeOfRawData) {
			Raw -= currentSection->PointerToRawData;
			Raw += currentSection->VirtualAddress;
			return Raw;
		}
	}
}

void Binary::displayImports() {
	PIMAGE_IMPORT_DESCRIPTOR ip = ImportDescriptors;
	PIMAGE_THUNK_DATA Thunk = NULL;
	if (ip == NULL) {
		ReportError("Import Descriptors not loaded properly", 0, true);
		return;
	}
	printf("******\t IMPORT DIRECTORY ******\n");
	for (int i = 0; ip[i].Name != 0; i++) {
		printf("\t%s\n", RVAtoRaw(ip[i].Name));

		Thunk = (PIMAGE_THUNK_DATA)RVAtoRaw(ip[i].FirstThunk);

		for (; Thunk->u1.AddressOfData != 0; Thunk++) {
			if ((Thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) == 0)
				printf("\t\t%s\n", ((PIMAGE_IMPORT_BY_NAME)RVAtoRaw(Thunk->u1.AddressOfData))->Name);
			else
				printf("\t\tOrdinal%d\n", Thunk->u1.Ordinal);
		}
	}
}