#pragma once
#include "everything.h"

#define NAMESIZE 100

class Binary
{
public:
	Binary() = default;
	~Binary();
	bool initBinary(const char*);
	void loadHeaders();
	void displayHeaders();
	void displayDataDirectories();
	void displaySections();
	void displayImports();
	DWORD RVAtoRaw(DWORD);
	DWORD RawToRVA(DWORD);

	char fileName[NAMESIZE];
	HANDLE hFile, hMap;
	LPBYTE pFile;
	DWORD fileSize;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_FILE_HEADER FileHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeaders;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptors;
	// TO DO
	PIMAGE_EXPORT_DIRECTORY ExportDirectories;
};

const char* const DataDirectoryEntryNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] =
{
	"Export Directory",
	"Import Directory",
	"Resource Directory",
	"Exception Directory",
	"Security Directory",
	"Base Relocation Table",
	"Debug Directory",
	// (X86 usage)
	"Architecture Specific Data",
	"RVA of GP",
	"TLS Directory",
	"Load Configuration Directory",
	"Bound Import Directory in headers",
	"Import Address Table",
	"Delay Load Import Descriptors",
	"COM Runtime descriptor",
	"Reserved"
};

