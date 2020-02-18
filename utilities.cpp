#include "everything.h"

VOID FlipBit(BYTE* buffer, DWORD len) {
	while (len-- > 0)
		buffer[len] ^= 0xff;
}

VOID ReportError(LPCSTR userMessage, DWORD exitCode, BOOL printErrorMessage) {
	DWORD eMsgLen, errNum = GetLastError();
	LPTSTR lpvSysMsg;
	fprintf(stderr, "%s\n", userMessage);
	if (printErrorMessage) {
		eMsgLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpvSysMsg, 0, NULL);
		if (eMsgLen > 0)
		{
			fprintf(stderr, "%s\n", lpvSysMsg);
		}
		else
		{
			fprintf(stderr, "Last Error Number; %d.\n", errNum);
		}

		if (lpvSysMsg != NULL) LocalFree(lpvSysMsg);
	}

	if (exitCode > 0)
		ExitProcess(exitCode);

	return;
}


VOID ReportException(LPSTR userMessage, DWORD exceptionCode) {
	if (lstrlen(userMessage) > 0)
		ReportError(userMessage, 0, TRUE);

	if (exceptionCode != 0)
		RaiseException(
		(0x0FFFFFFF & exceptionCode) | 0xE0000000, 0, 0, NULL);

	return;
}

BOOL isFileGood(LPCSTR filename) {
	std::ifstream ifs(filename, std::ifstream::in);
	return ifs.good();
}

