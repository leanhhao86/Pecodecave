#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include "PEParse.h"

#define FILEALIGMENT 0x200
VOID ReportError(LPCSTR userMessage, DWORD exitCode, BOOL printErrorMessage);
VOID ReportException(LPSTR userMessage, DWORD exceptionCode);
BOOL isFileGood(LPCSTR filename);