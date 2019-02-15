#define _CRT_SECURE_NO_WARNINGS

// VC++ Directory += $(ProgramFiles)\Common Files\System\ado\;
#import "msado15.dll" no_namespace rename("EOF", "EndOfFile")

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

#define PFATAL_GLE(msg) { _tprintf(_T("%s, GLE=%d\n"), msg, GetLastError()); exit(1); }
#define PFATAL(msg) { _tprintf(_T("%s\n"), msg); exit(1); }
#define PFATAL2_GLE(msg) { printf("%s, GLE=%d\n", msg, GetLastError()); exit(1); }
#define PFATAL2(msg) { printf("%s\n", msg); exit(1); }

void INIT();
void PRE();
void POST();
extern DWORD PERSISTENT_COUNT;

static void LOG(LPCSTR lpFormat, ...)
{
	CHAR buf[1024];
	va_list va;

	va_start(va, lpFormat);
	StringCbVPrintfA(buf, sizeof(buf), lpFormat, va);
	OutputDebugStringA(buf);

	_tprintf(_T("%s\n"), buf);
}
