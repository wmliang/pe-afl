#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#define PFATAL_GLE(msg) { printf("%s, GLE=%d\n", msg, GetLastError()); exit(1); }
#define PFATAL(msg) { printf("%s\n", msg); exit(1); }

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
}
