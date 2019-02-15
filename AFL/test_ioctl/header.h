#ifndef __MAIN_H__
#define __MAIN_H__

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h> // winsock2 MUST include before windows
#include <windows.h>
#include <tchar.h>
#include <stdio.h>

#include "helper.h"

#define PFATAL_GLE(msg) { _tprintf(_T("%s, GLE=%d\n"), msg, GetLastError()); exit(1); }
#define PFATAL(msg) { _tprintf(_T("%s\n"), msg); exit(1); }

void INIT();
void PRE();
void POST();
void FINI();
extern DWORD PERSISTENT_COUNT;
extern HANDLE hHelper;
DWORD HELPER_GetModuleSectionAddress(PTCHAR pBuffer);
DWORD HELPER_ReadMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen);
DWORD HELPER_WriteMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen);
DWORD HELPER_AllocateMemory(DWORD dwPoolType, DWORD dwTag, DWORD dwLen);
DWORD HELPER_FreeMemory(PBYTE dwAddr, DWORD dwTag);
DWORD HELPER_MapMemory(PBYTE dwAddr, DWORD dwLen, PBYTE* ptrUserAddr, PBYTE* ptrMdl);
DWORD HELPER_UnmapMemory(PBYTE ptrUserAddr, PBYTE ptrMdl);
DWORD HELPER_ResetBuffer();

static void LOG(TCHAR *fmt, ...)
{
	TCHAR szBuf[MAX_PATH] = { 0 };

	va_list ap;
	va_start(ap, fmt);
	_vstprintf_s(szBuf, fmt, ap);
	va_end(ap);
	OutputDebugString(szBuf);

	//_tprintf(L"%s", szBuf);
}

static void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

#endif
