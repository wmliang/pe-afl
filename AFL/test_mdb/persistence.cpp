#include "header.h"
#include <intrin.h>

#define SHM_ENV_VAR         _T("__AFL_SHM_ID")
#define PIPE_ENV_VAR        _T("__AFL_PIPE_ID")
#define MAP_SIZE 0x10000
#define PAGE_SIZE 0x1000
#define MEM_BARRIER() _ReadWriteBarrier(); MemoryBarrier()
//#pragma warning(disable : 4995) 

PCHAR target;
PCHAR cov_addr;
PCHAR afl_area;
HANDLE pipe;
DWORD PERSISTENT_COUNT;

void get_section(PCHAR target, PCHAR section, PCHAR *addr, PDWORD len) {
	ULONG i = 0;
	HMODULE ptrBaseAddr = GetModuleHandleA(target);
	if (!ptrBaseAddr) return;

	if ((((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
		IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
		IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
		IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
		IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
		IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
		for (i = 0; i<pFileheader->NumberOfSections; i++) {
			if (!strcmp((PCHAR)sectionHeader->Name, section)) {
				if (addr)	*addr = (PCHAR)ptrBaseAddr + sectionHeader->VirtualAddress;
				if (len)	*len = sectionHeader->Misc.VirtualSize;
				return;
			}
			sectionHeader++;
		}
	}
}

void setup_shmem() {
	HANDLE map_file;

	map_file = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,	// read/write access
		FALSE,					// do not inherit the name
		_tgetenv(SHM_ENV_VAR));	// name of mapping object

	if (map_file == NULL) PFATAL2("Error accesing shared memory\n");

	afl_area = (PCHAR)MapViewOfFile(map_file, // handle to map object
		FILE_MAP_ALL_ACCESS,	// read/write permission
		0,
		0,
		MAP_SIZE);

	if (afl_area == NULL) PFATAL2("Error accesing shared memory\n");
}

void setup_pipe() {
	pipe = CreateFile(
		_tgetenv(PIPE_ENV_VAR),   // pipe name
		GENERIC_READ |  // read and write access
		GENERIC_WRITE,
		0,              // no sharing
		NULL,           // default security attributes
		OPEN_EXISTING,  // opens existing pipe
		0,              // default attributes
		NULL);          // no template file

	if (pipe == INVALID_HANDLE_VALUE) PFATAL2("Error connecting to pipe\n");
}

void PRE() {
	if (!_tgetenv(SHM_ENV_VAR)) return;

	char command = 0;
	DWORD num_read;
	char buf[256];

	ReadFile(pipe, &command, 1, &num_read, NULL);	// blocking
	if (command != 'R') {
		sprintf(buf, "Wrong command, %hd\n", command);
		PFATAL2(buf);
	}

	if (!cov_addr) {
		get_section(target, ".cov", &cov_addr, NULL);
	}
	if (cov_addr) {
		memset(cov_addr, 0, MAP_SIZE + PAGE_SIZE);	// clear afl_prev_loc
	}
	else {
		PFATAL2("Can not get .cov section\n");
	}

}

void POST() {
	if (!_tgetenv(SHM_ENV_VAR)) return;

	if (cov_addr) {
		memcpy(afl_area, cov_addr, MAP_SIZE);
		MEM_BARRIER();
	}
	else {
		PFATAL2("Can not get .cov section\n");
	}

	DWORD num_written;
	if (PERSISTENT_COUNT) {
		WriteFile(pipe, "K", 1, &num_written, NULL);
	}
	else {
		WriteFile(pipe, "Q", 1, &num_written, NULL);
	}
}

void CRASH() {
	if (!_tgetenv(SHM_ENV_VAR)) return;

	if (cov_addr) {
		memcpy(afl_area, cov_addr, MAP_SIZE);
		MEM_BARRIER();
	}
	else {
		PFATAL2("Can not get .cov section\n");
	}

	DWORD num_written;
	WriteFile(pipe, "C", 1, &num_written, NULL);
}

LONG WINAPI log_exception(LPEXCEPTION_POINTERS exceptionInfo)
{

	// Send crash signal and update .cov
	CRASH();

	printf("-----EXCEPTION CAUGHT-----\n");
	printf("Exception Code: %#.8x\n", exceptionInfo->ExceptionRecord->ExceptionCode);
	printf("Exception Address: %#.8x\n", exceptionInfo->ExceptionRecord->ExceptionAddress);

	ExitProcess(0x1337);
	// Never return

	return EXCEPTION_EXECUTE_HANDLER;
}

void INIT() {
	target = getenv("AFL_TARGET");
	if (!target) {
		PFATAL2("Can not getenv AFL_TARGET\n");
	}

	if (_tgetenv(SHM_ENV_VAR)) {
		setup_shmem();
		setup_pipe();
		PERSISTENT_COUNT = 10000;
	}
	else {
		PERSISTENT_COUNT = 1;
	}

	SetUnhandledExceptionFilter(log_exception);
}