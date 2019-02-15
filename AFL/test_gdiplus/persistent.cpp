#include "header.h"
#include <intrin.h>

#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define PIPE_ENV_VAR        "__AFL_PIPE_ID"
#define MAP_SIZE 0x10000
#define PAGE_SIZE 0x1000
#define MEM_BARRIER() _ReadWriteBarrier(); MemoryBarrier()

PCHAR target;
PCHAR target_addr;
PCHAR afl_area;
HANDLE pipe;
DWORD PERSISTENT_COUNT;

PCHAR get_section_addr(PCHAR target, PCHAR section) {
	ULONG i = 0;
	HMODULE ptrBaseAddr = GetModuleHandleA(target);
	if (!ptrBaseAddr) return NULL;

	if ((((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
		IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
		IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
		IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
		IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
		IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
		for (i = 0; i<pFileheader->NumberOfSections; i++) {
			if (!strcmp((PCHAR)sectionHeader->Name, section)) {
				return (PCHAR)ptrBaseAddr + sectionHeader->VirtualAddress;
			}
			sectionHeader++;
		}
	}
	return NULL;
}

void setup_shmem() {
	HANDLE map_file;

	map_file = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,	// read/write access
		FALSE,					// do not inherit the name
		getenv(SHM_ENV_VAR));	// name of mapping object

	if (map_file == NULL) PFATAL("Error accesing shared memory");

	afl_area = (PCHAR)MapViewOfFile(map_file, // handle to map object
		FILE_MAP_ALL_ACCESS,	// read/write permission
		0,
		0,
		MAP_SIZE);

	if (afl_area == NULL) PFATAL("Error accesing shared memory");
}

void setup_pipe() {
	pipe = CreateFile(
		getenv(PIPE_ENV_VAR),   // pipe name
		GENERIC_READ |  // read and write access
		GENERIC_WRITE,
		0,              // no sharing
		NULL,           // default security attributes
		OPEN_EXISTING,  // opens existing pipe
		0,              // default attributes
		NULL);          // no template file

	if (pipe == INVALID_HANDLE_VALUE) PFATAL("Error connecting to pipe");
}

void PRE() {
	if (!getenv(SHM_ENV_VAR)) return;

	char command = 0;
	DWORD num_read;
	char buf[256];

	ReadFile(pipe, &command, 1, &num_read, NULL);	// blocking
	if (command != 'R') {
		sprintf(buf, "Wrong command, %hd", command);
		PFATAL(buf);
	}

	if (!target_addr) {
		target_addr = get_section_addr(target, ".cov");
	}
	if (target_addr) {
		memset(target_addr, 0, MAP_SIZE + PAGE_SIZE);	// clear afl_prev_loc
	}
	else {
		PFATAL("Can not get .cov section");
	}
}

void POST() {
	if (!getenv(SHM_ENV_VAR)) return;

	if (target_addr) {
		memcpy(afl_area, target_addr, MAP_SIZE);
		MEM_BARRIER();
	}
	else {
		PFATAL("Can not get .cov section");
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
	if (!getenv(SHM_ENV_VAR)) return;

	if (target_addr) {
		memcpy(afl_area, target_addr, MAP_SIZE);
		MEM_BARRIER();
	}
	else {
		PFATAL("Can not get .cov section");
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
		PFATAL("Can not getenv AFL_TARGET\n");
	}

	if (getenv(SHM_ENV_VAR)) {
		setup_shmem();
		setup_pipe();
		PERSISTENT_COUNT = 10000;
	}
	else {
		PERSISTENT_COUNT = 1;
	}

	SetUnhandledExceptionFilter(log_exception);
}