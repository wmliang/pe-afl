#include "header.h"
#include <intrin.h>
#include <process.h>
#include <fcntl.h>
#include <io.h>

#pragma comment(lib,"ntdll.lib")

#define SHM_ENV_VAR         _T("__AFL_SHM_ID")
#define PIPE_ENV_VAR        _T("__AFL_PIPE_ID")
#define MAP_SIZE 0x10000
#define PAGE_SIZE 0x1000
#define MEM_BARRIER() _ReadWriteBarrier(); MemoryBarrier()
#define DRIVER_NAME _T("\\\\.\\helper")

PUCHAR COV_ADDR = 0;
PUCHAR KCOV_ADDR = 0;
PUCHAR MDL_ADDR = 0;
PUCHAR shared_mem;
HANDLE pipe;
DWORD PERSISTENT_COUNT;
PTCHAR target;
HANDLE hHelper;
DWORD PID;
DWORD CALLBACK_ADDR = 0;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,             // obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef NTSTATUS(NTAPI * _NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS,
	PVOID,
	ULONG,
	PULONG);

SIZE_T get_driver_address(LPCSTR driver, LPCSTR symbol) {
	NTSTATUS status;
	ULONG i;
	ULONG len;

	PRTL_PROCESS_MODULES ModuleInfo;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);

	ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		printf("\nUnable to allocate memory for module list (%d)\n", GetLastError());
		return NULL;
	}

	if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, ModuleInfo, len, &len)))
	{
		printf("\nError: Unable to query module list (%#x)\n", status);
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	SIZE_T addr = 0;
	for (i = 0; i<ModuleInfo->NumberOfModules; i++)
	{
		if (!_stricmp((CHAR*)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName, driver)) {
			//printf("\nImage base: %#x\n", ModuleInfo->Modules[i].ImageBase);
			//printf("\nImage full path: %s\n", ModuleInfo->Modules[i].FullPathName);

			// DONT_RESOLVE_DLL_REFERENCES on some driver return ERROR_MOD_NOT_FOUND
			HINSTANCE h = LoadLibraryExA((LPCSTR)ModuleInfo->Modules[i].FullPathName + 4, NULL, DONT_RESOLVE_DLL_REFERENCES);
			if (symbol) {
				addr = (SIZE_T)ModuleInfo->Modules[i].ImageBase + (SIZE_T)GetProcAddress(h, symbol) - (SIZE_T)h;
			}
			else {
				addr = (SIZE_T)ModuleInfo->Modules[i].ImageBase;
			}
			break;
		}
	}

	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return addr;
}

SIZE_T get_helper_value(LPCSTR symbol) {
	DWORD v = get_driver_address("helper.sys", symbol);
	DWORD v2 = 0;
	if (!HELPER_ReadMemory((PBYTE)v, (PBYTE)&v2, sizeof(DWORD))) {
		PFATAL(_T("Can't read memory\n"));
	}
	return v2;
}

void setup_shmem() {
	HANDLE map_file;

	map_file = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,	// read/write access
		FALSE,					// do not inherit the name
		_tgetenv(SHM_ENV_VAR));	// name of mapping object

	if (map_file == NULL) PFATAL(_T("Error accesing shared memory"));

	shared_mem = (PUCHAR)MapViewOfFile(map_file, // handle to map object
		FILE_MAP_ALL_ACCESS,	// read/write permission
		0,
		0,
		MAP_SIZE);

	if (shared_mem == NULL) PFATAL(_T("Error accesing shared memory"));
	LOG(_T("shared_mem @ %p\n"), shared_mem);
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

	if (pipe == INVALID_HANDLE_VALUE) PFATAL(_T("Error connecting to pipe"));
}

void PRE() {

	if (!_tgetenv(SHM_ENV_VAR)) return;

	CHAR command = 0;
	DWORD num_read;

	ReadFile(pipe, &command, 1, &num_read, NULL);	// blocking
	if (command != 'R') {
		PFATAL(_T("Wrong command @ PRE()"));
	}

	BYTE buf[MAP_SIZE + PAGE_SIZE] = { 0 };
	memcpy(buf + MAP_SIZE + 0x10, &PID, sizeof(DWORD));

	if (CALLBACK_ADDR) {
		memcpy(buf + MAP_SIZE + 0x20, &CALLBACK_ADDR, sizeof(DWORD));
	}
	if (_tgetenv(_T("DUMP_TRACE"))) HELPER_ResetBuffer();

	memcpy(COV_ADDR, buf, sizeof(buf));
}

void dump_trace_buffer() {
	DWORD tbl_idx = get_helper_value("tbl_idx");
	printf("number of basic block = %d\n", tbl_idx);
	if (!tbl_idx) return;

	PBYTE base = (PBYTE)get_driver_address(getenv("AFL_TARGET"), NULL);
	PBYTE tbl = (PBYTE)get_helper_value("tbl");
	PULONG p = (PULONG)malloc(tbl_idx*sizeof(PULONG));
	if (!HELPER_ReadMemory(tbl, (PBYTE)p, tbl_idx*sizeof(PULONG))) {
		PFATAL(_T("Can't read memory\n"));
	}

	// convert the address with mapping.txt
	PCHAR out_file = "trace.txt";
	_unlink(out_file);
	DWORD fd = _open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) PFATAL(_T("Unable to create trace file"));

	FILE* f = _fdopen(fd, "w");
	for (DWORD i = 0; i < tbl_idx; i++) {
		fprintf(f, "%x\n", (PBYTE)p[i] - (PBYTE)base);
	}
	fclose(f);

	printf("trace.txt is created\n");
}

void POST() {

	if (!_tgetenv(SHM_ENV_VAR)) return;

	memcpy(shared_mem, COV_ADDR, MAP_SIZE);
	MEM_BARRIER();

	if (_tgetenv(_T("DUMP_TRACE"))) dump_trace_buffer();

	DWORD num_written;
	if (PERSISTENT_COUNT) {
		WriteFile(pipe, "K", 1, &num_written, NULL);
	}
	else {
		WriteFile(pipe, "Q", 1, &num_written, NULL);
	}

}

void CRASH() {
	// PASS
}

void INIT() {

	target = _tgetenv(_T("AFL_TARGET"));
	if (!target) {
		PFATAL(_T("Can not getenv AFL_TARGET\n"));
	}

	if (_tgetenv(SHM_ENV_VAR)) {
		setup_shmem();
		setup_pipe();
		PERSISTENT_COUNT = 10000;

		hHelper = CreateFile(DRIVER_NAME, MAXIMUM_ALLOWED, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hHelper == INVALID_HANDLE_VALUE) {
			PFATAL(_T("Can't create helper driver\n"));
		}

		LOG(_T("GetModuleSectionAddress(%s)\n"), target);
		KCOV_ADDR = (PUCHAR)HELPER_GetModuleSectionAddress(target);
		LOG(_T("Kernel coverage map @ 0x%X\n"), KCOV_ADDR);
		if (!KCOV_ADDR) {
			PFATAL(_T("Can't get section address\n"));
		}

		CALLBACK_ADDR = get_driver_address("helper.sys", "_callback@0");
		PID = _getpid();

		HELPER_MapMemory(KCOV_ADDR, MAP_SIZE + PAGE_SIZE, (PBYTE*)&COV_ADDR, (PBYTE*)&MDL_ADDR);
		LOG(_T("User coverage map @ %p\n"), COV_ADDR);
		LOG(_T("MDL @ %p\n"), MDL_ADDR);

	}
	else {
		PERSISTENT_COUNT = 1;
	}

}

void FINI()
{
	if (COV_ADDR && MDL_ADDR) {
		HELPER_UnmapMemory(COV_ADDR, MDL_ADDR);
	}
}