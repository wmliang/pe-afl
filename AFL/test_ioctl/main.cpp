#include "header.h"

DWORD g_szFile;
HANDLE g_hDev;

struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	const wchar_t* Buffer;
};

struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	_LSA_UNICODE_STRING*           ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
};

BOOL analyze_potential_leaks(PVOID buffer, UINT size) {
	BOOL result = FALSE;
	UINT i;
	if (size < 8) {
		return FALSE;
	}

	for (i = 0; i < size; i += 8) {
		if (i > size)
			break;
		DWORD64 content = ((DWORD64 *)buffer)[i];
		if ((content >= 0xFFFF800000000000 && content <= 0xFFFFFFFFFFFFFFFF) && content != 0xFFFFFFFFFFFFFFFF) {
			printf("LEAK? %i: %p\n", i, content);
		}
		result = TRUE;
	}

	return result;
}

PVOID mapInputFile(TCHAR* filepath)
{
	HANDLE hFile, hMap;
	PVOID pView = NULL;

	g_szFile = 0;

	// Open file
	hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {

		// Create the file mapping object
		hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hMap) {
			pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
			if (pView) {
				_tprintf(_T("Successfully mapped view of file %s as input\n"), filepath);

				g_szFile = GetFileSize(hFile, NULL);
				if (g_szFile == INVALID_FILE_SIZE) {
					_tprintf(_T("Failed to get file size with error %x\n"), GetLastError());
				}
			}
			else {
				_tprintf(_T("Failed to map view of file %s with error %x\n"), filepath, GetLastError());
			}
			CloseHandle(hMap);
		}
		else {
			_tprintf(_T("Failed to create file mapping for %s with error %x\n"), filepath, GetLastError());
		}
		CloseHandle(hFile);
	}
	else {
		_tprintf(_T("Failed to open file %s with error %#.8x\n"), filepath, GetLastError());
	}
	return pView;
}
HANDLE openDev(LPCTSTR deviceName) {
	HANDLE hDev;

	if (!_tcsncmp(deviceName, _T("\\\\.\\"), 4)) {
		hDev = CreateFile(deviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hDev == INVALID_HANDLE_VALUE) {
			_tprintf(_T("Device file %s open failed with GetLastError %#x\n"), deviceName, GetLastError());
			exit(EOF);
		}
	}
	else {

		NTSTATUS
			(NTAPI
			*ntCreateFile)(
			_Out_     PHANDLE FileHandle,
			_In_      ACCESS_MASK DesiredAccess,
			_In_      _OBJECT_ATTRIBUTES* ObjectAttributes,
			_Out_     PVOID IoStatusBlock,
			_In_opt_  PLARGE_INTEGER AllocationSize,
			_In_      ULONG FileAttributes,
			_In_      ULONG ShareAccess,
			_In_      ULONG CreateDisposition,
			_In_      ULONG CreateOptions,
			_In_      PVOID EaBuffer,
			_In_      ULONG EaLength
			);

		HMODULE ntdll = GetModuleHandleA("ntdll");
		*(void**)&ntCreateFile = GetProcAddress(ntdll, "NtCreateFile");

		_LSA_UNICODE_STRING name;
		name.Buffer = deviceName;
		name.Length = name.MaximumLength = _tcslen(deviceName) * 2;

		_OBJECT_ATTRIBUTES attr;
		attr.Length = sizeof(attr);
		attr.RootDirectory = 0;
		attr.ObjectName = &name;
		attr.Attributes = 64;
		attr.SecurityDescriptor = 0;
		attr.SecurityQualityOfService = 0;

		UINT64 tmp[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

		NTSTATUS ns = ntCreateFile(&hDev, MAXIMUM_ALLOWED, &attr, tmp, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0, 0, 0);
		if (ns) {
			_tprintf(_T("Device file %s open failed with NTSTATUS %#x\n"), deviceName, ns);
			exit(EOF);
		}
	}

	_tprintf(_T("Device file %s opened successfully\n"), deviceName);
	return hDev;
}

DWORD sendIoctl(HANDLE hDev, DWORD iocode, PVOID inbuf, DWORD inlen, PVOID outbuf, DWORD outlen)
{
	BOOL bResult, bSent = FALSE, bAddress = FALSE;
	LPTSTR errormessage;
	DWORD bytesreturned = 0;
	DWORD error;

	if (!iocode) return 0;

	if (inbuf) {
		_tprintf(_T("Sending ioctl %#.8x\n"), iocode);
		bResult = DeviceIoControl(hDev, iocode, inbuf, inlen, outbuf, outlen, &bytesreturned, NULL);
		error = bResult ? ERROR_SUCCESS : GetLastError();
		bSent = TRUE;
	}

	if (bSent) {
		if (error == ERROR_SUCCESS) {
			_tprintf(_T("IOCTL completed SUCCESSFULLY, returned %u bytes\n"), bytesreturned);
		}
		else {
			// Verbose error
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
			_tprintf(_T("IOCTL FAILED with error %x: %s\n"), error, errormessage);
			LocalFree(errormessage);
		}
	}

	if (bSent) {
		//hexDump(NULL, outbuf, bytesreturned);
		//analyze_potential_leaks(outbuf, bytesreturned);
	}
	
	return bytesreturned;
}

void init_device(TCHAR* name) {
	g_hDev = openDev(name);
}

void process(HANDLE hDev, DWORD iocode, PTCHAR input_path) {
	TCHAR outbuf[0x10000];

	PVOID inbuf = mapInputFile(input_path);

	if (g_szFile) {
		sendIoctl(hDev, iocode, inbuf, g_szFile, outbuf, g_szFile);
	}
	UnmapViewOfFile(inbuf);
}





INT _tmain(INT argc, TCHAR* argv[]) {

#ifndef UNICODE
	_tprintf(_T("Have to compile with unicode\n"));
	return 0;
#endif

	if (argc == 2) {
		// Test permission
		sendIoctl(openDev(argv[1]), 0, 0, 0, 0, 0);
		return 0;
	}

	if (argc != 4) {
		PFATAL(_T("test_ioctl.exe [device name] [ioctl code] [input buffer]\ntest_ioctl.exe [device name]"));
	}
	TCHAR *stop;
	DWORD ioctl = _tcstoul(argv[2], &stop, 0);

	INIT();
	atexit(FINI);
	init_device(argv[1]);

	while (PERSISTENT_COUNT--) {
		PRE();
		process(g_hDev, ioctl, argv[3]);
		POST();
	}

}
