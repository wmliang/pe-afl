#include <ntddk.h>
#include <Ntstrsafe.h>
#include "main.h"

#pragma warning (disable: 4201)
#define DRIVER_NAME                       L"\\Device\\helper"
#define DEVICE_NAME                       L"\\DosDevices\\helper"
#define IMAGE_SIZEOF_SHORT_NAME           8
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16
#define IMAGE_NT_SIGNATURE                0x00004550  // PE00
#define IMAGE_DOS_SIGNATURE               0x5A4D      // MZ

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONG BaseOfData;
	ULONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Reserved1;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONG SizeOfStackReserve;
	ULONG SizeOfStackCommit;
	ULONG SizeOfHeapReserve;
	ULONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;


typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	}Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_DOS_HEADER { // DOS .EXE header
	USHORT e_magic;                 // Magic number
	USHORT e_cblp;                  // Bytes on last page of file
	USHORT e_cp;                    // Pages in file
	USHORT e_crlc;                  // Relocations
	USHORT e_cparhdr;               // Size of header in paragraphs
	USHORT e_minalloc;              // Minimum extra paragraphs needed
	USHORT e_maxalloc;              // Maximum extra paragraphs needed
	USHORT e_ss;                    // Initial (relative) SS value
	USHORT e_sp;                    // Initial SP value
	USHORT e_csum;                  // Checksum
	USHORT e_ip;                    // Initial IP value
	USHORT e_cs;                    // Initial (relative) CS value
	USHORT e_lfarlc;                // File address of relocation table
	USHORT e_ovno;                  // Overlay number
	USHORT e_res[4];                // Reserved words
	USHORT e_oemid;                 // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;               // OEM information; e_oemid specific
	USHORT e_res2[10];              // Reserved words
	ULONG e_lfanew;                 // File address of new exe header
}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define MAX_PATH_LEN 1024

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONG  Unused;
	ULONG  Always0;
	PVOID  ModuleBaseAddress;
	ULONG  ModuleSize;
	ULONG  Unknown;
	ULONG  ModuleEntryIndex;
	USHORT ModuleNameLength;
	USHORT ModuleNameOffset;
	CHAR   ModuleName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

// Class 11
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG  Unknown1;
	ULONG  Unknown2;
#ifdef _WIN64
	ULONG Unknown3;
	ULONG Unknown4;
#endif
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

//extern "C" 
NTKERNELAPI  NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

PVOID
KernelGetModuleBase(
	PCHAR  pModuleName
)
{
	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;

	__try
	{
		NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
		ULONG    SystemInfoBufferSize = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation,
			&SystemInfoBufferSize,
			0,
			&SystemInfoBufferSize);

		if (!SystemInfoBufferSize)
			return NULL;

		pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

		if (!pSystemInfoBuffer)
			return NULL;

		memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

		status = ZwQuerySystemInformation(SystemModuleInformation,
			pSystemInfoBuffer,
			SystemInfoBufferSize * 2,
			&SystemInfoBufferSize);

		if (NT_SUCCESS(status))
		{
			PSYSTEM_MODULE_ENTRY pSysModuleEntry = (PSYSTEM_MODULE_ENTRY)
				((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
			ULONG i;

			for (i = 0; i <((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
			{
				if (_stricmp(pSysModuleEntry[i].ModuleName +
					pSysModuleEntry[i].ModuleNameOffset, pModuleName) == 0)
				{
					pModuleBase = pSysModuleEntry[i].ModuleBaseAddress;
					break;
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		pModuleBase = NULL;
	}
	if (pSystemInfoBuffer) {
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
} // end KernelGetModuleBase()

void Unload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("helper driver unloaded !\n"));
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS WriteMemory(ULONG ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
		__try {
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					KdPrint(("MmProtectMdlSystemAddress successed\n"));
					RtlCopyMemory(ptrBuffer, pData, ulLen);
					KdPrint(("Write data complete\n"));
				}
				else {
					KdPrint(("MmProtectMdlSystemAddress failed 0x%X\n", status));
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			MmUnlockPages(ptrMdl);
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS ReadMemory(ULONG ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
		__try {
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					KdPrint(("MmProtectMdlSystemAddress successed\n"));
					RtlCopyMemory(pData, ptrBuffer, ulLen);
					KdPrint(("Read data complete\n"));
				}
				else {
					KdPrint(("MmProtectMdlSystemAddress failed 0x%X\n", status));
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			MmUnlockPages(ptrMdl);
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS MapMemory(ULONG ulAddr, ULONG ulLen, PVOID *ptrBuffer, PMDL *ptrMdl)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	*ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (*ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
		__try {
			MmBuildMdlForNonPagedPool(*ptrMdl);
			*ptrBuffer = MmMapLockedPagesSpecifyCache(*ptrMdl, UserMode, MmCached, NULL, FALSE, HighPagePriority);
			if (*ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			return STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}
		/*
		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}
		if (ptrMdl) {
			IoFreeMdl(ptrMdl);
		}
		*/
	}
	return status;
}
VOID UnmapMemory(PVOID ptrBuffer, PMDL ptrMdl)
{
	if (ptrBuffer) {
		MmUnmapLockedPages(ptrBuffer, ptrMdl);
	}
	if (ptrMdl) {
		IoFreeMdl(ptrMdl);
	}
}

#define DllExport _declspec(dllexport)
DWORD tbl_size = 0x100;
DllExport DWORD tbl_idx = 0;
DllExport DWORD* tbl = NULL;
DllExport NTSTATUS callback() {
	if (!tbl) tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(DWORD), 0x41414141);
	if (tbl_idx >= tbl_size) {
		DWORD* old_tbl = tbl;
		tbl_size *= 2;
		tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(DWORD), 0x41414141);
		memcpy(tbl, old_tbl, tbl_size * sizeof(DWORD) / 2);
		ExFreePoolWithTag(old_tbl, 0x41414141);
	}
	tbl[tbl_idx++] = (DWORD)_ReturnAddress();
	return 0;
}

void dump_and_reset_callback() {
	for (DWORD i = 0; i < tbl_idx; i++) {
		KdPrint(("%x\n", tbl[i]));
	}
	if (tbl) {
		ExFreePoolWithTag(tbl, 0x41414141);
		tbl = NULL;
		tbl_size = 0x100;
		tbl_idx = 0;
	}
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	ULONG i = 0, code = 0, len = 0, size = 0;
	ULONG ptrBaseAddr = 0, ptrRetAddr = 0;
	ULONG ptrTag = 0, ptrType = 0;
	ULONG ptrUserAddr = 0, ptrMdl = 0;
	PIO_STACK_LOCATION stack = NULL;
	ANSI_STRING cov = { 4,5,".cov" };
	ANSI_STRING secName;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (code) {
	case IOCTL_HELPER_GET_SECTION_ADDRESS:
		KdPrint(("Get Section Address: %ws\n", (PWCHAR)pIrp->AssociatedIrp.SystemBuffer));

		CHAR name[MAX_PATH_LEN] = { 0 };
		RtlStringCchPrintfA(name, MAX_PATH_LEN, "%ws", pIrp->AssociatedIrp.SystemBuffer);
		ptrBaseAddr = (ULONG)KernelGetModuleBase(name);
		KdPrint(("KernelGetModuleBase(%s) = %X\n", name, ptrBaseAddr));

		if (ptrBaseAddr && (((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
			IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
			IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
			IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
			IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
			for (i = 0; i<pFileheader->NumberOfSections; i++) {
				RtlInitAnsiString(&secName, (PCSZ)sectionHeader->Name);
				if (RtlCompareString(&secName, &cov, TRUE) == 0) {
					ptrRetAddr = sectionHeader->VirtualAddress;
				}
				/*
				KdPrint(("------------------------------------------------------------------\n"));
				KdPrint(("Section Name = %s\n", sectionHeader->Name));
				KdPrint(("Virtual Offset = %X\n", sectionHeader->VirtualAddress));
				KdPrint(("Virtual Size = %X\n", sectionHeader->Misc.VirtualSize));
				KdPrint(("Raw Offset = %X\n", sectionHeader->PointerToRawData));
				KdPrint(("Raw Size = %X\n", sectionHeader->SizeOfRawData));
				KdPrint(("Characteristics = %X\n", sectionHeader->Characteristics));
				KdPrint(("------------------------------------------------------------------\n"));
				*/
				sectionHeader++;
			}
		}
		if(ptrRetAddr) ptrRetAddr += ptrBaseAddr;
		KdPrint((".cov Address: 0x%X\n", ptrRetAddr));
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrRetAddr;

		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_READ_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		KdPrint(("Read memory: addr 0x%X, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength));
#if 0
		ReadMemory(ptrBaseAddr, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
#else
		RtlCopyMemory((UCHAR*)pIrp->AssociatedIrp.SystemBuffer, (UCHAR*)ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength);
#endif
		len = stack->Parameters.DeviceIoControl.InputBufferLength;
		break;
	case IOCTL_HELPER_WRITE_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		KdPrint(("Write memory: addr 0x%X, size %d\n", ptrBaseAddr, stack->Parameters.DeviceIoControl.InputBufferLength));
		WriteMemory(ptrBaseAddr, (UCHAR*)pIrp->UserBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
		len = 0;
		break;
	case IOCTL_HELPER_ALLOCATE_MEMORY:
		ptrType = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		size = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer+1);
		ptrTag = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer+2);
		KdPrint(("Allocate memory: pooltype 0x%x, tag %X, size 0x%x\n", ptrType, ptrTag, size));
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = (ULONG)ExAllocatePoolWithTag(ptrType, size, ptrTag);
		len = sizeof(ULONG);
		break;
	case IOCTL_HELPER_FREE_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		ptrTag = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer+1);
		KdPrint(("free memory: tag %X, address 0x%x\n", ptrTag, ptrBaseAddr));
		ExFreePoolWithTag((PVOID)ptrBaseAddr, ptrTag);
		len = 0;
		break;
	case IOCTL_HELPER_MAP_MEMORY:
		ptrBaseAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		size = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer + 1);
		KdPrint(("Kernel Address: 0x%X\n", ptrBaseAddr));
		KdPrint(("Size: 0x%X\n", size));
		NTSTATUS ns = MapMemory(ptrBaseAddr, size, (PVOID*)&ptrUserAddr, (PMDL*)&ptrMdl);
		if (ns == STATUS_SUCCESS) {
			KdPrint(("Mapped User Address: 0x%X\n", ptrUserAddr));
			KdPrint(("MDL Address: 0x%X\n", ptrMdl));
		}
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer) = ptrUserAddr;
		*((ULONG*)pIrp->AssociatedIrp.SystemBuffer+1) = ptrMdl;
		len = sizeof(ULONG)*2;
		break;
	case IOCTL_HELPER_UNMAP_MEMORY:
		ptrUserAddr = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		ptrMdl = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer + 1);
		KdPrint(("Unmapped User Address: 0x%X\n", ptrUserAddr));
		KdPrint(("MDL Address: 0x%X\n", ptrMdl));
		UnmapMemory((PVOID)ptrUserAddr, (PMDL)ptrMdl);
		len = 0;
		break;
	case IOCTL_HELPER_DUMP_AND_RESET_CALLBACK:
		dump_and_reset_callback();
		len = 0;
		break;
	default:
		KdPrint(("Invalid IOCTL code: 0x%X\n", code));
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("helper driver loaded\n"));
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
		pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
