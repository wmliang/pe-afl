#include "common.h"

NTSTATUS TriggerDemo(IN PCHAR UserBuffer, IN SIZE_T Size);
NTSTATUS DemoIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerDemo)
#pragma alloc_text(PAGE, DemoIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)


NTSTATUS TriggerDemo(IN PCHAR UserBuffer, IN SIZE_T Size) {
	//PVOID KernelBuffer = NULL;
	//UCHAR KernelBuffer2[10];
	NTSTATUS Status = STATUS_SUCCESS;

	PAGED_CODE();

	__try {

		// Verify if the buffer resides in user mode
		ProbeForRead(UserBuffer, 0x10, (ULONG)__alignof(UCHAR));

		DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
		DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);

		if (UserBuffer[0] == 'B') {
			if (UserBuffer[1] == 'L') {
				if (UserBuffer[2] == 'U') {
					if (UserBuffer[3] == 'E') {
						KeBugCheck(0x1337);
						if (UserBuffer[4] == 'H') {
							if (UserBuffer[5] == 'A') {
								if (UserBuffer[6] == 'T') {
									DbgPrint("[-] @_wmliang_\n");
								}
							}
						}
					}
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		DbgPrint("[-] Exception Code: 0x%X\n", Status);
	}

	return Status;
}

NTSTATUS DemoIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
	SIZE_T Size = 0;
	PVOID UserBuffer = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UNREFERENCED_PARAMETER(Irp);
	PAGED_CODE();

	UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (UserBuffer) {
		Status = TriggerDemo(UserBuffer, Size);
	}

	return Status;
}

#pragma auto_inline()
