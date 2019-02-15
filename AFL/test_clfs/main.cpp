#include "header.h"
#include <Ktmw32.h>

void process(LPTSTR name) {

	HANDLE rc = CreateTransactionManager(0, name, 0, 0);

	if (rc == INVALID_HANDLE_VALUE) {
		_tprintf(_T("GetLastError: %d\n"), GetLastError());
	}
	else {
		_tprintf(_T("Success\n"));
	}

	RecoverTransactionManager(rc);
	CloseHandle(rc);
}

INT _tmain(INT argc, TCHAR* argv[]) {
	//SetStdHandle(STD_OUTPUT_HANDLE, CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0));
	//SetStdHandle(STD_ERROR_HANDLE, CreateFile(_T("CONERR$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0));

#ifndef UNICODE
	LOG(_T("Have to compile with unicode\n"));
	return 0;
#endif

	TCHAR *pp = _tcsstr(argv[argc - 1], _T(".blf"));
	if (pp && pp == (argv[argc-1] + _tcslen(argv[argc - 1]) - _tcslen(_T(".blf")))) {
		*pp = 0;
	}

	INIT();
	atexit(FINI);
	
	if (argc != 2) PFATAL(_T("test_clfs.exe [.blf]\nRemember do not add .blf extension"));

	while (PERSISTENT_COUNT--) {
		PRE();
		process(argv[1]);
		POST();
	}
}
