#include "header.h"

void process(LPTSTR name) {
	HKEY hKey;
	DWORD rc = RegLoadAppKey(name, &hKey, KEY_ALL_ACCESS, 0, 0);
	if (rc) {
		LOG(_T("Unable to load the hive with RegLoadAppKey(), rc = %d\n"), rc);
		_tprintf(_T("Unable to load the hive with RegLoadAppKey(), rc = %d\n"), rc);
	}
	else {
		RegCloseKey(hKey);
		LOG(_T("Done\n"));
		_tprintf(_T("Done\n"));
	}
}

INT _tmain(INT argc, TCHAR* argv[]) {

#ifndef UNICODE
	LOG(_T("Have to compile with unicode\n"));
	return 0;
#endif

	INIT();

	if (argc != 2) PFATAL(_T("test_hive.exe [.hiv]"));

	while (PERSISTENT_COUNT--) {
		PRE();
		process(argv[1]);
		POST();
	}
}
