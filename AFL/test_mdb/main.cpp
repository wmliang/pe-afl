#include "header.h"
#include <Shlwapi.h>

inline void TESTHR(HRESULT x) { if FAILED(x) _com_issue_error(x); };

void PrintProviderError(_ConnectionPtr pConnection) {
	// Print Provider Errors from Connection object.  
	// pErr is a record object in the Connection's Error collection.  
	ErrorPtr  pErr = NULL;

	if ((pConnection->Errors->Count) > 0) {
		long nCount = pConnection->Errors->Count;

		// Collection ranges from 0 to nCount -1.  
		for (long i = 0; i < nCount; i++) {
			pErr = pConnection->Errors->GetItem(i);
			_tprintf(_T("Error number: %x\t%s\n"), pErr->Number, (LPTSTR)pErr->Description);
		}
	}
}

void PrintComError(_com_error &e) {  
   _bstr_t bstrSource(e.Source());  
   _bstr_t bstrDescription(e.Description());  

   // Print Com errors.    
   _tprintf(_T("Error\n"));
   _tprintf(_T("\tCode = %08lx\n"), e.Error());
   _tprintf(_T("\tCode meaning = %s\n"), e.ErrorMessage());  
   _tprintf(_T("\tSource = %s\n"), (LPTSTR)bstrSource);
   _tprintf(_T("\tDescription = %s\n"), (LPTSTR)bstrDescription);
}  

void JetConnection(TCHAR *db_path) {
	HRESULT hr = S_OK;
	_ConnectionPtr m_pConnection = NULL;

	CHAR path[MAX_PATH] = { 0 };
	wcstombs(path, db_path, MAX_PATH);

	CHAR data_src[0x1000];
	sprintf(data_src, "Provider='Microsoft.JET.OLEDB.4.0';Data source = %s", path);

	try {
		TESTHR(m_pConnection.CreateInstance(__uuidof (Connection)));
		m_pConnection->Open(data_src, "", "", NULL);
		_tprintf(_T("OK\n"));
	}
	catch (_com_error &e) {
		PrintProviderError(m_pConnection);
		PrintComError(e);
		_tprintf(_T("NOT OK\n"));
	}

	if (m_pConnection) {
		if (m_pConnection->State == adStateOpen) m_pConnection->Close();
	}
	
}

void JET_PROCESS(TCHAR *db_path) {
//	if (FAILED(::CoInitialize(NULL)))
//		return;

	JetConnection(db_path);

//	::CoUninitialize();
}

INT _tmain(INT argc, TCHAR* argv[]) {

#ifndef UNICODE
	_tprintf(_T("Have to compile with unicode, due to RtlCompareUnicodeString in helper.sys\n"));
	return 0;
#endif

	INIT();
	
	if (argc != 2) PFATAL(_T("test_mdb.exe [.mdb]"));

	TCHAR fullFilename[MAX_PATH];
	if (!GetFullPathName(argv[1], MAX_PATH, fullFilename, nullptr)) {
		PFATAL(_T("GetFullPathName failed\n"));
	}
	if (!PathFileExists(fullFilename)) PFATAL(_T("test_mdb.exe [.mdb]"));

	if (FAILED(::CoInitialize(NULL)))
		return EOF;
	JetConnection(fullFilename);

	while (PERSISTENT_COUNT--) {
		PRE();
		JET_PROCESS(fullFilename);
		POST();
	}

	::CoUninitialize();
}