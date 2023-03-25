#include "dbutil.h"

DBUTIL::DBUTIL() {
	// Constructor for Memory Manager
	HANDLE hDevice = CreateFileW(wszDrive, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD errorCode = GetLastError();
	if (errorCode != 0) {
		printf("Error code %lu\n", errorCode);
		printf("[!] Could not create a handle to driver. Aborting.\n");
	}
	DBUTIL::DriverHandle = hDevice;
}

DBUTIL::~DBUTIL() {
	// Close Handle to driver. If it was obtained in constructor
	if (DBUTIL::DriverHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(DBUTIL::DriverHandle);
		DBUTIL::DriverHandle = INVALID_HANDLE_VALUE;
		printf("[!] Handle to driver closed!\n");
	}
	printf("[!] Close but INVALID_HANDLE_VALUE?\n");

}

BOOL DBUTIL::VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, 0x8);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, 0x8);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, 0x8);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_VIRTUAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x18], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL DBUTIL::VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x18], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(DBUTIL::DriverHandle, IOCTL_VIRTUAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

DWORD64 DBUTIL::GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		//printf("[DriverName] {%s} == {%s}\n", lpFileName, name.c_str());
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			//Logger::InfoHex("Found Image Base for " + name, imageBase);
			//printf("Found Image Base for %s 0x%lu\n", name.c_str(), imageBase);
			break;
		}
	}
	return imageBase;
}
