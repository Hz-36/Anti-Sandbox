// HUNT3R_ANTI_DEBUG HEADER
// 
//------------------------------------------------------------------------------------------COMPILER
#define ANTI_DEBUG
#ifdef ANTI_DEBUG

#define _CRT_SECURE_NO_WARNINGS

//------------------------------------------------------------------------------------------INCLUDES
#include <iostream>
#include <vector>
#include <Windows.h>
#include <SetupAPI.h>
#include <iomanip>
#include <comdef.h> // For _com_error
#include <sstream>
#include <initguid.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <Lmwksta.h>
#include <WinSvc.h>
#include <lm.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <algorithm>
#include <iphlpapi.h>
#include <TlHelp32.h>
#include <filesystem>
#include <atlbase.h>
#include <atlconv.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "comsuppw.lib")


DEFINE_GUID(GUID_DEVCLASS_DISKDRIVE, 0x4d36e967, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18);


//------------------------------------------------------------------------------------------> CHECK CPU
bool xCheckCPUCores();


//------------------------------------------------------------------------------------------> CHECK RAM
bool xCheckRAM();


//------------------------------------------------------------------------------------------> CHECK HDD
bool xCheckHDD();


//------------------------------------------------------------------------------------------> CHECK VM
bool xCheckVirtualBox();


//------------------------------------------------------------------------------------------> CHECK MAC 
bool xCheckMAC();


//------------------------------------------------------------------------------------------> CHECK CPU ID
//bool xCheckCPUID();


//------------------------------------------------------------------------------------------> CHECK ADMIN
bool xUAdmin();


//------------------------------------------------------------------------------------------> CHECK DOMAIN
bool xCheckDomain();


//------------------------------------------------------------------------------------------> CHECK FOR BLACKLISTED FILE PATHS
bool xCheckPath();


//------------------------------------------------------------------------------------------> CHECK FOR RUNNING BLACKLISTED PROCESSES
bool xCheckProcActive();


//------------------------------------------------------------------------------------------> CHECK FOR BLACKLISTED SERVICES
bool xCheckService();


//------------------------------------------------------------------------------------------> CHECK FOR WINE
bool xWineActive();


//------------------------------------------------------------------------------------------> CHECK UPTIME
bool xCheckUpTime(DWORD minutes);


//------------------------------------------------------------------------------------------> MANAGE WMIInfo
BOOL xManageWMIInfo(std::string& result, std::string table, std::wstring wcol);


//------------------------------------------------------------------------------------------> CHECK DRIVE NAME
bool xCheckDriveName();


//------------------------------------------------------------------------------------------> CHECK LOADED DLLS
bool xCheckLoadedDLL();


//------------------------------------------------------------------------------------------> CHECK FOR BLACKLISTED FILENAMES LOADED FROM PROCESS
bool xCheckKnownFilename();


//------------------------------------------------------------------------------------------> CHECK SANDBOX FILES
bool xCheckSandboxFiles(const WCHAR* blacklistedFilePath);


//------------------------------------------------------------------------------------------> CHECK FILES
bool xCheckFiles();


//------------------------------------------------------------------------------------------> CHECK 
bool xContainsSubstring(const WCHAR* string, const WCHAR* ySubString);


//------------------------------------------------------------------------------------------> CHECK REGISTRY KEYS
bool xCheckRegKey();


//------------------------------------------------------------------------------------------> CHECK 
bool xCheckRegKeyString();


//------------------------------------------------------------------------------------------> CHECK 



//------------------------------------------------------------------------------------------> CHECK 





#endif ANTI_DEBUG