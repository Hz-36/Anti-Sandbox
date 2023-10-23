// HUNT3R_ANTI_DEBUG
// 
//------------------------------------------------------------------------------------------INCLUDES
#include "ANTI_DEBUG.h"
#include <Shlwapi.h>
#include <winternl.h>
#include "PROCESS_EXPLORER_DETAILS.h"


//------------------------------------------------------------------------------------------CHECK CPU
bool xCheckCPUCores() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED); // Initialize COM
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code: " << hres << std::endl;
        return false;
    }

    hres = CoInitializeSecurity( // Initialize security
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code: " << hres << std::endl;
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code: " << hres << std::endl;
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hres)) {
        std::cerr << "Failed to connect to WMI. Error code: " << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to set proxy blanket. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "Failed to execute WQL query. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    ULONG uReturn = 0;
    IWbemClassObject* pclsObj = NULL;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"NumberOfCores", 0, &vtProp, 0, 0);
        if (FAILED(hr)) {
            pclsObj->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        int numCores = vtProp.intVal;
        VariantClear(&vtProp);
        pclsObj->Release();

        if (numCores < 2) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return true;
}


//------------------------------------------------------------------------------------------CHECK RAM
bool xCheckRAM() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    return (RAMMB >= 2048); // MIN 2048 MB RAM
}


//------------------------------------------------------------------------------------------CHECK HDD
bool xCheckHDD() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return false;
    }

    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    CloseHandle(hDevice);

    return (diskSizeGB >= 66);
}


//------------------------------------------------------------------------------------------CHECK DISK NAME -> VBOX
bool xCheckVirtualBox() {
    HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
    if (hDeviceInfo == INVALID_HANDLE_VALUE) {
        return false;
    }

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiEnumDeviceInfo(hDeviceInfo, 0, &deviceInfoData)) {
        SetupDiDestroyDeviceInfoList(hDeviceInfo);
        return false;
    }

    DWORD propertyBufferSize;
    if (!SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize)) {
        SetupDiDestroyDeviceInfoList(hDeviceInfo);
        return false;
    }

    PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);
    if (!HDDName) {
        SetupDiDestroyDeviceInfoList(hDeviceInfo);
        return false;
    }

    if (!SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL)) {
        HeapFree(GetProcessHeap(), 0, HDDName);
        SetupDiDestroyDeviceInfoList(hDeviceInfo);
        return false;
    }

    CharUpperW(HDDName);
    bool isVirtualBox = (wcsstr(HDDName, L"VBOX") != nullptr);

    HeapFree(GetProcessHeap(), 0, HDDName);
    SetupDiDestroyDeviceInfoList(hDeviceInfo);

    return isVirtualBox; // Return TRUE if the Disk name contains "VBOX"
}


//------------------------------------------------------------------------------------------CHECK MAC 
bool xCheckMAC() {
    std::vector<std::string> macPrefixes = {
        "00:03:FF", "00:50:56", "00:0C:29", "00:05:69",
        "00:1C:42", "00:16:3E", "00:0F:4B", "08:00:27"
    };

    IP_ADAPTER_INFO adapterInfo[16]; // Check MAC 
    DWORD bufferSize = sizeof(adapterInfo);
    DWORD result = GetAdaptersInfo(adapterInfo, &bufferSize);

    if (result == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            std::string macAddress;
            for (int i = 0; i < adapter->AddressLength; ++i) {
                char hex[3];
                sprintf_s(hex, "%02X", adapter->Address[i]);
                macAddress += hex;
                if (i < adapter->AddressLength - 1) {
                    macAddress += "-";
                }
            }

            std::string firstPart = macAddress.substr(0, 8); // Compare with macPrefixes
            if (std::find(macPrefixes.begin(), macPrefixes.end(), firstPart) != macPrefixes.end()) {
                return false; // MAC found
            }

            adapter = adapter->Next;
        }
    }

    return true; // MAC not found
}


//------------------------------------------------------------------------------------------CHECK CPU ID
/*
bool xCheckCPUID() {
    std::vector<std::string> forbiddenCPUs = { "Microsoft Hv", "VMwareVMware" };

    std::string cpuIdString;
    int cpuInfo[4] = { 0 };

    // Prüfe, ob CPUID-Unterstützung vorhanden ist
    __asm {
        xor eax, eax
        cpuid
        mov dword ptr[cpuInfo + 0], ebx
        mov dword ptr[cpuInfo + 4], edx
        mov dword ptr[cpuInfo + 8], ecx
    }

    int maxFunction = cpuInfo[0];
    if (maxFunction < 1) {
        // CPUID wird nicht unterstützt
        return true;
    }

    // Rufe CPUID-Informationen ab
    for (int i = 0x00000000; i <= maxFunction; ++i) {
        __asm {
            mov eax, i
            cpuid
            mov dword ptr[cpuInfo + 0], eax
            mov dword ptr[cpuInfo + 4], ebx
            mov dword ptr[cpuInfo + 8], edx
            mov dword ptr[cpuInfo + 12], ecx
        }

        cpuIdString += std::to_string(cpuInfo[0]);
        cpuIdString += std::to_string(cpuInfo[1]);
        cpuIdString += std::to_string(cpuInfo[2]);
        cpuIdString += std::to_string(cpuInfo[3]);
    }

    // Vergleiche CPUID mit verbotenen Werten
    for (const std::string& forbidden : forbiddenCPUs) {
        if (cpuIdString.find(forbidden) != std::string::npos) {
            return false; // CPUID gefunden, Rückgabe von false
        }
    }

    return true; // CPUID nicht gefunden, Rückgabe von true
}
*/

//------------------------------------------------------------------------------------------CHECK ADMIN
bool xUAdmin() {
    BOOL bAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) { // Get Current Process Token
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY; // Define SID -> Administrator
        PSID pAdminSid = NULL;
        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
            if (CheckTokenMembership(NULL, pAdminSid, &bAdmin)) { // Checking Privileges
                // TRUE -> Administrator
            }
            FreeSid(pAdminSid);
        }
        CloseHandle(hToken);
    }

    return bAdmin != 0; // Convert BOOL -> bo ol
}


//------------------------------------------------------------------------------------------CHECK DOMAIN
bool xCheckDomain() {
    bool ret = false;
    DWORD dwLevel = 100;
    LPWKSTA_INFO_100 pBuf = NULL;
    NET_API_STATUS nStatus;

    nStatus = NetWkstaGetInfo(NULL, dwLevel, (LPBYTE*)&pBuf);
    if (nStatus == NERR_Success) {
        char response[512];
        wcstombs(response, pBuf->wki100_langroup, 500); 
        char workgroup[] = "WORKGROUP";
        if (strcmp(response, workgroup) != 0) {
            ret = true;
        }
        else {
            ret = false;
        }
    }

    if (pBuf != NULL) { // Allocate Memory -> pBuf
        NetApiBufferFree(pBuf);
    }

    return ret;
}


//------------------------------------------------------------------------------------------CHECK FOR BLACKLISTED FILE PATHS
bool xCheckPath() {
    HKEY hkey;
    if (RegOpenKeyA(HKEY_CLASSES_ROOT, "\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS ||
        RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", &hkey) == ERROR_SUCCESS) {
        return false;
    }

    return true;
}


//------------------------------------------------------------------------------------------CHECK FOR RUNNING BLACKLISTED PROCESSES
bool xCheckProcActive() {
    const char* list[4] = { "VBoxService.exe", "VBoxTray.exe", "vmware.exe", "vmtoolsd.exe" };
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return true; // Failed To Create Snapshot
    }

    BOOL bResult = Process32First(hProcessSnap, &pe32);
    while (bResult) {
        char sz_Name[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, sz_Name, sizeof(sz_Name), NULL, NULL);
        for (int i = 0; i < 4; ++i) {
            if (strcmp(sz_Name, list[i]) == 0) {
                CloseHandle(hProcessSnap);
                return false; // Process load
            }
        }
        bResult = Process32Next(hProcessSnap, &pe32);
    }

    CloseHandle(hProcessSnap);
    return true; // Process not found
}


//------------------------------------------------------------------------------------------CHECK FOR BLACKLISTED SERVICES
bool xCheckService() {
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == nullptr) {
        // Fehler beim Öffnen des Dienstmanagers
        return true; // Service Control System not available -> TRUE
    }

    DWORD dwBytesNeeded, dwServicesReturned, dwResumeHandle = 0;
    EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE | SERVICE_INACTIVE, nullptr, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, nullptr);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSCManager); 
        return true; // No Blacklisted Services found / Error -> TRUE
    }

    std::vector<BYTE> buffer(dwBytesNeeded);
    ENUM_SERVICE_STATUS_PROCESS* pServiceInfo = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buffer.data());
    EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE | SERVICE_INACTIVE, reinterpret_cast<LPBYTE>(pServiceInfo), dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, nullptr);

    bool serviceFound = false;
    for (DWORD i = 0; i < dwServicesReturned; ++i) {
        if (lstrcmpi(pServiceInfo[i].lpServiceName, L"VMwareHostOpen.exe") == 0 || 
            lstrcmpi(pServiceInfo[i].lpServiceName, L"VirtualBox Guest Additions") == 0) { // Checking for Blacklisted Services 
            serviceFound = true;
            break;
        }
    }

    CloseServiceHandle(hSCManager);
    return !serviceFound;
}


//------------------------------------------------------------------------------------------CHECK WINE
bool xWineActive() {
    const char* functionName = "wine_get_host_version";
    HMODULE hModule = LoadLibraryA("ntdll.dll");
    if (hModule) {
        FARPROC funcAddress = GetProcAddress(hModule, functionName);
        if (funcAddress) {
            int result = ((int(*)(void))funcAddress)();
            FreeLibrary(hModule);
            return (result != 2);
        }
        FreeLibrary(hModule);
    }
    return true;
}


//------------------------------------------------------------------------------------------CHECK UP TIME
bool xCheckUpTime(DWORD minutes) {
    DWORD uptime = GetTickCount64(); // System runtime in ms
    DWORD minutesRunning = uptime / (1000 * 60); // Calc -> Minutes

    return minutesRunning >= minutes;
}


//------------------------------------------------------------------------------------------MANAGE WMI INFO
BOOL xManageWMIInfo(std::string& result, std::string table, std::wstring wcol) {
    BOOL bRet = FALSE;
    HRESULT hres = CoInitialize(0);

    if (SUCCEEDED(hres)) {
        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc
        );

        if (SUCCEEDED(hres)) {
            IWbemServices* pSvc = NULL;
            hres = pLoc->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"),
                NULL,
                NULL,
                0,
                NULL,
                0,
                0,
                &pSvc
            );

            if (SUCCEEDED(hres)) {
                hres = CoSetProxyBlanket(
                    pSvc,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    NULL,
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    NULL,
                    EOAC_NONE
                );

                if (SUCCEEDED(hres)) {
                    IEnumWbemClassObject* pEnumerator = NULL;
                    std::wstring select = L"SELECT * FROM " + std::wstring(table.begin(), table.end());
                    hres = pSvc->ExecQuery(
                        bstr_t("WQL"),
                        bstr_t(select.c_str()),
                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                        NULL,
                        &pEnumerator
                    );

                    if (SUCCEEDED(hres)) {
                        ULONG uReturn = 0;
                        IWbemClassObject* pclsObj;
                        while (pEnumerator) {
                            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                            if (0 == uReturn) {
                                break;
                            }

                            VARIANT vtProp;
                            VariantInit(&vtProp);
                            hr = pclsObj->Get(wcol.c_str(), 0, &vtProp, 0, 0);
                            if (!FAILED(hr)) {
                                CW2A tmpstr(vtProp.bstrVal);
                                result = tmpstr;
                                bRet = TRUE;
                            }
                            VariantClear(&vtProp);
                            pclsObj->Release();
                        }
                        pEnumerator->Release();
                    }
                }
                pSvc->Release();
            }
            pLoc->Release();
        }
        CoUninitialize();
    }

    return bRet;
}


//------------------------------------------------------------------------------------------CHECK BLACKLISTED DRIVE NAMES
bool xCheckDriveName() {
    std::string ret;

    if (!xManageWMIInfo(ret, "Win32_BaseBoard", L"SerialNumber")) {
        return false;
    }
    if (ret == "None") {
        return false;
    }

    if (!xManageWMIInfo(ret, "Win32_DiskDrive", L"Caption")) {
        return false;
    }
    if (ret.find("VMware") != std::string::npos || ret.find("VBOX") != std::string::npos || ret.find("Virtual HD") != std::string::npos) {
        return false;
    }

    if (!xManageWMIInfo(ret, "Win32_computersystem", L"Model")) {
        return false;
    }
    if (ret.find("VMware") != std::string::npos || ret.find("VirtualBox") != std::string::npos || ret.find("Virtual Machine") != std::string::npos) {
        return false;
    }

    return true;
}


//------------------------------------------------------------------------------------------CHECK LOADED DLLS
bool xCheckLoadedDLL() {
    const TCHAR* yBlacklistedDLLS[] = {
        _T("avghookx.dll"),     // AVG
        _T("avghooka.dll"),     // AVG
        _T("snxhk.dll"),        // Avast
        _T("sbiedll.dll"),      // Sandboxie
        _T("dbghelp.dll"),      // WindBG
        _T("api_log.dll"),      // iDefense Lab
        _T("dir_watch.dll"),    // iDefense Lab
        _T("pstorec.dll"),      // SunBelt Sandbox
        _T("vmcheck.dll"),      // Virtual PC
        _T("wpespy.dll"),       // WPE Pro
        _T("cmdvrt64.dll"),     // Comodo Container
        _T("cmdvrt32.dll"),     // Comodo Container
    };

    WORD dwlength = sizeof(yBlacklistedDLLS) / sizeof(yBlacklistedDLLS[0]);
    for (int i = 0; i < dwlength; i++) {
        HMODULE hDll = GetModuleHandle(yBlacklistedDLLS[i]); // Check if Process loaded Modules Contains any Blacklisted DLL
        if (hDll != NULL) {
            return false; // Found Blacklisted DLL -> FALSE
        }
    }

    return true; // No Blacklisted DLL Found -> TRUE
}


//------------------------------------------------------------------------------------------CHECK FOR BLACKLISTED FILENAMES LOADED FROM PROCESS
bool xHexString(const TCHAR* str) { 
    for (int i = 0; str[i] != '\0'; i++) {
        TCHAR ch = str[i];
        if (!((ch >= _T('0') && ch <= _T('9')) || (ch >= _T('a') && ch <= _T('f')) || (ch >= _T('A') && ch <= _T('F')))) {
            return false;
        }
    }
    return true;
}

bool xCheckKnownFilename() {
    const TCHAR* yBlacklistedFilenames[] = {
        _T("sample.exe"),
        _T("bot.exe"),
        _T("sandbox.exe"),
        _T("malware.exe"),
        _T("test.exe"),
        _T("klavme.exe"),
        _T("myapp.exe"),
        _T("testapp.exe"),
    };

    TCHAR szModuleFileName[MAX_PATH];
    if (GetModuleFileName(NULL, szModuleFileName, MAX_PATH) == 0) {
        return false; // Error -> Cannot Retrieve Module Filename
    }

    WCHAR* szFileName = PathFindFileName(szModuleFileName); // Get Filename From Path

    WORD dwlength = sizeof(yBlacklistedFilenames) / sizeof(yBlacklistedFilenames[0]);
    for (int i = 0; i < dwlength; i++) {
        if (StrCmpIW(yBlacklistedFilenames[i], szFileName) == 0) { // Checking for matching Blacklisted Filenames
            return false; // Found Blacklisted Filename -> FALSE
        }
    }

    PathRemoveExtension(szFileName); // Checking for known hashes
    if ((wcslen(szFileName) == 32 || wcslen(szFileName) == 40 || wcslen(szFileName) == 64) && xHexString(szFileName)) {
        return false; // Filename Looks Like Hash -> FALSE
    }

    return true; // No Blacklisted Filename or Hash Found -> TRUE
}


//------------------------------------------------------------------------------------------
bool xCheckSandboxFiles(const WCHAR* yBlacklistedFilePath) {
    DWORD yBlacklistAtributes = GetFileAttributes(yBlacklistedFilePath);
    if (yBlacklistAtributes == INVALID_FILE_ATTRIBUTES || (yBlacklistAtributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return false;
    }

    ULONGLONG blacklistedSize = std::filesystem::file_size(yBlacklistedFilePath);
    ULONGLONG kernel32Size = std::filesystem::file_size(L"C:\\Windows\\System32\\kernel32.dll");

    return (blacklistedSize != kernel32Size);
}

bool xCheckFiles() {  // Check for Blacklisted Sandbox Files
    const WCHAR* filePaths[] = {
        L"C:\\take_screenshot.ps1",
        L"C:\\analysis",
        L"C:\\sample",
        L"C:\\sandbox",
        L"C:\\malware",
        L"C:\\virus",
        L"C:\Program Files\\oracle\virtualbox guest additions\\",
        L"C:\Program Files\\VMware\\",
        L"C:\loaddll.exe",
        L"C:\\email.doc",
        L"C:\\email.htm",
        L"C:\\123\\email.doc",
        L"C:\\123\\email.docx",
        L"C:\\a\\foobar.bmp",
        L"C:\\a\\foobar.doc",
        L"C:\\a\\foobar.gif",
        L"C:\\symbols\\aagmmc.pdb",
        L"C:\\windows\\system32\\drivers\\prleth.sys",
        L"C:\\windows\\system32\\drivers\\prlfs.sys",
        L"C:\\windows\\system32\\drivers\\prlmouse.sys",
        L"C:\\windows\\system32\\drivers\\prlvideo.sys",
        L"C:\\windows\\system32\\drivers\\prltime.sys",
        L"C:\\windows\\system32\\drivers\\prl_pv32.sys",
        L"C:\\windows\\system32\\drivers\\prl_paravirt_32.sys",
        L"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        L"C:\\windows\\system32\\drivers\\VBoxSF.sys",
        L"C:\\windows\\system32\\drivers\\VBoxVideo.sys",
        L"C:\\windows\\system32\\vboxdisp.dll",
        L"C:\\windows\\system32\\vboxhook.dll",
        L"C:\\windows\\system32\\vboxmrxnp.dll",
        L"C:\\windows\\system32\\vboxogl.dll",
        L"C:\\windows\\system32\\vboxoglarrayspu.dll",
        L"C:\\windows\\system32\\vboxoglcrutil.dll",
        L"C:\\windows\\system32\\vboxoglerrorspu.dll",
        L"C:\\windows\\system32\\vboxoglfeedbackspu.dll",
        L"C:\\windows\\system32\\vboxoglpackspu.dll",
        L"C:\\windows\\system32\\vboxoglpassthroughspu.dll",
        L"C:\\windows\\system32\\vboxservice.exe",
        L"C:\\windows\\system32\\vboxtray.exe",
        L"C:\\windows\\system32\\VBoxControl.exe",
        L"C:\\windows\\system32\\drivers\\vmsrvc.sys",
        L"C:\\windows\\system32\\drivers\\vpc-s3.sys",
        L"C:\\windows\\system32\\drivers\\vmmouse.sys",
        //L"C:\\windows\\system32\\drivers\\vmnet.sys",
        L"C:\\windows\\system32\\drivers\\vmxnet.sys",
        L"C:\\windows\\system32\\drivers\\vmhgfs.sys",
        //L"C:\\windows\\system32\\drivers\\vmx86.sys",
        L"C:\\windows\\system32\\drivers\\hgfs.sys"
    };

    for (int i = 0; i < sizeof(filePaths) / sizeof(filePaths[0]); ++i) {
        if (xCheckSandboxFiles(filePaths[i])) {
            return false;
        }
    }

    return true;
}


//------------------------------------------------------------------------------------------CHECK FOR BLACKLISTED REGISTRY KEYS -> UNSAFE
bool xContainsSubstring(const WCHAR* string, const WCHAR* ySubString) {
    return (wcsstr(string, ySubString) != nullptr);
}

bool xCheckRegKey() {
    const WCHAR* ySearchStrings[] = {
        L"andbox",
        //L"Hyper",
        L"ualMac",
        L"Parameters",
        //L"vmic",
        L"VEN_1AB8*",
        L"VEN_5333*",
        L"VEN_15AD*",
        L"VEN_80EE*",
        L"SbieDrv",
        L"VBox",
        L"VBOX__",
        L"ualBox Guest Additi",
        L"vpcbus",
        L"vpc-s3",
        L"vpcuhub",
        L"msvmmouf",
        //L"VMware",
        L"vmdebug",
        L"vmmouse",
        L"VMTools",
        L"VMMEMCTL",
        L"vmware",
        //L"vmci",
        //L"vmx86",
        L"CdRomNECVMWar_VM",
        L"DiskVMware_Vi",
        L"xen"
    };

    const WCHAR* ySearchPaths[] = {
        L"SYSTEM\\ControlSet001\\Services\\",
        L"HKLM\\SYSTEM\\ControlSet001\\Services\\",
        L"HKCU\\SOFTWARE\\",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\",
        L"HKLM\\SOFTWARE\\VMware, Inc.\\",
        L"HKCU\\SOFTWARE\\VMware, Inc.\\",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\",
        L"HKLM\\SOFTWARE\\Oracle\\",
        L"HKLM\\Software\\Classes\\Folder\\shell\\",
        L"HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\",
        L"HKLM\\SOFTWARE\\Microsoft\\",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\",
        L"HKLM\\HARDWARE\\ACPI\\DSDT\\",
        L"HKLM\\HARDWARE\\ACPI\\FADT\\",
        L"HKLM\\HARDWARE\\ACPI\\RSDT\\",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
        L"HKLM\HARDWARE\Description\System\\"
    };

    for (int i = 0; i < sizeof(ySearchPaths) / sizeof(ySearchPaths[0]); ++i) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ySearchPaths[i], 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            continue; // Failed To Open Reg Key -> Next Path
        }

        WCHAR keyName[256];
        DWORD index = 0;
        DWORD resultLength;

        while (true) {
            resultLength = sizeof(keyName) / sizeof(WCHAR);
            if (RegEnumKeyEx(hKey, index, keyName, &resultLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                if (GetLastError() == ERROR_NO_MORE_ITEMS) { 
                    RegCloseKey(hKey); // Close Reg Key -> BREAK
                    break;
                }
                else {
                    RegCloseKey(hKey); // Error occurred -> TRUE
                    return true;
                }
            }

            for (int j = 0; j < sizeof(ySearchStrings) / sizeof(ySearchStrings[0]); ++j) {
                if (xContainsSubstring(keyName, ySearchStrings[j])) {
                    RegCloseKey(hKey);
                    return false; // Match Found -> FALSE
                }
            }

            index++;
        }

        RegCloseKey(hKey);
    }

    return true;
}


//------------------------------------------------------------------------------------------CHECK BLACKLISTED REGISTRY KEY STRINGS
bool xCheckRegKeyString() {
    const std::vector<std::wstring> searchStrings = {
        L"VBox",
        L"VMBox",
        L"QEMU",
        L"VIRTUAL",
        L"VIRTUALBOX",
        L"VMWARE",
        L"Xen"
    };

    const std::vector<std::wstring> searchPaths = {
        L"HARDWARE\\Description\\System",
        L"HARDWARE\\Description\\System\\BIOS",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 3\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
        L"SYSTEM\\ControlSet002\\Services\\Disk\\Enum",
        L"SYSTEM\\ControlSet003\\Services\\Disk\\Enum",
        L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
        L"SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video",
        L"SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\0000",
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000",
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings"
    };

    for (const auto& path : searchPaths) {
        HKEY hKey;
        LONG ret;

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t value[1024];
            DWORD size = sizeof(value);

            for (const auto& originalSearchString : searchStrings) {
                auto searchString = originalSearchString; 

                for (size_t i = 0; i < searchString.length(); i++) { 
                    searchString[i] = towupper(searchString[i]);
                }

                if (RegQueryValueEx(hKey, searchString.c_str(), NULL, NULL, (BYTE*)value, &size) == ERROR_SUCCESS) {
                    for (size_t i = 0; i < size / sizeof(wchar_t); i++) { 
                        value[i] = towupper(value[i]);
                    }

                    if (wcsstr(value, searchString.c_str()) != NULL) {
                        RegCloseKey(hKey);
                        return false;
                    }
                }

                size = sizeof(value);
            }

            RegCloseKey(hKey);
        }
    }

    return true;
}
