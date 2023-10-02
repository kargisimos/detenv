#include "detenv.h"

//comment out next line to disable debugging
#define DEBUG 
#ifdef DEBUG
#define DEBUG_SUCCESS(...) do { \
    printf(__VA_ARGS__); \
} while (0)

#define DEBUG_FAIL(...) do { \
    printf(__VA_ARGS__); \
} while (0)
#else
#define DEBUG_SUCCESS(...) do {} while (0)

#define DEBUG_FAIL(...) do {} while (0)
#endif

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

BOOL ALL_CHECKS_OK = TRUE;


///////////////////////////////////////////////////////////////////////////////////////////////

//									call all checks

///////////////////////////////////////////////////////////////////////////////////////////////

BOOL detenv_all_checks() {
	DEBUG_SUCCESS("----------------------------------------------------\n");
	DEBUG_SUCCESS("[+]Generic OS queries\n");
	DEBUG_SUCCESS("----------------------------------------------------\n");
	check_username();
	check_hostname();
	check_RAM();
	check_no_processors();
	check_no_monitors();
	check_uptime();
	check_harddisk_size();
	check_audio_device();
	check_mouse();
	check_sleep_skipping();
	DEBUG_SUCCESS("----------------------------------------------------\n");
	DEBUG_SUCCESS("[+]Networking queries\n");
	DEBUG_SUCCESS("----------------------------------------------------\n");
	check_internet();
	check_MAC();
	check_shares();
	DEBUG_SUCCESS("----------------------------------------------------\n");
	DEBUG_SUCCESS("[+]Filesystem queries\n");
	DEBUG_SUCCESS("----------------------------------------------------\n");
	check_files();
	check_directories();
	check_path();
	DEBUG_SUCCESS("----------------------------------------------------\n");
	DEBUG_SUCCESS("[+]Registry queries\n");
	DEBUG_SUCCESS("----------------------------------------------------\n");
	check_regpaths();
	DEBUG_SUCCESS("----------------------------------------------------\n");
	DEBUG_SUCCESS("[+]Process queries\n");
	DEBUG_SUCCESS("----------------------------------------------------\n");
	check_running_processes();

	return ALL_CHECKS_OK;
}



///////////////////////////////////////////////////////////////////////////////////////////////

//                                  generic OS queries

///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific username
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_username() {

	char* usernames[] = {
		"admin",
		"andy",
		"honey",
		"john",
		"john doe",
		"malnetvm",
		"maltest",
		"malware",
		"roo",
		"sandbox",
		"snort",
		"tequilaboomboom",
		"test",
		"virus",
		"virusclone",
		"wilbert",
		"nepenthes",
		"currentuser",
		"username",
		"user",
		"vmware"
	};


	DWORD size = UNLEN + 1; // Maximum length of a username
	char username[UNLEN + 1];
	BOOL get_username = GetUserNameA(username, &size);
	for (int i = 0; i < sizeof(usernames) / sizeof(usernames[0]); i++) {
		if (strcmp(username, usernames[i]) == 0) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Username check failed. Username: %s\n" ANSI_COLOR_RESET, usernames[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Username check success.\n" ANSI_COLOR_RESET);
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific hostname
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_hostname() {

	char* hostnames[] = {
		"sandbox",
		"sandboxdetect",
		"john - pc",
		"mueller - pc",
		"virus",
		"malware",
		"hanspeter - pc",
		"malwaretest",
		"fortinet"
	};

	DWORD size = MAX_COMPUTERNAME_LENGTH + 1; // Maximum length of a computer name
	char hostname[MAX_COMPUTERNAME_LENGTH + 1];
	BOOL get_computername = GetComputerNameA(hostname, &size);
	for (int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]); i++) {
		if (strcmp(hostname, hostnames[i]) == 0) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Hostname check failed. Hostname: %s\n ANSI_COLOR_RESET", hostnames[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Hostname check success.\n" ANSI_COLOR_RESET);
}

///////////////////////////////////////////////////////////////////////////////////////////////
//convert bytes to gigabytes
///////////////////////////////////////////////////////////////////////////////////////////////

double bytes_to_gb(ULONGLONG bytes) {
	const double gb = 1024.0 * 1024.0 * 1024.0;
	return (double)bytes / gb;
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check if the total RAM is lower than 4 GB
///////////////////////////////////////////////////////////////////////////////////////////////

void check_RAM() {
	MEMORYSTATUSEX status;
	status.dwLength = sizeof(status);
	if (GlobalMemoryStatusEx(&status)) {
		DOUBLE RAM = bytes_to_gb(status.ullTotalPhys);
		if (RAM >= 4.0) {
			DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]RAM check success.\n" ANSI_COLOR_RESET);
		}
		else {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]RAM check failed. Total physical memory: %.2f GB\n" ANSI_COLOR_RESET, RAM);
			ALL_CHECKS_OK = FALSE;
		}
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to get memory status. Error code: %lu\n" ANSI_COLOR_RESET, GetLastError());
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check number of processors less than 2
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_no_processors() {
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	if (info.dwNumberOfProcessors < 2) {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Number of processors check failed. Number of processors: %u\n" ANSI_COLOR_RESET, info.dwNumberOfProcessors);
		ALL_CHECKS_OK = FALSE;
	}
	else {
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Number of processors check success. \n" ANSI_COLOR_RESET);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//enumerate monitors function
///////////////////////////////////////////////////////////////////////////////////////////////

BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
	int* monitorCount = (int*)dwData;
	(*monitorCount)++;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check if there are any monitors
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_no_monitors() {
	int monitorCount = 0;
	if (EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)&monitorCount)) {
		if (monitorCount) {
			DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Number of monitors check success.\n" ANSI_COLOR_RESET);
		}
		else {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Number of monitors check failed. No monitors found\n" ANSI_COLOR_RESET);
			ALL_CHECKS_OK = FALSE;
		}
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to enumerate monitors. Error code: %lu\n" ANSI_COLOR_RESET, GetLastError());
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check if uptime of system is less than 5 minutes
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_uptime() {
	DWORD ticks = GetTickCount();
	DWORD minutes = ticks / (1000 * 60);
	if (minutes <= 5) {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]System uptime check failed. Uptime: %d\n" ANSI_COLOR_RESET, minutes);
		ALL_CHECKS_OK = FALSE;
	}
	else {
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]System uptime check success.\n" ANSI_COLOR_RESET);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check if hard disk drive size is less than 250 GB
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_harddisk_size()
{
	ULARGE_INTEGER totalBytes;
	ULARGE_INTEGER totalGigabytes;

	if (GetDiskFreeSpaceEx(NULL, NULL, &totalBytes, NULL))
	{
		totalGigabytes.QuadPart = totalBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL); // Convert bytes to gigabytes

		if (totalGigabytes.QuadPart < 250)
		{
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Hard disk drive size failed. Hard disk drive size: %llu GB\n" ANSI_COLOR_RESET, totalGigabytes.QuadPart);
			ALL_CHECKS_OK = FALSE;
		}
		else
		{
			DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Hard disk drive size check success.\n" ANSI_COLOR_RESET);
		}
	}
	else
	{
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to retrieve hard disk size.\n" ANSI_COLOR_RESET);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check if there are any audio devices
///////////////////////////////////////////////////////////////////////////////////////////////
VOID check_audio_device() {

	//cmd command: "wmic sounddev get caption"

	if (waveOutGetNumDevs() == 0) {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to retrieve any audio device.\n" ANSI_COLOR_RESET);
		ALL_CHECKS_OK = FALSE;
	}
	else {
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Audio device(s) check success.\n" ANSI_COLOR_RESET);
	}
}


///////////////////////////////////////////////////////////////////////////////////////////////
//check if mouse is present
///////////////////////////////////////////////////////////////////////////////////////////////
VOID check_mouse() {
	if (GetSystemMetrics(SM_MOUSEPRESENT)) {
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Mouse check success.\n" ANSI_COLOR_RESET);
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Mouse check failed. No mouse detected\n" ANSI_COLOR_RESET);
		ALL_CHECKS_OK = FALSE;
	}
}


///////////////////////////////////////////////////////////////////////////////////////////////
//check if sleep functionality is being skipped 
///////////////////////////////////////////////////////////////////////////////////////////////
VOID check_sleep_skipping() {
	SYSTEMTIME startTime, endTime;

	GetSystemTime(&startTime);
	// Sleep for three seconds
	Sleep(3000);
	GetSystemTime(&endTime);

	ULONGLONG startTimeMs = ((ULONGLONG)startTime.wSecond * 1000) + startTime.wMilliseconds;
	ULONGLONG endTimeMs = ((ULONGLONG)endTime.wSecond * 1000) + endTime.wMilliseconds;
	ULONGLONG timeDifference = endTimeMs - startTimeMs;

	if (timeDifference >= 2800) {
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Sleep detection check success.\n" ANSI_COLOR_RESET);
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Sleep detection failed.\n" ANSI_COLOR_RESET);
		ALL_CHECKS_OK = FALSE;
	}
}



///////////////////////////////////////////////////////////////////////////////////////////////

//                                  networking queries

///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
//check for internet connection
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_internet() {
	// Check google.com domain for internet connectivity
	if (InternetCheckConnection(L"https://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0))
	{
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Internet connection check success.\n" ANSI_COLOR_RESET);
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to connect to google.com. Error code: %lu\n" ANSI_COLOR_RESET, GetLastError());
		ALL_CHECKS_OK = FALSE;
	}
}


///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific MAC address
///////////////////////////////////////////////////////////////////////////////////////////////


VOID check_MAC() {
	char* MACS[] = {
		"00-05-69",		//VMware, Inc.
		"00-0C-29",
		"00-1C-14",
		"00-50-56",
		"00-0F-4F",		//PCS Systemtechnik GmbH(VirtualBox)
		"08-00-27",
		"EC-75-ED",		//Citrix Systems, Inc.
		"00-1C-42"		//Parallels, Inc.
	};


	ULONG ulOutBufLen = 0;

	// Allocate memory for the GetAdaptersInfo buffer
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]Error allocating memory needed to retrieve adapter info\n" ANSI_COLOR_RESET);
		return;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Failed to retrieve adapter info. Error code: %lu\n" ANSI_COLOR_RESET, GetLastError());
			return;
		}
	}

	// Get the adapter information
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != NO_ERROR) {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]GetAdaptersInfo failed\n" ANSI_COLOR_RESET);
		free(pAdapterInfo);
		return;
	}



	// Loop through the adapter information and compare the first three bytes
	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while (pAdapter) {
		for (int i = 0; i < sizeof(MACS) / sizeof(MACS[0]); i++) {
			//printf("MAC address: %02X-%02X-%02X\n", pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2]);

			if (strncmp(MACS[i], pAdapter->Address, 6) == 0) {
				DEBUG_FAIL(ANSI_COLOR_RED "[-]MAC address check failed. MAC address: %s\n" ANSI_COLOR_RESET, MACS[i]);
				ALL_CHECKS_OK = FALSE;
				free(pAdapterInfo);
				ALL_CHECKS_OK = FALSE;
				return;
			}
			pAdapter = pAdapter->Next;
		}
		DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]MAC address check success.\n" ANSI_COLOR_RESET);
		free(pAdapterInfo);
		return;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific network shares
///////////////////////////////////////////////////////////////////////////////////////////////

VOID check_shares() {

	LPWSTR network_shares[] = {
		L"VirtualBox Shared Folders",
		L"VBoxSharedFolders",
		L"VMware Shared Folders",
		L"vmware-host"
	};


	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwResumeHandle = 0;
	NET_API_STATUS nStatus;
	SHARE_INFO_0* pShareInfo = NULL;

	// Call NetShareEnum to retrieve the share information
	nStatus = NetShareEnum(NULL, 0, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

	if (nStatus == NERR_Success) {
		for (DWORD i = 0; i < dwEntriesRead; i++) {
			for (int x = 0; x < sizeof(network_shares) / sizeof(network_shares[0]); x++) {
				if (wcscmp(pShareInfo[i].shi0_netname, network_shares[x]) == 0) {
					DEBUG_FAIL(ANSI_COLOR_RED "[-]Network share check failed. Network share name: %ls\n" ANSI_COLOR_RESET, network_shares[x]);
					ALL_CHECKS_OK = FALSE;
					return;
				}
			}
		}
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "[-]NetShareEnum failed with error code %d\n" ANSI_COLOR_RESET, nStatus);
	}

	if (pShareInfo != NULL) {
		NetApiBufferFree(pShareInfo);
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Network shares check success.\n" ANSI_COLOR_RESET);
}


///////////////////////////////////////////////////////////////////////////////////////////////

//                                  filesystem queries

///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific files
///////////////////////////////////////////////////////////////////////////////////////////////

BOOL FileExists(const char* filePath) {
	if (PathFileExistsA(filePath)) {
		return TRUE;
	}
	return FALSE;
}


VOID check_files() {

	char* files[] = {
		//VirtualBox
		"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
		"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
		"C:\\windows\\system32\\drivers\\VBoxSF.sys",
		"C:\\windows\\system32\\drivers\\VBoxVideo.sys",
		"C:\\windows\\system32\\vboxdisp.dll",
		"C:\\windows\\system32\\vboxhook.dll",
		"C:\\windows\\system32\\vboxmrxnp.dll",
		"C:\\windows\\system32\\vboxogl.dll",
		"C:\\windows\\system32\\vboxoglarrayspu.dll",
		"C:\\windows\\system32\\vboxoglcrutil.dll",
		"C:\\windows\\system32\\vboxoglerrorspu.dll",
		"C:\\windows\\system32\\vboxoglfeedbackspu.dll",
		"C:\\windows\\system32\\vboxoglpackspu.dll",
		"C:\\windows\\system32\\vboxoglpassthroughspu.dll",
		"C:\\windows\\system32\\vboxservice.exe",
		"C:\\windows\\system32\\vboxtray.exe",
		"C:\\windows\\system32\\VBoxControl.exe",
		//VMware
		"C:\\windows\\system32\\drivers\\vmmouse.sys",
		"C:\\windows\\system32\\drivers\\vmnet.sys",
		"C:\\windows\\system32\\drivers\\vmxnet.sys",
		"C:\\windows\\system32\\drivers\\vmhgfs.sys",
		"C:\\windows\\system32\\drivers\\vmx86.sys",
		"C:\\windows\\system32\\drivers\\hgfs.sys"
	};

	for (int i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (FileExists(files[i])) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Filename check failed. Filename: %s\n" ANSI_COLOR_RESET, files[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Filenames check success. \n" ANSI_COLOR_RESET);
}


///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific directories
///////////////////////////////////////////////////////////////////////////////////////////////

BOOL DirectoryExists(const char* dirPath) {
	// Append a backslash to the path if it's missing
	char path[MAX_PATH];
	snprintf(path, sizeof(path), "%s\\", dirPath);

	if (PathFileExistsA(path)) {
		DWORD attr = GetFileAttributesA(path);
		return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
	}

	return FALSE;
}

VOID check_directories() {

	char* directories[] = {
		"C:\\Program Files\\VMware\\VMware Tools",
		"C:\\Program Files\\Oracle\\VirtualBox Guest Additions"
	};

	for (int i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) {
		if (DirectoryExists(directories[i])) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Directories check failed. Directory: %s\n" ANSI_COLOR_RESET, directories[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Directories check success. \n" ANSI_COLOR_RESET);

}

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific strings in the executable path
///////////////////////////////////////////////////////////////////////////////////////////////
VOID check_path() {

	const char* forbiddenSubstrings[] = {
		"sample",
		"virus",
		"sandbox"
	};

	char executablePath[MAX_PATH];
	DWORD pathLength = GetModuleFileNameA(NULL, executablePath, MAX_PATH);


	//printf("Executable path: %s\n", executablePath);


	int numForbiddenSubstrings = sizeof(forbiddenSubstrings) / sizeof(forbiddenSubstrings[0]);

	for (int i = 0; i < numForbiddenSubstrings; i++) {
		if (strstr(executablePath, forbiddenSubstrings[i]) != NULL) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Executable path check failed. Full path: %s\n" ANSI_COLOR_RESET, executablePath);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Executable path check success. \n" ANSI_COLOR_RESET);
}

///////////////////////////////////////////////////////////////////////////////////////////////

//                                  registry queries

///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
//check for specific registry paths
///////////////////////////////////////////////////////////////////////////////////////////////

BOOL DoesRegistryKeyExist(const char* registryPath) {
	HKEY hKey;
	LONG result;

	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

	if (result == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return TRUE;
	}
	else if (result == ERROR_FILE_NOT_FOUND) {
		return FALSE;
	}
	else {
		DEBUG_FAIL(ANSI_COLOR_RED "Error opening registry key: %ld\n" ANSI_COLOR_RESET, result);
		return FALSE;
	}
}

VOID check_regpaths() {

	const char* registryPaths[] = {
		//VirtualBox
		"HARDWARE\\ACPI\\DSDT\\VBOX__",
		"HARDWARE\\ACPI\\FADT\\VBOX__",
		"HARDWARE\\ACPI\\RSDT\\VBOX__",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		"SYSTEM\\ControlSet001\\Services\\VBoxService",
		"SYSTEM\\ControlSet001\\Services\\VBoxSF",
		"SYSTEM\\ControlSet001\\Services\\VBoxVideo",
		//VMware
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SYSTEM\\ControlSet001\\Services\\vmdebug",
		"SYSTEM\\ControlSet001\\Services\\vmmouse",
		"SYSTEM\\ControlSet001\\Services\\VMTools",
		"SYSTEM\\ControlSet001\\Services\\VMMEMCTL",
		"SYSTEM\\ControlSet001\\Services\\vmware",
		"SYSTEM\\ControlSet001\\Services\\vmci",
		"SYSTEM\\ControlSet001\\Services\\vmx86",
		//Wine
		"SOFTWARE\\Wine",
		//Xen
		"HARDWARE\\ACPI\\DSDT\\xen",
		"HARDWARE\\ACPI\\FADT\\xen",
		"HARDWARE\\ACPI\\RSDT\\xen",
		"SYSTEM\\ControlSet001\\Services\\xenevtchn",
		"SYSTEM\\ControlSet001\\Services\\xennet",
		"SYSTEM\\ControlSet001\\Services\\xennet6",
		"SYSTEM\\ControlSet001\\Services\\xensvc",
		"SYSTEM\\ControlSet001\\Services\\xenvdb"
	};

	for (int i = 0; i < sizeof(registryPaths) / sizeof(registryPaths[0]); i++) {
		if (DoesRegistryKeyExist(registryPaths[i])) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Registry path check failed. Regpath: %s\n" ANSI_COLOR_RESET, registryPaths[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Registry paths check success. \n" ANSI_COLOR_RESET);
}


///////////////////////////////////////////////////////////////////////////////////////////////

//                                  process queries

///////////////////////////////////////////////////////////////////////////////////////////////

	///////////////////////////////////////////////////////////////////////////////////////////////
	//check for specific running processes
	///////////////////////////////////////////////////////////////////////////////////////////////

BOOL isProcessRunning(const char* processName) {
	DWORD processes[1024], cbNeeded, numProcesses;

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
		return FALSE;
	}

	numProcesses = cbNeeded / sizeof(DWORD);

	for (DWORD i = 0; i < numProcesses; i++) {
		if (processes[i] != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

			if (hProcess != NULL) {
				char processPath[MAX_PATH];
				if (GetModuleFileNameExA(hProcess, NULL, processPath, MAX_PATH)) {
					if (strstr(processPath, processName) != NULL) {
						CloseHandle(hProcess);
						return TRUE;
					}
				}
				CloseHandle(hProcess);
			}
		}
	}

	return FALSE;
}


VOID check_running_processes() {

	const char* processNames[] = {
		//VirtualBox
		"vboxservice.exe",
		"vboxtray.exe",
		//VirtualPC
		"vmsrvc.exe",
		"vmusrvc.exe",
		//VMWare
		"vmtoolsd.exe",
		"vmacthlp.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vmware.exe",
		"vmount2.exe",
		//Xen
		"xenservice.exe",
		"xsvc_depriv.exe"
	};

	int numProcesses = sizeof(processNames) / sizeof(processNames[0]);

	for (int i = 0; i < numProcesses; i++) {
		if (isProcessRunning(processNames[i])) {
			DEBUG_FAIL(ANSI_COLOR_RED "[-]Running processes check failed. Process: %s\n" ANSI_COLOR_RESET, processNames[i]);
			ALL_CHECKS_OK = FALSE;
			return;
		}
	}
	DEBUG_SUCCESS(ANSI_COLOR_GREEN "[+]Running processes check success. \n" ANSI_COLOR_RESET);

}