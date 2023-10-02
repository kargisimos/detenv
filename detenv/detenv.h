/*
	created by: kargisimos

	small and portable Windows C library for sandbox detection.
*/


#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <Lmcons.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <lm.h>
#include <shlwapi.h>
#include <mmsystem.h>
#include <psapi.h>


#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Winmm.lib")

BOOL ALL_CHECKS_OK;


/*
	call all checks
*/
BOOL detenv_all_checks(VOID);

/*
	generic OS queries
*/
VOID check_username(VOID);
VOID check_hostname(VOID);
DOUBLE bytes_to_gb(ULONGLONG bytes);
VOID check_RAM(VOID);
VOID check_no_processors(VOID);
BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData);
VOID check_no_monitors(VOID);
VOID check_uptime(VOID);
VOID check_harddisk_size(VOID);
VOID check_audio_device(VOID);
VOID check_mouse(VOID);
VOID check_sleep_skipping(VOID);

/*
	networking queries
*/
VOID check_internet(VOID);
VOID check_MAC(VOID);
VOID check_shares(VOID);

/*
	filesystem queries
*/
BOOL FileExists(const char* filePath);
VOID check_files(VOID);
BOOL DirectoryExists(const char* dirPath);
VOID check_directories(VOID);
VOID check_path(VOID);

/*
	registry queries
*/
BOOL DoesRegistryKeyExist(const char* registryPath);
VOID check_regpaths(VOID);

/*
	process queries
*/
BOOL isProcessRunning(const char* processName);
VOID check_running_processes(VOID);