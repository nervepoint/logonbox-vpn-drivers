/**
 * Copyright © 2023 LogonBox Limited (support@logonbox.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the “Software”), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>

TCHAR LOGPATH[256];

void srv_log_close(HANDLE hndl) {
	CloseHandle(hndl);
}

HANDLE srv_log_open() {
	HANDLE hndl;
	hndl = CreateFile(LOGPATH, FILE_APPEND_DATA,        // open for writing
			FILE_SHARE_READ,          // allow multiple readers
			NULL,                     // no security
			OPEN_ALWAYS,              // open or create
			FILE_ATTRIBUTE_NORMAL,    // normal file
			NULL);                    // no attr. template
	if (hndl != INVALID_HANDLE_VALUE) {
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			unsigned char Header[2];
			Header[0] = 0xFF;
			Header[1] = 0xFE;
			DWORD wr;
			WriteFile(hndl, Header, 2, &wr, NULL);
		}
		SetFilePointer(hndl, 0, 0, FILE_END);
	}
	return hndl;
}

void srv_log_write(HANDLE hndl, LPCWSTR txt) {
	DWORD bytesWritten = 0;
	WriteFile(hndl, txt, (int)wcslen(txt) * 2, &bytesWritten,
			NULL);
}

void srv_log(LPCWSTR txt) {
	HANDLE logHndl = srv_log_open();
	if (logHndl != INVALID_HANDLE_VALUE) {
		// Not much we can do if there is an error I suppose. Perhaps this should just exit or something
		srv_log_write(logHndl, txt);
		srv_log_close(logHndl);
	}
}

int __cdecl _tmain(int argc, TCHAR *argv[])
{
	if( argc != 4 || lstrcmpi( argv[1], _T("/service")) != 0 )
	{
		return 1;
	}

	SetCurrentDirectory(argv[2]);
 	swprintf_s(LOGPATH, 256, L"logs\\%s.log", argv[3]);
	DeleteFile(LOGPATH);

	srv_log(L"[network-configuration-service] [INFO] Service for ");
	srv_log(argv[3]);
	srv_log(L"\r\n");
	srv_log(L"[network-configuration-service] [INFO] Running in ");
	srv_log(argv[2]);
	srv_log(L"\r\n");
	srv_log(L"[network-configuration-service] [INFO] Opening tunnel.dll\r\n");

	HMODULE tunnel_lib = LoadLibrary(L"tunnel.dll");
	if (!tunnel_lib)
	{
		srv_log(L"[network-configuration-service] [ERROR] No tunnel.dll found in PATH\r\n");
		return 2;
	}

	srv_log(_T("[network-configuration-service] [INFO] Looking up procedure\r\n"));
	BOOL (_cdecl *tunnel_proc)(_In_ LPCWSTR conf_file);
	*(FARPROC*)&tunnel_proc = GetProcAddress(tunnel_lib, "WireGuardTunnelService");
	if (!tunnel_proc)
	{
		srv_log(L"[network-configuration-service] [INFO] No procedure found! This should be impossible\r\n");
		return 3;
	}

	TCHAR wcstr[256];
 	swprintf_s(wcstr, 256, L"conf\\connections\\%s.conf", argv[3]);
	
	srv_log(L"[network-configuration-service] [INFO] Starting tunnel\r\n");
	tunnel_proc(wcstr);
	srv_log(L"[network-configuration-service] [INFO] Normal tunnel exit\r\n");
	return 0;
}
