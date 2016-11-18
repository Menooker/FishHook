// FishHookTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../FishHook32/exports.h"

int _tmain(int argc, _TCHAR* argv[])
{
	InitFishHook();
	int id[]={6,11};
/*	PROCESS_INFORMATION info;
	STARTUPINFO si;
	memset(&si,0,sizeof(si));

	si.cb=sizeof(si);
	si.wShowWindow =SW_SHOW;
	si.dwFlags=STARTF_USESHOWWINDOW;
	WCHAR path[]=L"cmd";
	CreateProcess(NULL,path,NULL,NULL,0,CREATE_SUSPENDED|CREATE_NEW_CONSOLE,NULL,NULL,&si,&info);
	SetIATHookByAPC(info.hProcess,(HANDLE)info.dwProcessId,NULL,id,1);
	ResumeThread(info.hThread);
	WaitForSingleObject(info.hProcess,-1);
	//*/

    HWND hWnd = FindWindow(NULL,L"CWNPTransportImpl");
    DWORD pid;
	GetWindowThreadProcessId(hWnd,&pid);
	//HANDLE hprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	printf("PID %d\n",pid);
	SetAPIHook64(pid,NULL,id,2);
	//*/
	
	system("pause");
	return 0;
}

