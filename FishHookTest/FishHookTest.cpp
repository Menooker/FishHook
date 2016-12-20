// FishHookTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../FishHook32/exports.h"
#include <iostream>
#include <string>
using namespace std;

long __stdcall CallBackProc(SharedInfo* psInfo)
 {
	 	 WCHAR* pathname;
		 WCHAR* keyname;
		 char* pstr;
	 	 switch(psInfo->type )
		 {
		 case FILTER_CREATE_PROCESS_PRE:
			 cout<<"CreateProcess @pid "<<psInfo->pid<<endl;
			 printf("str1: %ws\n",(wchar_t*)psInfo->data.strd.str1);
             printf("str2: %ws\n",(wchar_t*)psInfo->data.strd.str2);
			 return 1; //change to 0 if you don't want to allow creating process
			 break;
		 case FILTER_CREATE_PROCESS_POST:
			 cout<<"CreateProcess @pid "<<psInfo->pid<<endl;
			 printf("str1: %ws\n",(wchar_t*)psInfo->data.strd.str1);
             printf("str2: %ws\n",(wchar_t*)psInfo->data.strd.str2);
			 printf("New pid= %d\n" ,psInfo->data.intArray[253]);
			 return 1;
			 break;
		 default:
			 cout<<"???"<<endl;
		 }
 
		 return 1;
 }

int _tmain(int argc, _TCHAR* argv[])
{
	InitFishHook();
	FishHookTypes id[]={HOOK_CreateProcessInternalW,HOOK_AicLaunchAdminProcess};
	PROCESS_INFORMATION info;
	STARTUPINFO si;
	memset(&si,0,sizeof(si));

	si.cb=sizeof(si);
	si.wShowWindow =SW_SHOW;
	si.dwFlags=STARTF_USESHOWWINDOW;
	WCHAR path[]=L"cmd";
	CreateProcess(NULL,path,NULL,NULL,0,CREATE_SUSPENDED|CREATE_NEW_CONSOLE,NULL,NULL,&si,&info);
	printf("RET=%d",SetIATHookByAPC(info.hProcess,(HANDLE)info.dwProcessId,CallBackProc,id,2));
	ResumeThread(info.hThread);
	//WaitForSingleObject(info.hProcess,-1);
	//*/

    /*HWND hWnd = FindWindow(NULL,L"CWNPTransportImpl");
    DWORD pid;
	GetWindowThreadProcessId(hWnd,&pid);
	//HANDLE hprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	printf("PID %d\n",pid);
	SetAPIHook64(pid,NULL,id,2);
	//*/
	
	system("pause");
	return 0;
}

