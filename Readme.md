# FishHook
FishHook is a Windows inline hook platform, which supports x86 and x64 environment. You can write filter routines to monitor or alter the behavior of other programs's API. Also, you can write your own "fake" APIs in your own DLL, and FishHook will inject your DLL into the process and replace the target API with your "fake" one. Besides, FishHook provides a function to hook the child-processes created by a "hooked" process, which is useful for building a "sandbox" environment.

## How to build
### Dependencies
 * Visual Studio 2010. The community version is free.
 * Detours Express 3.0 x86
 * Detours x64. Original Detours x64 is charged. [Here](http://bbs.pediy.com/showthread.php?t=156369) is a third-party-made Detours x64 lib, which is based on mhook. A copy of it is uploaded [here](https://github.com/Menooker/FishHook/files/605676/Detours.V3.0.x64.zip).
 
### Build me
This repo includes a VS2010 solution. Open FishHook32.sln. Build x86 version of the project "FishHook32". This generates "FishHook32.dll". Then switch to x64 mode and build the project "FishHook32" again. This generates "FishHook64.dll". Finally, switch to x86 mode and build and run project FishHookTest, which is an example of FishHook.

## FishHook Introduction
A process that initializes FishHook and filters the API calls of hooked processes is called "debugger". Only one debugger is running at a time, and a debugger is a 32-bit process. This means even though you run FishHook on a 64 bit system, usually you should call FishHook APIs in a 32-bit debugger. (However, your custom "fake" APIs can be written in x64 code.)

The easiest way to use FishHook is to implement a filter. FishHook has implemented some "fake" APIs, such as CreateProcessInternalW and ZwSetValueKey. You should give FishHook a process-id to hook and the list of the APIs you want to hook. In addition, you should write a filter program in your 32-bit debugger. FishHook will replace the APIs with its built-in "fake" APIs. Once the hooked process calls the hooked API, the user-defined filter routine will be called, and you can monitor or alter the behavoir of the API in your filter. Note that the filter runs in the debugger's address space.

The other way to utilize FishHook is to use custom hooks. You should write the your "fake" APIs in DLLs, and pass the DLL and a process-id to FishHook. FishHook will inject your DLL and replace the target API with yours. Now you can do whatever you want. Note that your "fake" APIs will run in the hooked process's address space.

Some may want to hook the child-process created by a hooked process, which is a common way to build a sandbox or a monitor program. FishHook provides built-in "fake" APIs which will automatically hook the newly created process launched by a hooked program. 

## A quick example on writing a filter

 ```c
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
	system("pause");
	return 0;
}

 ```
 This program writes a filter "CallBackProc" and then creates and hook a "cmd" procress. If the cmd process creates a new process, CallBackProc is called and you can see some outputs in our debugger console. Note that all the processes created by the cmd process are hooked too. 
