#include "stdafx.h"
#include "var.h"
#include "stringex.h"
#include "hi.h"
#include "NativeApi.h"
#include <malloc.h>
#include "internals.h"

#ifdef _WIN64
#define HOOKDLLEVENT ("Global\\HookDllEvent64")
#define HOOK_SHARED_INFO_MUTEX ("Global\\HookSharedInfoMutex64")
#define HOOK_DLL_MUTEX ("Global\\HookDllMutex64")
#else
#define HOOKDLLEVENT ("Global\\HookDllEvent")
#define HOOK_SHARED_INFO_MUTEX ("Global\\HookSharedInfoMutex")
#define HOOK_DLL_MUTEX ("Global\\HookDllMutex")
#endif

 _vbaStrCmp oldstrcmp=NULL;

ptrGetAddr oldGetProcAddress=0;
ptrDllCall oldDLLFunctionCall=0;
OLD_MessageBox oldMessageBoxA=0;
OLD_MessageBoxW oldMessageBoxW=0;
long (__stdcall *oldSwitchDesktop)(long)=0;
int (__stdcall *oldCreateProcessA)(LPCTSTR, LPTSTR,LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID ,LPCTSTR ,LPSTARTUPINFO,LPPROCESS_INFORMATION )=0;
int (__stdcall *oldCreateProcessW)( LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)=0;
HINSTANCE (__stdcall *oldShellExecuteW)(HWND hwnd,LPCWSTR lpOperation,LPCWSTR lpFile,LPCWSTR lpParameters,LPCWSTR lpDirectory,INT nShowCmd)=0;
 BOOL (__stdcall *oldShellExecuteExW)(  _Inout_  SHELLEXECUTEINFOW *pExecInfo)=0;
 PFNCreateProcessInternalW oldCreateProcessInternalW=0 ;
 ZWSETVALUEKEY oldZwSetValueKey=0;
 NTCREATEFILE oldNtCreateFile=0;
 PSHCreateProcess oldSHCreateProcess=0;
 PAicLaunchAdminProcess oldAicLaunchAdminProcess=0;


long __stdcall vbaStrCmp(PVOID str1,PVOID str2);
long __stdcall myDllFunctionCall(DLLInfo *);
long __stdcall myGetProcAddress(HMODULE hModule,LPCSTR lpProcName );
long __stdcall mySwitchDesktop(long h);
int __stdcall myCreateProcessA(LPCTSTR, LPTSTR,LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID ,LPCTSTR ,LPSTARTUPINFO,LPPROCESS_INFORMATION );
int __stdcall myCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
int __stdcall myMessageBoxA( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption,UINT uType);
int __stdcall myMessageBoxW( HWND hWnd, LPWSTR lpText, LPCWSTR lpCaption,UINT uType);
HINSTANCE __stdcall myShellExecuteW(HWND hwnd,LPCWSTR lpOperation,LPCWSTR lpFile,LPCWSTR lpParameters,LPCWSTR lpDirectory,INT nShowCmd);
 BOOL __stdcall myShellExecuteExW(  _Inout_  SHELLEXECUTEINFOW *pExecInfo);
  BOOL _stdcall myCreateProcessInternalW ( HANDLE hToken, LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, 
     LPSECURITY_ATTRIBUTES lpThreadAttributes,        
     BOOL bInheritHandles,        
     DWORD dwCreationFlags, 
     LPVOID lpEnvironment,        
     LPCWSTR lpCurrentDirectory,        
     LPSTARTUPINFOW lpStartupInfo,        
     LPPROCESS_INFORMATION lpProcessInformation , 
 PHANDLE hNewToken 
);
 long myZwSetValueKey
 (
     __in      HANDLE KeyHandle,
     __in      PUNICODE_STRING ValueName,
     __in_opt  ULONG TitleIndex,
     __in      ULONG Type,
     __in_opt  PVOID Data,
     __in      ULONG DataSize
 );
 NTSTATUS myNtCreateFile(
  _Out_     PHANDLE FileHandle,
  _In_      ACCESS_MASK DesiredAccess,
  _In_      POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_     PIO_STATUS_BLOCK IoStatusBlock,
  _In_opt_  PLARGE_INTEGER AllocationSize,
  _In_      ULONG FileAttributes,
  _In_      ULONG ShareAccess,
  _In_      ULONG CreateDisposition,
  _In_      ULONG CreateOptions,
  _In_      PVOID EaBuffer,
  _In_      ULONG EaLength
);
 int __stdcall mySHCreateProcess(int p1,HANDLE hToken,wchar_t *lpApplicationName,wchar_t* lpCommandLine,DWORD dwCreationFlags,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation,int p2,char p3,int p4);
 int __fastcall myAicLaunchAdminProcess(WCHAR *lpApplicationName, WCHAR *lpCommandLine, void* a3, DWORD dwCreationFlags, WCHAR *lpCurrentDirectory, HWND a6, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD *a9);
DLLHookInfo hinfo[]={
{"msvbvm60.dll","__vbaStrCmp",vbaStrCmp,(void**)&oldstrcmp},
{"user32.dll","SwitchDesktop",mySwitchDesktop,(void**)&oldSwitchDesktop},
{"kernel32.dll","CreateProcessA",myCreateProcessA,(void**)&oldCreateProcessA},
{"kernel32.dll","CreateProcessW",myCreateProcessW,(void**)&oldCreateProcessW},
{"user32.dll","MessageBoxA",myMessageBoxA,(void**)&oldMessageBoxA},
{"user32.dll","MessageBoxW",myMessageBoxW,(void**)&oldMessageBoxW},
{"kernelbase.dll","CreateProcessInternalW",myCreateProcessInternalW,(void**)&oldCreateProcessInternalW},
{"shell32.dll","ShellExecuteExW",myShellExecuteExW,(VOID**)&oldShellExecuteExW},
{"ntdll.dll","ZwSetValueKey",myZwSetValueKey,(VOID**)&oldZwSetValueKey},
{"shell32.dll","_SHCreateProcess",mySHCreateProcess,(VOID**)&oldSHCreateProcess},
{"ntdll.dll","NtCreateFile",myNtCreateFile,(VOID**)&oldNtCreateFile},
{"windows.storage.dll","AicLaunchAdminProcess",myAicLaunchAdminProcess,(VOID**)&oldAicLaunchAdminProcess},
//{"ntdll.dll","NtCreateProcessEx",myNtCreateProcessEx,(void**)&oldNtCreateProcessEx}
};

extern "C" BOOL __stdcall IsWow64ProcessEx(HANDLE hProcess);
extern "C" long FHPrint(char *format,...);
 extern "C" long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void * callproc,int *pDLLid,long num);
 extern  void __stdcall Msgbox(char* str,long a);
 extern "C" long __stdcall SetAPIHook64(long pid,long callproc,int *pDLLid,long num);
 extern "C" long __stdcall ResumeProcessEx(long pid);
 extern "C" long __stdcall SuspendProcessEx(long pid);
 extern  long ResumeProcess(DWORD dwProcessId,long selftid);
 extern  long SuspendProcess(DWORD dwProcessId,long selftid);
#ifdef _WIN64
 long __stdcall InsertDLL64(DWORD pid)
{
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				psInfo->type=92;
				psInfo->pid=pid;


				SetEvent(hEProcess);
				WaitForSingleObject(hEProcessBack,-1);
				ResetEvent(hEProcessBack);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
				return psInfo->ret;
}
long __stdcall SetAPIHook64(long pid,int *pDLLid,long num)
{
	if (psInfo==0)
		return 100;
	if (num<=20)
	{
		HANDLE hMsInfo=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
		long ret=WaitForSingleObject(hMsInfo,1000);
		if (ret==WAIT_TIMEOUT)
		{
			return 12;
		}

		psInfo->type=109;
		psInfo->pid=pid;
		psInfo->data.intArray[0]=num;
		CopyMemory(&(psInfo->data.intArray[1]),pDLLid,num*sizeof(int));
		SetEvent(hEProcess);

		WaitForSingleObject(hEProcessBack,-1);
		ResetEvent(hEProcessBack);
		ret=psInfo->ret;
		ReleaseMutex(hMsInfo);
		CloseHandle(hMsInfo);
		return ret;
	}
	else
	{
		return 13;
	}
}
#else
 long InsertDLL32(DWORD pid)
 {
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				psInfo64->type=90;
				psInfo64->pid=pid;


				SetEvent(hEProcess32);
				WaitForSingleObject(hEProcessBack32,-1);
				ResetEvent(hEProcessBack32);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
				return psInfo64->ret;
 }
#endif
 long UnHook(void ** ppFun,PVOID pDetour)
{
 //       DetourRestoreAfterWith();
        DetourTransactionBegin();
		//Detour
        DetourUpdateThread(GetCurrentThread());

        //这里可以连续多次调用DetourAttach，表明HOOK多个函数
        DetourDetach(ppFun,pDetour);

        return DetourTransactionCommit();
}


long Hook(void ** ppOld,PVOID pNew)
{
 //       DetourRestoreAfterWith();
        DetourTransactionBegin();
		//Detour
        DetourUpdateThread(GetCurrentThread());

        //这里可以连续多次调用DetourAttach，表明HOOK多个函数
        DetourAttach(ppOld,pNew);

        return DetourTransactionCommit();
}




int  HookIt(const char *pDllName,const char *pApiName,void *pNew,PVOID * pOld)
{

	if (*pOld!=0)
		return 9;
	HMODULE h=GetModuleHandleA(pDllName);
	//HMODULE h=LoadLibrary(pDllName);
	if (h==0)
	{
		return 1;
	}
	else
	{
		void* p=GetProcAddress(h,pApiName);
		if (p==0)
			return 2;
		void*p2=0 ;
		long ret;
		SuspendProcess(CurrentPid,GetCurrentThreadId());		
		if (chk_IAT(pDllName,pApiName,&p2)==0)
		{
			if (p!=p2 && p2!=0)
			{
				void* p3=0;
				replace_IAT(pDllName,pApiName,p,&p3);
				//Msgbox((char*)pApiName,(long)p2);
				//ret=Hook(&p2,pNew);
				//*pOld=p2;
				//if (ret!=0)
					//return ret;
			}
		}
		//Msgbox((char*)pApiName,(long)p);
		ret=Hook(&p,pNew);
		*pOld=p;
		ResumeProcess(CurrentPid,GetCurrentThreadId());
		return ret;
	}
}


typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

long IsWow64(HANDLE hProcess)
{
/*
Notes - this routine is deprecated in FishHook32, for the true meaning of the API "IsWow64Process" is
"If the process is running under 32-bit Windows, the value is set to FALSE. If the process is a 64-bit
application running under 64-bit Windows, the value is also set to FALSE." by MSDN.
So this routine invoking 'IsWow64Process' cannot distinguish a 32-bit process from a 64-bit process.
If a 32-bit process runs on a 32-bit,  it will returns a 'False'. So we use IsWow64ProcessEx which is
exported by our dll instead. However, in 64-bit processes, it is not an issue, it will return a correct value.
*/
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(hProcess,&bIsWow64))
        {
			return 123;
            //handle error
        }
    }
	
    return bIsWow64;
}


long __stdcall vbaStrCmp(PVOID str1,PVOID str2)
{//MessageBoxW(NULL,(WCHAR *)str1,(WCHAR *) str2,64);
//	Logss(str1,str2);
	wcsncpy((wchar_t*)(sInfo.data.strd.str1) ,(WCHAR*)str1,sizeof(sInfo.data.strd.str1)/2-1);
	wcsncpy((wchar_t*)(sInfo.data.strd.str2) ,(WCHAR*)str2,sizeof(sInfo.data.strd.str2)/2-1);
	sInfo.type =0;
	sInfo.pid=CurrentPid;
	HANDLE hE= OpenEvent(EVENT_ALL_ACCESS,FALSE,HOOKDLLEVENT);
    SetEvent(hE);
	CloseHandle(hE);
	if (breakpoint)MessageBoxW(NULL,(WCHAR *)str1,(WCHAR *) str2,64);
	
 return oldstrcmp(str1,str2);
}


long __stdcall myDllFunctionCall(DLLInfo *pDll)
{
	strncpy(sInfo.data.strd.str1 ,pDll->ModuleName,sizeof(sInfo.data.strd.str1)-1 );
	strncpy(sInfo.data.strd.str2 ,pDll->FunctionName,sizeof(sInfo.data.strd.str2)-1 );
	//sInfo.type =2;
	HANDLE hE= OpenEvent(EVENT_ALL_ACCESS,FALSE,HOOKDLLEVENT);
    SetEvent(hE);
	CloseHandle(hE);
	if (breakpoint)		MessageBox(NULL,pDll->ModuleName,pDll->FunctionName,64);
	long ret=oldDLLFunctionCall(pDll);
    for (int i=0;i<REGDLLNUM;i++)
	{
		char mod[255]={0};
		strncpy(mod,pDll->ModuleName,254);
		if (!stristr(mod,".dll"))
		{
			strcat(mod,".dll");
		}
		if (!strcmpi(mod,hinfo[i].ModName) && (!strcmpi(pDll->FunctionName,hinfo[i].ProcName)))
		{
			DllFunctionContext* pContext=(DllFunctionContext *) pDll->ContextPtr;
            *(hinfo[i].ppOld)=pContext->FunctionPtr;
	        pContext->FunctionPtr=hinfo[i].pProc;
            
			break;
		}
	}

	return ret;
}


long __stdcall mySwitchDesktop(long h)
{
    sInfo.data.Param2.p1=h;
	sInfo.type =1799;
	sInfo.pid=CurrentPid;
	HANDLE hE= OpenEvent(EVENT_ALL_ACCESS,FALSE,HOOKDLLEVENT);
    SetEvent(hE);
	CloseHandle(hE);
	//if (breakpoint)		MessageBox(NULL,pDll->ModuleName,pDll->FunctionName,64);
	return oldSwitchDesktop(h);
}

 long __stdcall myGetProcAddress(HMODULE hModule,LPCSTR lpProcName )
 {
	 MessageBox(NULL,lpProcName,"haha",64);
	 return oldGetProcAddress(hModule, lpProcName);
 }


 

  DWORD WINAPI ReleaseProc (LPVOID lpParam)
 {
		HANDLE* h=(HANDLE*)lpParam;
	 	long rtn=WaitForSingleObject(h[0],7000);
		if(rtn==WAIT_TIMEOUT)
		{//Inject Failed!!!!!
#ifdef DBG
				MessageBoxW(NULL,L"time out",L"ha",64);
#endif
				ReleaseMutex(h[1]);
					
		}	
//MessageBoxW(NULL,L"Released",L"ha",64);
#ifndef _WIN64
		CloseHandle(h[1]);
#endif
		CloseHandle(h[0]);
		delete []h;
		return 1;
 }


 BOOL WINAPI myCreateProcessA(
       LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes,
       LPSECURITY_ATTRIBUTES lpThreadAttributes,
           BOOL bInheritHandles,
           DWORD dwCreationFlags,
       LPVOID lpEnvironment,
       LPCTSTR lpCurrentDirectory,
           LPSTARTUPINFO lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation
)
{
	 char DLLPath[255];
	 GetModuleFileName((HINSTANCE)hMod,DLLPath,255);
	 ///////////////////////////////////
	 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
	 WaitForSingleObject(hM,-1);
	 sInfo.type=2;
	 sInfo.pid=CurrentPid;
	 if (lpApplicationName!=NULL)
		strcpy(sInfo.data.strd.str1 ,lpApplicationName);
	 if (lpCommandLine!=NULL)
		strcpy(sInfo.data.strd.str2 ,lpCommandLine);

     SetEvent(hEvent);
	 WaitForSingleObject(hEventBack,-1);
	 ResetEvent(hEventBack);
	 if (sInfo.ret==0)
	 {

		ReleaseMutex(hM);
		CloseHandle(hM);
		//CloseHandle(hEE2);
		return 0;
	 }
	 ReleaseMutex(hM);
	 CloseHandle(hM);
	 //////////////////////////
	 HANDLE hMutex = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex");
	 WaitForSingleObject(hMutex,-1);
	 //MessageBoxA(NULL,lpCommandLine,"ha",64);
	 thInfo.count=2;
	 thInfo.DLLid[0]=3;
	 thInfo.DLLid[1]=2;
	 NeedToLoad=0;
#ifdef _WIN64
	 HANDLE hE=hEventHookBack64;
#else
	 HANDLE hE=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
#endif

	 long rtn=0;
	 long ret= DetourCreateProcessWithDllA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              bInheritHandles,dwCreationFlags|CREATE_SUSPENDED, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation,DLLPath,oldCreateProcessA);

	 if (ret)
	 {
			for (int i=0;i<128;i++)
			{
				if (toHookPid[i]==0)
				{
					toHookPid[i]=(HANDLE)lpProcessInformation->dwProcessId;
					break;
				}
			}
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				  ResumeThread(lpProcessInformation->hThread);
			}


		    
			HANDLE *EM=new HANDLE [2];
			EM[0]=hE;
			EM[1]=hMutex;
			CreateThread(NULL,0,ReleaseProc,EM,0,NULL);
			
			return ret;
	 }
	 else
	 {
		    ReleaseMutex(hMutex);
			CloseHandle(hMutex);
#ifndef WIN64
			CloseHandle(hE);
#endif
			ret= oldCreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              bInheritHandles,dwCreationFlags, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation);
			if (ret)
			{
				WaitForInputIdle(lpProcessInformation->hProcess,-1);
				int temp[2]={2,3};
				SetIATHookByAPC(lpProcessInformation->hProcess,(HANDLE)lpProcessInformation->dwProcessId,(void*)1,temp,2);
				
			}
			return ret;
			
	 } 

}

  int WINAPI myCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{ 


	 char DLLPath[255];
	 GetModuleFileName((HINSTANCE)hMod,DLLPath,255);

	 	 ///////////////////////////////////
	 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
	 WaitForSingleObject(hM,-1);
	 
	 sInfo.type=3;
	 sInfo.pid=CurrentPid;
	 if (lpApplicationName!=NULL)
		 wcscpy((wchar_t*)sInfo.data.strd.str1 ,lpApplicationName);
	 if (lpCommandLine!=NULL)
	     wcscpy((wchar_t*)sInfo.data.strd.str2 ,lpCommandLine);
	 
     SetEvent(hEvent);
	 WaitForSingleObject(hEventBack,-1);
	 ResetEvent(hEventBack);
	 if (sInfo.ret==0)
	 {

		ReleaseMutex(hM);
		CloseHandle(hM);
		//CloseHandle(hEE2);
		return 0;
	 }
	 ReleaseMutex(hM);
	 CloseHandle(hM);
	 //CloseHandle(hEE2);
	 //////////////////////////

	 HANDLE hMutex = CreateMutex(&SecAttr,FALSE,HOOK_DLL_MUTEX);
	 WaitForSingleObject(hMutex,-1);

     /*thInfo.count=2;
	 thInfo.DLLid[0]=3;
	 thInfo.DLLid[1]=2;
	 NeedToLoad=0;*/
	 thInfo=autoHook;
#ifdef _WIN64
	 HANDLE hE=hEventHookBack64;
#else
	 HANDLE hE=CreateEvent(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
#endif
	 long rtn=0;
	 long ret= DetourCreateProcessWithDllW(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              bInheritHandles,dwCreationFlags|CREATE_SUSPENDED, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation,DLLPath,oldCreateProcessW);

	 if (ret)
	 {
		 int i;
			for (i=0;i<128;i++)
			{
				if (toHookPid[i]==0)
				{
					toHookPid[i]=(HANDLE)lpProcessInformation->dwProcessId;
					break;
				}
			}
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				  ResumeThread(lpProcessInformation->hThread);
				  WaitForSingleObject(hE,2000);
				  toHookPid[i]=0;
				  ReleaseMutex(hMutex);
			}
			else
			{
				ReleaseMutex(hMutex);
			}
			CloseHandle(hMutex);
#ifndef _WIN64
		    CloseHandle(hE);
#endif
			/*HANDLE *EM=new HANDLE [2];
			EM[0]=hE;
			EM[1]=hMutex;
			CreateThread(NULL,0,ReleaseProc,EM,0,NULL);*/
			
			return ret;
	 }
	 else
	 {
		    ReleaseMutex(hMutex);
			CloseHandle(hMutex);
			CloseHandle(hE);
			ret= oldCreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              bInheritHandles,dwCreationFlags|CREATE_SUSPENDED, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation);
#ifdef _WIN64
			if(IsWow64(lpProcessInformation->hProcess)==1)
			{
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				psInfo->type=94;
				psInfo->pid=lpProcessInformation->dwProcessId;
				psInfo->data.Param2.p2=(long)hMapFile;
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
				{
					psInfo->data.Param2.p1=1;
				}
				else
				{
					psInfo->data.Param2.p1=0;
				}

				SetEvent(hEProcess32);
				WaitForSingleObject(hEProcessBack32,-1);
				ResetEvent(hEProcessBack32);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			    {
				  ResumeThread(lpProcessInformation->hThread);
			    }
			}
			else
			{
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			    {
				  ResumeThread(lpProcessInformation->hThread);
			    }
				WaitForInputIdle(lpProcessInformation->hProcess,-1);
				int temp[2]={3,2};
				SetIATHookByAPC(lpProcessInformation->hProcess,(HANDLE)lpProcessInformation->dwProcessId,(void*)1,temp,2);
				
			}
#else
			if (IsWow64ProcessEx(lpProcessInformation->hProcess)==1)
			{// 64-bit

				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
				WaitForSingleObject(hMsInfo64,-1);
				psInfo64->type=93;
				psInfo64->pid=lpProcessInformation->dwProcessId;
				psInfo64->data.Param2.p2=(long)hMapFile;
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
				{
					sInfo.data.Param2.p1=1;
				}
				else
				{
					sInfo.data.Param2.p1=0;
				}

				SetEvent(hEProcess);
				WaitForSingleObject(hEProcessBack,-1);
				ResetEvent(hEProcessBack);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
			}
			else
			{

				int temp[2]={2,3};
				WaitForInputIdle(lpProcessInformation->hProcess,-1);
				SetIATHookByAPC(lpProcessInformation->hProcess,(HANDLE)lpProcessInformation->dwProcessId,(void*)1,temp,2);
				
			}
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				  ResumeThread(lpProcessInformation->hThread);
			}
	
#endif
			return ret;
			
	 } 
	 	/**/

}

    int __stdcall myMessageBoxA( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption,UINT uType)
 {
  //printf("%s\t%d\r\n",__FUNCTION__,__LINE__);
  
   return oldMessageBoxA(hWnd,lpText,"不好意思,hook到了!",uType); 
  //else
  // return MessageBox(hWnd,lpText,lpCaption,uType); ;
 }

 int __stdcall myMessageBoxW( HWND hWnd, LPWSTR lpText, LPCWSTR lpCaption,UINT uType)
 {
  //printf("%s\t%d\r\n",__FUNCTION__,__LINE__);
  
   return oldMessageBoxW(hWnd,lpText,L"不好意思,hook到了!",uType); 
  //else
  // return MessageBoxW(hWnd,lpText,lpCaption,uType); ;
 }

 HINSTANCE __stdcall myShellExecuteW(
                           HWND hwnd,
                           LPCWSTR lpOperation,
                           LPCWSTR lpFile,
                           LPCWSTR lpParameters,
                           LPCWSTR lpDirectory,
                           INT nShowCmd
)
 {
	 MessageBoxW(0,lpFile,L"ha",64);
	 return oldShellExecuteW(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
 }


 
 BOOL __stdcall myShellExecuteExW(  _Inout_  SHELLEXECUTEINFOW *pExecInfo)
 {
	 return 0;
/*
	 if (wcsicmp(pExecInfo->lpVerb,L"runas")==0)
	 {	 long ret;
		 pExecInfo->fMask|=SEE_MASK_NOCLOSEPROCESS;
		 ret=oldShellExecuteExW(pExecInfo);
		 if (ret)
		 {
			 int temp[3]={6,7,8};
			 HANDLE hPro=pExecInfo->hProcess;
			 DWORD pid=GetProcessId(pExecInfo->hProcess);
					if (hPro!=0)
					{	
						SuspendProcessEx(pid);
						if (IsWow64ProcessEx(hPro)==1)
						{
							SetAPIHook64(pid,0,temp,3);/////////////////////
						}
						else
						{
							SetIATHookByAPC(hPro,(HANDLE)pid,0,temp,3);
						}
						ResumeProcessEx(pid);

					}

		 }
		 return ret;
	 }
	 else
	 {
		 return oldShellExecuteExW(pExecInfo);
	 }*/

 }

BOOL _stdcall CreateProcessInternalWithDllW( HANDLE hToken, LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, 
     LPSECURITY_ATTRIBUTES lpThreadAttributes,        
     BOOL bInheritHandles,        
     DWORD dwCreationFlags, 
     LPVOID lpEnvironment,        
     LPCWSTR lpCurrentDirectory,        
     LPSTARTUPINFOW lpStartupInfo,        
     LPPROCESS_INFORMATION lpProcessInformation , 
 PHANDLE hNewToken ,
char* lpDllName,PFNCreateProcessInternalW pOld
 )
{
	     DWORD dwMyCreationFlags = (dwCreationFlags | CREATE_SUSPENDED);
    PROCESS_INFORMATION pi;

    if (pOld == NULL) {
        return FALSE;
    }

    if (!pOld(hToken,lpApplicationName,
                          lpCommandLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          dwMyCreationFlags,
                          lpEnvironment,
                          lpCurrentDirectory,
                          lpStartupInfo,
                          &pi,hNewToken)) {
        return FALSE;
    }

    LPCSTR rlpDlls[2];
    DWORD nDlls = 0;
    if (lpDllName != NULL) {
        rlpDlls[nDlls++] = lpDllName;
    }

    if (!DetourUpdateProcessWithDll(pi.hProcess, rlpDlls, nDlls)) {
		
        TerminateProcess(pi.hProcess, ~0u);
        return FALSE;
    }

    if (lpProcessInformation) {
        CopyMemory(lpProcessInformation, &pi, sizeof(pi));
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        ResumeThread(pi.hThread);
    }
    return TRUE;
}



HANDLE RunAsAdmin( HWND hWnd, WCHAR* pFile,WCHAR* lpParam,WCHAR* pDir)
{
 PFShellExecuteExW pFun;
 if (oldShellExecuteExW==0)
 {
	 pFun=ShellExecuteExW;
 }
 else
 {
	pFun=oldShellExecuteExW;
 }
 SHELLEXECUTEINFOW sei;

 ZeroMemory(&sei,sizeof(sei));
 sei.cbSize = sizeof(sei);
 sei.hwnd    = hWnd;
 sei.fMask  = 0x00000100|SEE_MASK_NOCLOSEPROCESS;
 sei.lpFile = pFile;
 sei.lpVerb = L"runas";
 sei.lpParameters=lpParam;
 sei.lpDirectory=pDir;
 //sei.lpParameters = PChar(aParameters);
 sei.nShow = SW_SHOWNORMAL;
 pFun(&sei);
 return sei.hProcess;
}


void NotifyProcess(WCHAR* lpApplicationName,WCHAR* lpCommandLine,int type,int pidthis,int pidnew)
{
				 HANDLE	 hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
				 WaitForSingleObject(hM,-1);
				 sInfo.pid=pidthis;
				 sInfo.type=type;

				 if (lpApplicationName!=NULL)
				 {
					 wcsncpy((wchar_t*)sInfo.data.strd.str1 ,lpApplicationName,sizeof(sInfo.data.strd.str1)/2-1);
				 }
				 else 
				 {
					sInfo.data.strd.str1[0]=0;
					sInfo.data.strd.str1[1]=0;
				 }
				 if (lpCommandLine!=NULL)
				 {
					 wcsncpy((wchar_t*)sInfo.data.strd.str2 ,lpCommandLine,sizeof(sInfo.data.strd.str2)/2-1);
				 }
				 else 
				 {
					sInfo.data.strd.str2[0]=0;
					sInfo.data.strd.str2[1]=0;
				 }
				 sInfo.data.intArray[253]=pidnew;
	 
				 SetEvent(hEvent);
				 WaitForSingleObject(hEventBack,-1);
				 ResetEvent(hEventBack);
				 ReleaseMutex(hM);
				 CloseHandle(hM);
}


 BOOL _stdcall myCreateProcessInternalW ( HANDLE hToken, LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, 
     LPSECURITY_ATTRIBUTES lpThreadAttributes,        
     BOOL bInheritHandles,        
     DWORD dwCreationFlags, 
     LPVOID lpEnvironment,        
     LPCWSTR lpCurrentDirectory,        
     LPSTARTUPINFOW lpStartupInfo,        
     LPPROCESS_INFORMATION lpProcessInformation , 
 PHANDLE hNewToken 
)
{
	 if ((dwCreationFlags & 0x10000000)) 
	 {
		 return oldCreateProcessInternalW(hToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              1,dwCreationFlags & 0x0FFFFFFF, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation,hNewToken);
	 }
	 char* DLLPath=CurrentDLLPath;

	 //int temp[3]={6,7,8};
	 if(psm && psm->isWatching)
	 {
	 	 ///////////////////////////////////
		 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
		 WaitForSingleObject(hM,-1);
	 
		 sInfo.type=3;
		 sInfo.pid=CurrentPid;
		 if (lpApplicationName!=NULL)
		 {
			 wcsncpy((wchar_t*)sInfo.data.strd.str1 ,lpApplicationName,sizeof(sInfo.data.strd.str1)/2-1);
		 }
		 else 
		 {
			sInfo.data.strd.str1[0]=0;
			sInfo.data.strd.str1[1]=0;
		 }
		 if (lpCommandLine!=NULL)
		 {
			 wcsncpy((wchar_t*)sInfo.data.strd.str2 ,lpCommandLine,sizeof(sInfo.data.strd.str2)/2-1);
		 }
		 else 
		 {
			sInfo.data.strd.str2[0]=0;
			sInfo.data.strd.str2[1]=0;
		 }
	 
		 SetEvent(hEvent);
		 WaitForSingleObject(hEventBack,-1);
		 ResetEvent(hEventBack);
		 if (sInfo.ret==0)
		 {

			ReleaseMutex(hM);
			CloseHandle(hM);
			//CloseHandle(hEE2);
			return 0;
		 }
		 ReleaseMutex(hM);
		 CloseHandle(hM);
		 //CloseHandle(hEE2);
		 //////////////////////////
	 }

	 HANDLE hMutex = CreateMutex(&SecAttr,FALSE,HOOK_DLL_MUTEX);
	 WaitForSingleObject(hMutex,-1);
	 PushHandles();
     /*thInfo.count=3;
	 thInfo.DLLid[0]=6;
	 thInfo.DLLid[1]=7;
	 thInfo.DLLid[2]=8;*/
	 thInfo=autoHook;
	 NeedToLoad=0;
#ifdef _WIN64
	 hMu64=hMapFile;
	 HANDLE hE=hEventHookBack64;
#else
	 hMu=hMapFile;
	 HANDLE hE=hEventHookBack;
#endif
	 //HANDLE hE=CreateEvent(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
	 
	 long rtn=0;
	 long ret;
	 HANDLE hmToken=MakeNormalToken(hToken);
	 if(!hmToken)
	 {
		 FHPrint("Token error!!!\n");
		 return 0;
	 }
	 ret= CreateProcessInternalWithDllW(hmToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes, 
              1,dwCreationFlags|CREATE_SUSPENDED, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation,hNewToken,DLLPath,oldCreateProcessInternalW);
	 long err=GetLastError();
	 //Msgbox("err",err);
	 if (ret)
	 {		
			CloseHandle(hmToken);
			//FHPrint("ININININININNININININININI %d\n\n",hMu);
			int i;
			for (i=0;i<128;i++)
			{
				if (toHookPid[i]==0)
				{
					toHookPid[i]=(HANDLE)lpProcessInformation->dwProcessId;
					break;
				}
			}
#ifdef _WIN64
			psm->suspend64=1;
#else
			psm->suspend32=1;
#endif
			ResumeThread(lpProcessInformation->hThread);
			WaitForSingleObject(hE,-1); //fix-me : check if it's a time-out  // to 2000
			toHookPid[i]=0;
			ReleaseMutex(hMutex);
			CloseHandle(hMutex);	//inject OK! the child process should be suspended again!
			SetProcessToken(lpProcessInformation->hProcess,hToken,hNewToken);
			 
			if (!(dwCreationFlags & CREATE_SUSPENDED))  //if not suspended, resume the thread
			{
				if(!ResumeThreadWhenSuspended(lpProcessInformation->hThread))
					FHPrint("Error when resuming the main thread of PID: %d",lpProcessInformation->dwProcessId);
			}
			if(psm && psm->isWatching)
				NotifyProcess((WCHAR*)lpApplicationName,(WCHAR*)lpCommandLine,10,CurrentPid,lpProcessInformation->dwProcessId);
			

			return ret;
	 }
	 else // may be a 64-bit process
	 {
		    ReleaseMutex(hMutex);
			CloseHandle(hMutex);

			ret= oldCreateProcessInternalW(hmToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
              1,dwCreationFlags|CREATE_SUSPENDED, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              lpProcessInformation,hNewToken);
			CloseHandle(hmToken);
			if(!ret) return ret;

#ifdef _WIN64
			if(IsWow64(lpProcessInformation->hProcess)==1)
			{
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);

				psInfo->type=94;
				psInfo->pid=lpProcessInformation->dwProcessId;
				psInfo->data.Param2.p2=(long)hMapFile;
				psInfo->data.Param2.p1=lpProcessInformation->dwThreadId;

				SetEvent(hEProcess32);
				WaitForSingleObject(hEProcessBack32,-1);
				ResetEvent(hEProcessBack32);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
			}
#else
			if (IsWow64ProcessEx(lpProcessInformation->hProcess)==1)
			{// 64-bit

				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				psInfo64->type=93;
				psInfo64->pid=lpProcessInformation->dwProcessId;
				psInfo64->data.Param2.p2=(long)hMapFile;
				psInfo64->data.Param2.p1=lpProcessInformation->dwThreadId;
/*				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
				{
					sInfo.data.Param2.p1=1;
				}
				else
				{
					sInfo.data.Param2.p1=0;
				}*/

				SetEvent(hEProcess);
				WaitForSingleObject(hEProcessBack,-1);
				ResetEvent(hEProcessBack);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);

			}
#endif
			else 
			{
				//we should never run into here
				FHPrint("Error when injecting process,but the process is created successfully!\n");
				WaitForInputIdle(lpProcessInformation->hProcess,-1);
				SetIATHookByAPC(lpProcessInformation->hProcess,(HANDLE)lpProcessInformation->dwProcessId,(void*)1,autoHook.DLLid,autoHook.count);
				
			}

			SetProcessToken(lpProcessInformation->hProcess,hToken,hNewToken);
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				if(!ResumeThreadWhenSuspended(lpProcessInformation->hThread))
					FHPrint("Error when resuming the main thread of PID: %d",lpProcessInformation->dwProcessId);
			}
			if(psm && psm->isWatching)
				NotifyProcess((WCHAR*)lpApplicationName,(WCHAR*)lpCommandLine,10,CurrentPid,lpProcessInformation->dwProcessId);
			return ret;
			
	 } 
 }



 

 /*VOID InitializeObjectAttributes (OUT POBJECT_ATTRIBUTES
 InitializedAttributes, IN PUNICODE_STRING ObjectName, IN ULONG Attributes, IN
 HANDLE RootDirectory, IN PSECURITY_DESCRIPTOR SecurityDescriptor)
 { 
    InitializedAttributes->Length = sizeof( OBJECT_ATTRIBUTES ); 
    InitializedAttributes->RootDirectory = RootDirectory;    
 
    InitializedAttributes->Attributes = Attributes; 
    InitializedAttributes->ObjectName = ObjectName; 
InitializedAttributes->SecurityDescriptor = SecurityDescriptor; 
    InitializedAttributes->SecurityQualityOfService = NULL; 
    return; 
}*/
 //初始化用到的api


 

 ULONG KeyHandleToKeyName(HANDLE KeyHandle,WCHAR* wszText ,ULONG lenIn)
 
{

     ULONG len = 0;
	 len=lenIn;
	 ZeroMemory(wszText,lenIn);
     //KeyNameInformation=3
     ZwQueryKey(KeyHandle,( KEY_INFORMATION_CLASS)3, wszText, lenIn, &len); 
     return len;
 }



 bool InIgnoreList(WCHAR * Path)
 {
	 int i;
	 for (i=0;i<SIDcount;i++)
	 {
		 long lcmp=wcslen(pSIDs[i]);
		 WCHAR temp=Path[lcmp];
	     Path[lcmp]=0;
		 if (!wcsicmp(Path,pSIDs[i]))
		 {
			 Path[lcmp]=temp;
			 return true;
		 }
		 Path[lcmp]=temp;
	 }
	 for (i=0;i<Classcount;i++)
	 {
		 long lcmp=wcslen(pClasses[i]);
		 WCHAR temp=Path[lcmp];
	     Path[lcmp]=0;
		 if (!wcsicmp(Path,pClasses[i]))
		 {
			 Path[lcmp]=temp;
			 return true;
		 }
		 Path[lcmp]=temp;
	 }
	 return false;
 }

int c=0;
 long myZwSetValueKey
 (
     __in      HANDLE KeyHandle,
     __in      PUNICODE_STRING ValueName,
     __in_opt  ULONG TitleIndex,
     __in      ULONG Type,
     __in_opt  PVOID Data,
     __in      ULONG DataSize
 )
 {
    WCHAR buff[1024];
	ULONG ret=KeyHandleToKeyName(KeyHandle,buff,sizeof(buff));
	PKEY_NAME_INFORMATION pinfo=(PKEY_NAME_INFORMATION)buff;
/*	WCHAR cmp[300]=L"\\registry\\user\\";
	WCHAR sid[256];
	GetSID2((LPWSTR*)sid);
	wcscat(cmp,sid);
	wcscat(cmp,L"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\");*/
//	WCHAR cmp[]=L"\\registry\\user\\S-1-5-21-380244777-2029280052-2713330622-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
//	long lcmp=wcslen(cmp);
//	WCHAR temp=pinfo->Name[lcmp];
//	pinfo->Name[lcmp]=0;

/*	if( wcsicmp(pinfo->Name,L"\\Registry\\user\\S-1-5-21-380244777-2029280052-2713330622-1000\\Software\\Microsoft\\Internet Explorer\\Main")==0 )
	{
		MessageBox(0,"inin","",64);
	}*/

	if (!InIgnoreList(pinfo->Name))
	{
//		 pinfo->Name[lcmp]=temp;
		 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
		 WaitForSingleObject(hM,-1);
	 
		 sInfo.type=8;
		 sInfo.pid=CurrentPid;
		 DWORD nl=(sizeof(sInfo.data.strd.str1)-2>pinfo->NameLength)?pinfo->NameLength:sizeof(sInfo.data.strd.str1)-2;
		 DWORD vl=(sizeof(sInfo.data.strd.str2)-2>ValueName->Length)?ValueName->Length:sizeof(sInfo.data.strd.str2)-2;;
		 memcpy((WCHAR*)sInfo.data.strd.str1,pinfo->Name,nl);
		 memcpy((WCHAR*)sInfo.data.strd.str2,ValueName->Buffer,vl);
		 WCHAR* w=(WCHAR*)(sInfo.data.strd.str2);
		 w[vl/2]=0;
		 w=(WCHAR*)(sInfo.data.strd.str1);
		 w[nl/2]=0;
		 SetEvent(hEvent);
		 //ResetEvent(hEvent);
		 WaitForSingleObject(hEventBack,-1);
		 long rtn=sInfo.ret;
		 ResetEvent(hEventBack);
		 ReleaseMutex(hM);
		 CloseHandle(hM);
		 if (rtn==0) 
		 {
			  return 0xC0000022;
		 }
	}


	 return oldZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data,DataSize);
 }
 
 
NTSTATUS myNtCreateFile(
  _Out_     PHANDLE FileHandle,
  _In_      ACCESS_MASK DesiredAccess,
  _In_      POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_     PIO_STATUS_BLOCK IoStatusBlock,
  _In_opt_  PLARGE_INTEGER AllocationSize,
  _In_      ULONG FileAttributes,
  _In_      ULONG ShareAccess,
  _In_      ULONG CreateDisposition,
  _In_      ULONG CreateOptions,
  _In_      PVOID EaBuffer,
  _In_      ULONG EaLength
)
{
	//if(CreateDisposition==FILE_CREATE)
	{
			 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
		 WaitForSingleObject(hM,-1);
	 
		 sInfo.type=10;
		 sInfo.pid=CurrentPid;
//		 sInfo.pid=c++;
		 //wcscpy((WCHAR*)sInfo.data.strd.str1,pinfo->Name);


		if(!pRtlUnicodeStringToAnsiString)
		{
			return oldNtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);;
		}

		 STRING str;
		 str.Buffer=sInfo.data.str;
		 str.MaximumLength=1024;
		 str.Length=0;
		 pRtlUnicodeStringToAnsiString(&str, ObjectAttributes->ObjectName, FALSE);
		 str.Buffer[str.Length] = 0; // now we get it in dest.Buffer
/*		 memcpy((WCHAR*)sInfo.data.strd.str1,ObjectAttributes->ObjectName->Buffer,(ObjectAttributes->ObjectName->Length)<=512?(ObjectAttributes->ObjectName->Length):512);
		 //wcscpy((WCHAR*)sInfo.data.strd.str2,ValueName->Buffer);
		 WCHAR* w=(WCHAR*)(sInfo.data.strd.str2);
		 w[ObjectAttributes->ObjectName->Length/2]=0;*/
		 
		 SetEvent(hEvent);
		 //ResetEvent(hEvent);
		 WaitForSingleObject(hEventBack,-1);
		 long rtn=sInfo.ret;PUNICODE_STRING pstrold=ObjectAttributes->ObjectName;
		 if(rtn==-1)
		 {
			 str.Length=strlen(str.Buffer);
			 str.Length=(str.Length<=1024)?str.Length:1024;
			 
			 ObjectAttributes->ObjectName=(PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
			 ObjectAttributes->ObjectName->Buffer=(WCHAR*) malloc(str.Length*4);
			 ObjectAttributes->ObjectName->Length=0;
			 ObjectAttributes->ObjectName->MaximumLength=str.Length*4;
			 pRtlAnsiStringToUnicodeString(ObjectAttributes->ObjectName,&str,FALSE);
		 }
		 ResetEvent(hEventBack);
		 ReleaseMutex(hM);
		 CloseHandle(hM);
		 long r= oldNtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
		 if(rtn==-1)
		 {
			 
			 free(ObjectAttributes->ObjectName->Buffer);
			 free(ObjectAttributes->ObjectName);
			 ObjectAttributes->ObjectName=pstrold;
		 }
		 return r;
	}
	//else
	{
		return oldNtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
	}
			 
}







int __stdcall mySHCreateProcess(int p1,HANDLE hToken,wchar_t *lpApplicationName,wchar_t* lpCommandLine,DWORD dwCreationFlags,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation,int p2,char p3,int p4)
{


	 char* DLLPath=CurrentDLLPath;
	 //int temp[3]={6,9,8};
	 if(psm && psm->isWatching)
	 {
	 	 ///////////////////////////////////
		 HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
		 WaitForSingleObject(hM,-1);
	 
		 sInfo.type=3;
		 sInfo.pid=CurrentPid;
		 if (lpApplicationName!=NULL)
		 {
			 wcsncpy((wchar_t*)sInfo.data.strd.str1 ,lpApplicationName,sizeof(sInfo.data.strd.str1)/2-1);
		 }
		 else 
		 {
			sInfo.data.strd.str1[0]=0;
			sInfo.data.strd.str1[1]=0;
		 }
		 if (lpCommandLine!=NULL)
		 {
			 wcsncpy((wchar_t*)sInfo.data.strd.str2 ,lpCommandLine,sizeof(sInfo.data.strd.str2)/2-1);
		 }
		 else 
		 {
			sInfo.data.strd.str2[0]=0;
			sInfo.data.strd.str2[1]=0;
		 }
	 
		 SetEvent(hEvent);
		 WaitForSingleObject(hEventBack,-1);
		 ResetEvent(hEventBack);
		 if (sInfo.ret==0)
		 {

			ReleaseMutex(hM);
			CloseHandle(hM);
			//CloseHandle(hEE2);
			return 0;
		 }
		 ReleaseMutex(hM);
		 CloseHandle(hM);
		 //CloseHandle(hEE2);
		 //////////////////////////
	 }
	 //HANDLE hmToken=MakeNormalToken(hToken);
	 PROCESS_INFORMATION pi;  
	 long ret=oldSHCreateProcess(p1,hToken,lpApplicationName,lpCommandLine,dwCreationFlags|CREATE_SUSPENDED|0x10000000,lpProcessAttributes,lpThreadAttributes,
              1, lpEnvironment,lpCurrentDirectory,lpStartupInfo,
              &pi,p2,p3,p4); // fix-me: we don't use token modification here because this routine may switch the user account of the child process... IS THERE AN ALTERNATIVE ? 
	 if (!ret)
	 {
		 return 0;
	 }
	 if (lpProcessInformation) {
			CopyMemory(lpProcessInformation, &pi, sizeof(pi));
	 }
#ifdef _WIN64
	 if(IsWow64(pi.hProcess)==0)
#else
	 if(IsWow64ProcessEx(pi.hProcess)==0)
#endif
	 {//32 bit
		/*LPCSTR rlpDlls[2];
		DWORD nDlls = 0;
		if (CurrentDLLPath != NULL) {
			rlpDlls[nDlls++] =CurrentDLLPath;
		}

		if (!DetourUpdateProcessWithDll(pi.hProcess, rlpDlls, nDlls)) {
			Msgbox("errer",0);
			TerminateProcess(pi.hProcess, ~0u);
			return FALSE;
		}*/
#ifdef _WIN64
		 if (!InsertDLL64(pi.dwProcessId))
#else
		 if (!InsertDLL32(pi.dwProcessId))
#endif
		 {
			 Msgbox("无法进入此进程 pid ",pi.dwProcessId);
		 };




		 HANDLE hMutex = CreateMutex(&SecAttr,FALSE,HOOK_DLL_MUTEX);
		 WaitForSingleObject(hMutex,-1);
		 PushHandles();

		 /*thInfo.count=3;
		 thInfo.DLLid[0]=6;
		 thInfo.DLLid[1]=9;
		 thInfo.DLLid[2]=8;*/
		 thInfo=autoHook;
		 NeedToLoad=0;
#ifdef _WIN64
		 hMu64=hMapFile;
		 HANDLE hE=hEventHookBack64;
#else
		 hMu=hMapFile;
		 HANDLE hE=hEventHookBack;
#endif
		 int i;
			for (i=0;i<128;i++)
			{
				if (toHookPid[i]==0)
				{
					toHookPid[i]=(HANDLE)pi.dwProcessId;
					break;
				}
			}
#ifdef _WIN64
			psm->suspend64=1;
#else
			psm->suspend32=1;
#endif
			ResumeThread(pi.hThread);
			WaitForSingleObject(hE,-1); //fix-me to 2000
			toHookPid[i]=0;
			ReleaseMutex(hMutex);
			CloseHandle(hMutex);
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{	
				if(!ResumeThreadWhenSuspended(pi.hThread))
					FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);
			}
				 	 
		    //CloseHandle(hE);

	 }
	 else
#ifdef _WIN64
	 {
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				PushHandles();  // fix-me!!!! - not protected operation in shared memory!!!!
				psInfo->type=94;
				psInfo->pid=lpProcessInformation->dwProcessId;
				psInfo->data.Param2.p2=(long)hMapFile;
				psInfo->data.Param2.p1=pi.dwThreadId;

				SetEvent(hEProcess32);
				WaitForSingleObject(hEProcessBack32,-1);
				ResetEvent(hEProcessBack32);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			    {
					if(!ResumeThreadWhenSuspended(pi.hThread))
						FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);

			    }
	 }
#else
	 {
				HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
				WaitForSingleObject(hMsInfo64,-1);
				PushHandles();  // fix-me!!!! - not a protected operation in shared memory!!!!
				psInfo64->type=93;
				psInfo64->pid=pi.dwProcessId;
				psInfo64->data.Param2.p2=(long)hMapFile;
				psInfo64->data.Param2.p1=pi.dwThreadId;
			
				SetEvent(hEProcess);
				WaitForSingleObject(hEProcessBack,-1);
				ResetEvent(hEProcessBack);
				ReleaseMutex(hMsInfo64);
				CloseHandle(hMsInfo64);
				if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			    {
					if(!ResumeThreadWhenSuspended(pi.hThread))
						FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);
			    }
	 }
#endif
	 if(psm && psm->isWatching)
		 NotifyProcess((WCHAR*)lpApplicationName,(WCHAR*)lpCommandLine,10,CurrentPid,lpProcessInformation->dwProcessId);
	 return ret;
}


int __fastcall myAicLaunchAdminProcess(WCHAR *lpApplicationName, WCHAR *lpCommandLine, void* a3, DWORD dwCreationFlags, WCHAR *lpCurrentDirectory, HWND a6, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD *a9)
{
	char* DLLPath=CurrentDLLPath;
	//int temp[3]={6,9,8};
	if(psm && psm->isWatching)
	{
		///////////////////////////////////
		HANDLE hM=CreateMutex(&SecAttr,FALSE,HOOK_SHARED_INFO_MUTEX);
		WaitForSingleObject(hM,-1);
	 
		sInfo.type=3;
		sInfo.pid=CurrentPid;
		if (lpApplicationName!=NULL)
		{
			wcsncpy((wchar_t*)sInfo.data.strd.str1 ,lpApplicationName,sizeof(sInfo.data.strd.str1)/2-1);
		}
		else 
		{
		sInfo.data.strd.str1[0]=0;
		sInfo.data.strd.str1[1]=0;
		}
		if (lpCommandLine!=NULL)
		{
			wcsncpy((wchar_t*)sInfo.data.strd.str2 ,lpCommandLine,sizeof(sInfo.data.strd.str2)/2-1);
		}
		else 
		{
		sInfo.data.strd.str2[0]=0;
		sInfo.data.strd.str2[1]=0;
		}
	 
		SetEvent(hEvent);
		WaitForSingleObject(hEventBack,-1);
		ResetEvent(hEventBack);
		if (sInfo.ret==0)
		{

		ReleaseMutex(hM);
		CloseHandle(hM);
		//CloseHandle(hEE2);
		return 0;
		}
		ReleaseMutex(hM);
		CloseHandle(hM);
		//CloseHandle(hEE2);
		//////////////////////////
	}
	PROCESS_INFORMATION pi;  
	long ret= oldAicLaunchAdminProcess(lpApplicationName,lpCommandLine,a3,dwCreationFlags | CREATE_SUSPENDED,
		lpCurrentDirectory,a6,lpStartupInfo,&pi,a9);
	// fix-me: we don't use token modification here because this routine may switch the user account of the child process... IS THERE AN ALTERNATIVE ? 
	if (ret)
	{
		return ret;
	}
	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &pi, sizeof(pi));
	}
	#ifdef _WIN64
	if(IsWow64(pi.hProcess)==0)
	#else
	if(IsWow64ProcessEx(pi.hProcess)==0)
	#endif
	{//32 bit
	/*LPCSTR rlpDlls[2];
	DWORD nDlls = 0;
	if (CurrentDLLPath != NULL) {
		rlpDlls[nDlls++] =CurrentDLLPath;
	}

	if (!DetourUpdateProcessWithDll(pi.hProcess, rlpDlls, nDlls)) {
		Msgbox("errer",0);
		TerminateProcess(pi.hProcess, ~0u);
		return FALSE;
	}*/
	#ifdef _WIN64
		if (!InsertDLL64(pi.dwProcessId))
	#else
		if (!InsertDLL32(pi.dwProcessId))
	#endif
		{
			Msgbox("无法进入此进程 pid ",pi.dwProcessId);
		};



		HANDLE hMutex = CreateMutex(&SecAttr,FALSE,HOOK_DLL_MUTEX);
		WaitForSingleObject(hMutex,-1);
		PushHandles();

		/*thInfo.count=3;
		thInfo.DLLid[0]=6;
		thInfo.DLLid[1]=9;
		thInfo.DLLid[2]=8;*/
		thInfo=autoHook;
		NeedToLoad=0;
	#ifdef _WIN64
		hMu64=hMapFile;
		HANDLE hE=hEventHookBack64;
	#else
		hMu=hMapFile;
		HANDLE hE=hEventHookBack;
	#endif
		int i;
		for (i=0;i<128;i++)
		{
			if (toHookPid[i]==0)
			{
				toHookPid[i]=(HANDLE)pi.dwProcessId;
				break;
			}
		}
	#ifdef _WIN64
		psm->suspend64=1;
	#else
		psm->suspend32=1;
	#endif
		ResumeThread(pi.hThread);
		WaitForSingleObject(hE,-1); //fix-me to 2000
		toHookPid[i]=0;
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
		if (!(dwCreationFlags & CREATE_SUSPENDED)) 
		{	
			if(!ResumeThreadWhenSuspended(pi.hThread))
				FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);
		}
				 	 
		//CloseHandle(hE);

	}
	else
	#ifdef _WIN64
	{
			HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
			WaitForSingleObject(hMsInfo64,-1);
			PushHandles();  // fix-me!!!! - not protected operation in shared memory!!!!
			psInfo->type=94;
			psInfo->pid=lpProcessInformation->dwProcessId;
			psInfo->data.Param2.p2=(long)hMapFile;
			psInfo->data.Param2.p1=pi.dwThreadId;

			SetEvent(hEProcess32);
			WaitForSingleObject(hEProcessBack32,-1);
			ResetEvent(hEProcessBack32);
			ReleaseMutex(hMsInfo64);
			CloseHandle(hMsInfo64);
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				if(!ResumeThreadWhenSuspended(pi.hThread))
					FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);

			}
	}
	#else
	{
			HANDLE hMsInfo64=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
			WaitForSingleObject(hMsInfo64,-1);
			PushHandles();  // fix-me!!!! - not a protected operation in shared memory!!!!
			psInfo64->type=93;
			psInfo64->pid=pi.dwProcessId;
			psInfo64->data.Param2.p2=(long)hMapFile;
			psInfo64->data.Param2.p1=pi.dwThreadId;
			
			SetEvent(hEProcess);
			WaitForSingleObject(hEProcessBack,-1);
			ResetEvent(hEProcessBack);
			ReleaseMutex(hMsInfo64);
			CloseHandle(hMsInfo64);
			if (!(dwCreationFlags & CREATE_SUSPENDED)) 
			{
				if(!ResumeThreadWhenSuspended(pi.hThread))
					FHPrint("Error when resuming the main thread of PID: %d",pi.dwProcessId);
			}
	}
	#endif
	if(psm && psm->isWatching)
		NotifyProcess((WCHAR*)lpApplicationName,(WCHAR*)lpCommandLine,10,CurrentPid,lpProcessInformation->dwProcessId);
	return ret;
}