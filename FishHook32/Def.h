#ifndef _H_DEF
#define _H_DEF

#include <windows.h>
#include <ShellAPI.h>

#include<detours.h>
#ifdef _WIN64
#pragma comment(lib, "detours64.lib")  
#else
#pragma comment(lib, "detours.lib")  
#endif
#define REGDLLNUM 11
#define CHOOK_NUM 10



#ifndef MYLIBAPI
#define MYLIBAPI extern "C"__declspec(dllimport)
#endif



struct DllFunctionContext
{
    long Unknown;
    long ModuleHandle;
    PVOID FunctionPtr;
};


struct DLLHookInfo
{
	char ModName[MAX_PATH];
	char ProcName[MAX_PATH];
	PVOID pProc;
	void **ppOld;
};

struct CustomHookInfo
{
	void* pNew;
	void* pOld;
	HMODULE hMod;
};

struct DLLInfo
{
char* ModuleName;char* FunctionName;long Unknown;PVOID ContextPtr;
};




struct SharedInfo
{
	int type;
	int pid;
	int ret;
	union data
	{
		char str[1024];
		struct strlong
		{
			char str1[511];
			long p1;
		}strlong;
		struct strd
		{
			char str1[512];
			char str2[512];
		}strd;
        struct Param2
		{
			long p1;
			long p2;
		}Param2;
		int intArray[255];

	}data;
	
};

 struct ToHookInfo
 {
	 int count;
	 int DLLid[20];
 };

 struct CustomHook/*10-25 new*/
 {
	 char oldName[40];
	 char oldMod[MAX_PATH];
	 char newName[40];
	 char newMod[MAX_PATH];
	 char oldProcAddr[40];
 };
 

struct InheritedHandles32
{
#ifdef _WIN64
#define MHANDLE long
#else
#define MHANDLE HANDLE
#endif
	MHANDLE hEvent;
	MHANDLE hEventBack;
	MHANDLE hEvent64;
	MHANDLE hEventBack64;
	MHANDLE hEProcess;
	MHANDLE hEProcessBack;
	MHANDLE hEProcess32;
	MHANDLE hEProcessBack32;
	MHANDLE hEventRelease;
	MHANDLE hEventOutput;
	MHANDLE hEventHookBack32;
	MHANDLE hEventHookBack64;
#undef MHANDLE
};

struct SharedMemory3264
{
	SharedInfo si;
	CustomHook ch[CHOOK_NUM];
	CustomHook ch64[CHOOK_NUM];
	long DebugerPid;
	long DebugerPid64;
	long isWatching;
	char PrintBuf[500];
	InheritedHandles32 handle32;
	long suspend64;
	long suspend32;
	char CustomBuf[1024+sizeof(SharedInfo)];
};


struct SyncBlock{
	HANDLE hEvent;
	HANDLE hEventBack;
	WCHAR* lpMutex;
	SharedInfo* psinfo;
};


 //typedef
typedef void (__stdcall *ptOutputProc)(char*);
typedef long (__stdcall *ptrGetAddr)(HMODULE hModule,LPCSTR lpProcName );
typedef long (__stdcall *ptrDllCall)(DLLInfo *);
 typedef long( __stdcall *_vbaStrCmp)(PVOID str1,PVOID str2);
 typedef int (__stdcall *OLD_MessageBox)( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption,UINT uType );
 typedef int (__stdcall *OLD_MessageBoxW)( HWND hWnd, PWCHAR lpwText, LPCWSTR lpCaption,UINT uType );
 typedef BOOL (_stdcall *PFNCreateProcessInternalW) 
 ( 
HANDLE hToken, LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, 
     LPSECURITY_ATTRIBUTES lpThreadAttributes,        
     BOOL bInheritHandles,        
     DWORD dwCreationFlags, 
     LPVOID lpEnvironment,        
     LPCWSTR lpCurrentDirectory,        
     LPSTARTUPINFOW lpStartupInfo,        
     LPPROCESS_INFORMATION lpProcessInformation , 
 PHANDLE hNewToken 
 ); 

typedef  BOOL (__stdcall *PFShellExecuteExW)(  _Inout_  SHELLEXECUTEINFOW *pExecInfo);
typedef  int (__stdcall *PSHCreateProcess)(int p1,HANDLE hToken,wchar_t *lpApplicationName,wchar_t * lpCommandLine,DWORD dwCreationFlags,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation,int p2,char p3,int p4);

//pointers
#endif