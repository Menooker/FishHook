#include "Def.h"

#define FH_TOKEN_ERROR 2
#define FH_CREATE_PROCESS_ERROR 3

MYLIBAPI long __stdcall GetDebugerPid(long* p32,long* p64);
MYLIBAPI long FHPrint(char *format,...);
MYLIBAPI void* __stdcall GetSharedInfo();
MYLIBAPI void* __stdcall GetCustomSharedMemory();

MYLIBAPI long __stdcall CreateSyncBlock(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo,OUT SyncBlock* psb);
MYLIBAPI HANDLE __stdcall EnterSharedMemory(SyncBlock* psb);
MYLIBAPI long __stdcall LeaveSharedMemory(HANDLE hM,SyncBlock* psb);
MYLIBAPI long __stdcall CallFilter(SyncBlock* psb);
MYLIBAPI long __stdcall CreateFilterPort(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo);
MYLIBAPI long __stdcall CreateNormalProcess(WCHAR* path,HANDLE* pProcess);
MYLIBAPI long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void * callproc,FishHookTypes *pDLLid,long num);
MYLIBAPI long __stdcall SetAPIHook64(long pid,long callproc,FishHookTypes *pDLLid,long num);
MYLIBAPI BOOL __stdcall IsWow64ProcessEx(HANDLE hProcess);
MYLIBAPI void __stdcall InitFishHook();
#ifdef _WIN64
MYLIBAPI  void CALLBACK DLLEntry(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine,int nCmdShow);
#endif
MYLIBAPI  void CALLBACK GetAddressProc(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine,int nCmdShow);