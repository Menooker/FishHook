#include "Def.h"

#define FH_TOKEN_ERROR 2
#define FH_CREATE_PROCESS_ERROR 3

MYLIBAPI long __stdcall GetDebugerPid(long* p32,long* p64);
MYLIBAPI long FHPrint(char *format,...);
MYLIBAPI long __stdcall GetSharedInfo();
MYLIBAPI void* __stdcall GetCustomSharedMemory();

MYLIBAPI long __stdcall CreateSyncBlock(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo,OUT SyncBlock* psb);
MYLIBAPI HANDLE __stdcall EnterSharedMemory(SyncBlock* psb);
MYLIBAPI long __stdcall LeaveSharedMemory(HANDLE hM,SyncBlock* psb);
MYLIBAPI long __stdcall CallFilter(SyncBlock* psb);
MYLIBAPI long __stdcall CreateFilterPort(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo);
MYLIBAPI long __stdcall CreateNormalProcess(WCHAR* path,HANDLE* pProcess);
