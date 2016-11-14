#ifndef _FISHHOOK_INTERNALS
#define _FISHHOOK_INTERNALS

 #include <aclapi.h>
#include <Windows.h>
void __stdcall TrulyUnloadDLLAndExitThread(HMODULE hmod,DWORD exitcode);
void __stdcall MsgboxW(WCHAR* str,long a);
void PopHandles();
void PushHandles();
BOOL ResumeThreadWhenSuspended(HANDLE hThread);
void ShowSID(HANDLE hNewt);
HANDLE MakeNormalToken(HANDLE hToken);
BOOL CopyToken(HANDLE hsrc,HANDLE hdest);
void SetProcessToken(HANDLE hProcess,HANDLE hToken,HANDLE* hNewToken);
bool SetObjectToLowIntegrity(
 HANDLE hObject, SE_OBJECT_TYPE type = SE_KERNEL_OBJECT);
typedef NTSTATUS( NTAPI *ptDbgPrint)(
  IN LPCSTR               Format,
  ... );
extern ptDbgPrint DbgPrint ;

#endif