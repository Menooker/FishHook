#ifndef _H_VAR
#define _H_VAR

#include "def.h"
#include "NativeApi.h"

extern void Logn(char* x, long y);
extern HANDLE hMod;
extern HHOOK hhook;

extern HANDLE hEvent;
extern HANDLE hEventBack;
#ifdef _WIN64
	extern HANDLE hEvent32;
	extern HANDLE hEventBack32;
	extern HANDLE hEProcess;
	extern HANDLE hEProcessBack;
	extern HANDLE hEventOutput;
	extern HANDLE hMu64;
#else
	extern HANDLE hEvent64;
	extern HANDLE hEventBack64;
	extern HANDLE hMu;
#endif
extern HANDLE hEventOutput;
//HANDLE hMsInfo64=0;
//HANDLE hMhook64=0;
extern HANDLE hEProcess;
extern HANDLE hEProcessBack;
extern HANDLE hEProcess32;
extern HANDLE hEProcessBack32;
extern HANDLE hEventRelease;
#ifdef _WIN64
	extern HANDLE hEventHookBack32;
	extern DWORD CurrentPid;
	extern SECURITY_ATTRIBUTES SecAttr;  
	extern SECURITY_DESCRIPTOR SecDesc;  
#else
	extern HANDLE hEventHookBack;
#endif

extern HANDLE hEventHookBack64;
extern long breakpoint;
extern HANDLE hMapFile;
extern char CurrentDLLPath[255];
extern SharedInfo* psInfo64;
extern SharedInfo sInfo;
extern PSHCreateProcess pSHCreateProcess;
extern SharedMemory3264* psm;
extern ToHookInfo autoHook;
extern ToHookInfo thInfo;
extern HANDLE toHookPid[128];
extern long NeedToLoad;
extern SECURITY_ATTRIBUTES SecAttr;  
extern SECURITY_DESCRIPTOR SecDesc;  
extern DWORD CurrentPid;
//extern RTLINITUNICODESTRING RtlInitUnicodeString;
extern LONG (WINAPI *pRtlUnicodeStringToAnsiString)(PVOID, PVOID, BOOL);
extern NTSTATUS (WINAPI * pRtlAnsiStringToUnicodeString)(PVOID,PVOID,BOOL);
extern ZWSETVALUEKEY ZwSetValueKey;
extern ZWOPENKEY ZwOpenKey;
extern ZWCLOSE ZwClose;
extern ZWQUERYKEY ZwQueryKey;

extern HANDLE hMapFile;
extern WCHAR *pClasses[];
extern WCHAR *pSIDs[];
extern int Classcount;
extern int SIDcount;
extern char* PrintBuf;

#endif