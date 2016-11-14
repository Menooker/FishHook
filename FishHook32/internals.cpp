#include "StdAfx.h"
#include <stdlib.h>
#include <Windows.h>
#include <stdio.h>
#include "var.h"
#include "internals.h"
#include <Sddl.h>

ptDbgPrint DbgPrint=(ptDbgPrint)GetProcAddress(GetModuleHandleW(L"ntdll"),"DbgPrint");
extern "C" long FHPrint(char *format,...);

typedef HMODULE (WINAPI *ptGetModuleHandleW)(
    __in_opt LPCWSTR lpModuleName
    );

typedef FARPROC (WINAPI *ptGetProcAddress)(
    __in HMODULE hModule,
    __in LPCSTR lpProcName
    );
typedef BOOL
(WINAPI
*ptFreeLibrary) (
    __in HMODULE hLibModule
    );

typedef VOID
(WINAPI
*ptExitThread)(
    __in DWORD dwExitCode
    );

typedef HGLOBAL (WINAPI *ptGlobalAlloc)(
  _In_  UINT uFlags,
  _In_  SIZE_T dwBytes
);

typedef HGLOBAL
(WINAPI *ptGlobalFree)(
    __deref HGLOBAL hMem
    );

struct myEnvir
{
	ptGetProcAddress GetProcAddress;
	ptFreeLibrary FreeLibrary;
	ptExitThread ExitThread;
	ptGlobalFree GlobalFree;
} ;

long __stdcall  DoTrulyUnloadDLLAndExitThread(myEnvir* par,HMODULE hmod,DWORD exitcode,void* pcode)
{
	
	BOOL ret=1;
	//ptFreeLibrary PFreeLibrary=(ptFreeLibrary)par->GetProcAddress(par->hmodkernel,par->pfree);
	// PExitThread=(ptExitThread)par->GetProcAddress(par->hmodkernel,par->pexit);
	while(ret)
	{

		ret=par->FreeLibrary(hmod);
	}
#ifdef _WIN64
	typedef void (*ptShellcode)(void* pcode,void* pexit,void* pfree);
	ptShellcode pFun=(ptShellcode)((char*)pcode+200);
	pFun(pcode,par->ExitThread,par->GlobalFree);
#else
	void* pExit=par->ExitThread;
	void* pFree=par->GlobalFree;
	__asm{
		push exitcode
		push 0
		push pcode
		push pExit
		jmp pFree
	}
#endif
	return 0;
}


#ifdef _WIN64
void __stdcall TrulyUnloadDLLAndExitThread(HMODULE hmod,DWORD exitcode)
{

UCHAR shellcode[10]=

"\x48\x83\xEC\x28" //4
"\x52"             //5
"\x41\xFF\xE0";    //8          
	void* p=(BYTE*)GlobalAlloc(GMEM_FIXED,300);
	memset(p,0xcc,300);
	memcpy(p,DoTrulyUnloadDLLAndExitThread,200);
	memcpy((char*)p+200,shellcode,sizeof(shellcode));
	DWORD oldpro;
	VirtualProtect(p,300,PAGE_EXECUTE_READWRITE,&oldpro);	
	typedef long (__stdcall *ptFun)(myEnvir* par,HMODULE hmod,DWORD exitcode,void* pcode);
	ptFun pFun=(ptFun)p;
	myEnvir par={GetProcAddress,FreeLibrary,ExitThread,GlobalFree};
	
	pFun(&par,hmod,exitcode,p);
}

void PopHandles()
{
			if (hEvent32==0) hEvent32=(HANDLE)psm->handle32.hEvent;
			if (hEventBack32==0)hEventBack32=(HANDLE)psm->handle32.hEventBack;
			if (hEvent==0) hEvent=(HANDLE)psm->handle32.hEvent64;
			if (hEventBack==0)hEventBack=(HANDLE)psm->handle32.hEventBack64;	
			if (hEProcess==0) hEProcess=(HANDLE)psm->handle32.hEProcess;
			if (hEProcessBack==0)hEProcessBack=(HANDLE)psm->handle32.hEProcessBack;
			if (hEProcess32==0) hEProcess32=(HANDLE)psm->handle32.hEProcess32;
			if (hEProcessBack32==0)hEProcessBack32=(HANDLE)psm->handle32.hEProcessBack32;
			if (hEventRelease==0)hEventRelease=(HANDLE)psm->handle32.hEventRelease;
			if (hEventOutput==0)hEventOutput=(HANDLE)psm->handle32.hEventOutput;
			if (hEventHookBack32==0)hEventHookBack32=(HANDLE)psm->handle32.hEventHookBack32;
			if (hEventHookBack64==0)hEventHookBack64=(HANDLE)psm->handle32.hEventHookBack64;
}

void PushHandles()
{
				psm->handle32.hEProcess=(long)hEProcess; psm->handle32.hEProcess32=(long)hEProcess32; psm->handle32.hEProcessBack=(long)hEProcessBack;
				psm->handle32.hEProcessBack32=(long)hEProcessBack32; psm->handle32.hEvent=(long)hEvent32; psm->handle32.hEvent64=(long)hEvent;
				psm->handle32.hEventBack=(long)hEventBack32; psm->handle32.hEventBack64=(long)hEventBack; psm->handle32.hEventOutput=(long)hEventOutput;
				psm->handle32.hEventRelease=(long)hEventRelease; psm->handle32.hEventHookBack32=(long)hEventHookBack32;
				psm->handle32.hEventHookBack64=(long)hEventHookBack64; 
}

#else

void __stdcall TrulyUnloadDLLAndExitThread(HMODULE hmod,DWORD exitcode)
{

                
	void* p=(BYTE*)GlobalAlloc(GMEM_FIXED,200);
	memcpy(p,DoTrulyUnloadDLLAndExitThread,200);
	DWORD oldpro;
	VirtualProtect(p,100,PAGE_EXECUTE_READWRITE,&oldpro);	
	typedef long (__stdcall *ptFun)(myEnvir* par,HMODULE hmod,DWORD exitcode,void* pcode);
	ptFun pFun=(ptFun)p;
	myEnvir par={GetProcAddress,FreeLibrary,ExitThread,GlobalFree};
	
	pFun(&par,hmod,exitcode,p);
}

void PopHandles()
{
			if (hEvent==0) hEvent=psm->handle32.hEvent;
			if (hEventBack==0)hEventBack=psm->handle32.hEventBack;
			if (hEvent64==0) hEvent64=psm->handle32.hEvent64;
			if (hEventBack64==0)hEventBack64=psm->handle32.hEventBack64;	
			if (hEProcess==0) hEProcess=psm->handle32.hEProcess;
			if (hEProcessBack==0)hEProcessBack=psm->handle32.hEProcessBack;
			if (hEProcess32==0) hEProcess32=psm->handle32.hEProcess32;
			if (hEProcessBack32==0)hEProcessBack32=psm->handle32.hEProcessBack32;
			if (hEventRelease==0)hEventRelease=psm->handle32.hEventRelease;
			if (hEventOutput==0)hEventOutput=psm->handle32.hEventOutput;
			if (hEventHookBack==0)hEventHookBack=psm->handle32.hEventHookBack32;
			if (hEventHookBack64==0)hEventHookBack64=psm->handle32.hEventHookBack64;
}

void PushHandles()
{
				psm->handle32.hEProcess=hEProcess; psm->handle32.hEProcess32=hEProcess32; psm->handle32.hEProcessBack=hEProcessBack;
				psm->handle32.hEProcessBack32=hEProcessBack32; psm->handle32.hEvent=hEvent; psm->handle32.hEvent64=hEvent64;
				psm->handle32.hEventBack=hEventBack; psm->handle32.hEventBack64=hEventBack64; psm->handle32.hEventOutput=hEventOutput;
				psm->handle32.hEventRelease=hEventRelease; psm->handle32.hEventHookBack32=hEventHookBack;
				psm->handle32.hEventHookBack64=hEventHookBack64; 
}

#endif
void __stdcall MsgboxW(WCHAR* str,long a)
{
	char p[255];

	sprintf(p,"%ws : %d",str,a);
	MessageBox(NULL,p,"hh",64);
}

void __stdcall Msgbox(char* str,long a)
{
	char p[255];

	sprintf(p,"%s : %d",str,a);
	MessageBox(NULL,p,str,64);
}





void ShowSID(HANDLE hNewt)
{
			WCHAR pbuf[1000]={0};
			LPWSTR psid=0;
			TOKEN_MANDATORY_LABEL* pp=(TOKEN_MANDATORY_LABEL* )pbuf;
			DWORD len;
			if(GetTokenInformation(hNewt,TokenIntegrityLevel ,pbuf,1000,&len))
			{
				if(ConvertSidToStringSidW(pp->Label.Sid,&psid))
					MessageBoxW(0,psid,L"",64);
				else
					Msgbox("CON",GetLastError());
			}
}

HANDLE MakeNormalToken(HANDLE hToken)
{
	 //HANDLE hToken;
	
	 WCHAR wszIntegritySid[20] = L"S-1-16-8192";
	 PSID pIntegritySid = NULL;
	 TOKEN_MANDATORY_LABEL TIL = {0};
	 HANDLE hmNewToken;
     if (OpenProcessToken(GetCurrentProcess(),MAXIMUM_ALLOWED, &hToken))
     {

         if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,SecurityImpersonation, TokenPrimary, &hmNewToken))
         { 
              if (ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid))
              {
				  //Msgbox("TOKEN",(long)hToken);
                  TIL.Label.Attributes = SE_GROUP_INTEGRITY;
                  TIL.Label.Sid = pIntegritySid;
                   // Set the process integrity level
                   if (SetTokenInformation(hmNewToken, TokenIntegrityLevel, &TIL,
                       sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid)))
                   {
					   CloseHandle(hToken);
					   return hmNewToken;
				   }
			  }
		 }
	 }
	 CloseHandle(hToken);
	 CloseHandle(hmNewToken);
	 return 0;
}

BOOL CopyToken(HANDLE hsrc,HANDLE hdest)
{
	//ShowSID(hsrc);
	DWORD len;
	PVOID pbuf=malloc(2000);
	for(int i=1;i<MaxTokenInfoClass;i++)
	{
		if(GetTokenInformation(hsrc,(TOKEN_INFORMATION_CLASS)i ,pbuf,2000,&len))
		{	
			//Msgbox("i",i);
			if(!SetTokenInformation(hdest,(TOKEN_INFORMATION_CLASS)i,pbuf,len))
			{
				//Msgbox("ERR",GetLastError());
				continue;
			}
		}

	}
	free(pbuf);

	return 1;
}

void SetProcessToken(HANDLE hProcess,HANDLE hToken,HANDLE* hNewToken)
{
	HANDLE hNewt;
			if(OpenProcessToken(hProcess,MAXIMUM_ALLOWED,&hNewt)) // now copy the token
			{
				CopyToken(hToken,hNewt); //fix-me: is it right to copy the token like this?????
				if(hNewToken)
				{
					CloseHandle(*hNewToken); //fix-me: should we close the old token?????
					*hNewToken=hNewt;
				}
				else{
					CloseHandle(hNewt);
				}
			}
			else{
				FHPrint("Failed to load token\n");
			}
}



LPCWSTR LOW_INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;LW)";

bool SetObjectToLowIntegrity(
 HANDLE hObject, SE_OBJECT_TYPE type )
{
bool bRet = false;
DWORD dwErr = ERROR_SUCCESS;
PSECURITY_DESCRIPTOR pSD = NULL;
PACL pSacl = NULL;
BOOL fSaclPresent = FALSE;
BOOL fSaclDefaulted = FALSE;
 if ( ConvertStringSecurityDescriptorToSecurityDescriptorW (
         LOW_INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL ) )
    {
    if ( GetSecurityDescriptorSacl (

           pSD, &fSaclPresent, &pSacl, &fSaclDefaulted ) )

      {
      dwErr = SetSecurityInfo (
                hObject, type, LABEL_SECURITY_INFORMATION,
                NULL, NULL, NULL, pSacl );
      bRet = (ERROR_SUCCESS == dwErr);
      }
    LocalFree ( pSD );
    }
 return bRet;
}


BOOL ResumeThreadWhenSuspended(HANDLE hThread)
{
				  int rcnt;
				  for (rcnt=0;rcnt<1000;rcnt++)
				  {
					  if(ResumeThread(hThread))
					  {
						  break;
					  }
					  Sleep(0);
				  }
				  if(rcnt==1000)
				  {
					  return FALSE;
				  }
				  return TRUE;
}
/*
// A few required typedefs

typedef enum _PROCESS_INFORMATION_CLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;

typedef struct _PROCESS_ACCESS_TOKEN
{
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef NTSTATUS (NTAPI * NtSetInformationProcess) (HANDLE processHandle, PROCESS_INFORMATION_CLASS infoClass, PVOID info, ULONG infoLength);


// Assume we have a handle to an existing process: targetProcessHandle, started in a suspended state, and a new token: newToken to assign to this process.

// First we must enable SeAssignPrimaryTokenPrivilege.
// Note: The user under which this runs must already hold the privilege, this only enables it (it is initially disabled by default).
LUID luid;
LookupPrivilegeValue(0, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
TOKEN_PRIVILEGES privs;
privs.PrivilegeCount = 1;
privs.Privileges[0].Luid = luid;
privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

HANDLE myToken;
if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &myToken))
{
    wprintf("Unable to open own process token to enable permissions\n");
    return FALSE;
}
if (!AdjustTokenPrivileges(myToken, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), 0, 0))
{
    wprintf("Error setting token privileges: 0x%08x\n", GetLastError());
    CloseHandle(myToken);
    return FALSE;
}
// Even if AdjustTokenPrivileges returns TRUE, it may not have succeeded, check last error top confirm
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
{
    wprintf("Unable to enable a required privilege\n");
    CloseHandle(myToken);
    return FALSE;
}
CloseHandle(myToken);

PROCESS_ACCESS_TOKEN tokenInfo;
tokenInfo.Token = newToken;
tokenInfo.Thread = 0;

// Get a handle to ntdll
HMODULE ntdll = LoadLibrary(L"ntdll.dll");

// And a pointer to the NtSetInformationProcess function
NtSetInformationProcess setInfo = (NtSetInformationProcess)GetProcAddress(ntdll,"NtSetInformationProcess");
NTSTATUS setInfoResult = setInfo(targetProcessHandle, ProcessAccessToken, &tokenInfo, sizeof(PROCESS_ACCESS_TOKEN));
if (setInfoResult < 0)
{
    wprintf(L"Error setting token: 0x%08x\n", setInfoResult);
    return FALSE;
}

FreeLibrary(ntdll);

// You can now resume the target process' main thread here using ResumeThread().
//http://stackoverflow.com/questions/5141997/is-there-a-way-to-set-a-token-for-another-process
return TRUE;*/