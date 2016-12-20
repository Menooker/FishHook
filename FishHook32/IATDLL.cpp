// IATDLL.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "NativeApi.h"
#include <stdio.h>
#include "Def.h"
#include "apc.h"
#include "HookedFunctions.h"
#include <malloc.h>
#include <Sddl.h>
#include <lm.h>
#include "internals.h"
#include "exports.h"
#include <stdlib.h>
//#include "var.h"
//#include "hi.h"

//#include "iathookheader.h"

#ifdef _WIN64
SharedInfo* psInfo=0;
#endif

#pragma data_seg (".myseg")
#ifndef _WIN64
	#pragma comment(linker,"/export:_SetAPIHook32@20=_SetIATHookByAPC@20")
	#pragma comment(linker,"/export:GetAddressProc=_GetAddressProc@16")
	SharedInfo sInfo={0};
	HANDLE hMu=0;
#else
	HANDLE hMu64=0;
#endif

long MAGIC1=1234567890;
ToHookInfo autoHook={0};
ToHookInfo thInfo={0};
long MAGIC2=1234567891;
HANDLE toHookPid[128]={0};
long NeedToLoad=0;
long IsDebugerExist=0;
PSHCreateProcess SHCreateProcess=0;

WCHAR SID0[MAX_PATH]={0};
WCHAR SID1[MAX_PATH]={0};
WCHAR SID2[MAX_PATH]={0};
WCHAR SID3[MAX_PATH]={0};
WCHAR SID4[MAX_PATH]={0};


WCHAR Classes0[MAX_PATH]={0};
WCHAR Classes1[MAX_PATH]={0};

int Classcount=0;
int SIDcount=0;
size_t AicLaunchAdminProcess_offset=0;

#pragma data_seg()
#pragma comment(linker,"/section:.myseg,rws")
#pragma comment(lib,"Netapi32.lib")

WCHAR *pSIDs[]={SID0,SID1,SID2,SID3,SID4};
WCHAR *pClasses[]={Classes0,Classes1};
 PSHCreateProcess pSHCreateProcess=0;
 PAicLaunchAdminProcess pAicLaunchAdminProcess=0;
CustomHook* customHooks;/*10-25 new*/
CustomHook* customHooks64;/*10-25 new*/
//functions
extern int  HookIt(const char *pDllName,const char *pApiName,void *pNew,PVOID * pOld);
void __stdcall Msgbox(char* str,long a);
DWORD WINAPI ReleaseHookProc (LPVOID lpParam);
extern long Hook(void ** ppOld,PVOID pNew);
extern int __stdcall myCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
//exports
MYLIBAPI  long __stdcall SetIATHook(HANDLE PID,long,void*,FishHookTypes);

MYLIBAPI long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void* callproc,FishHookTypes *pDLLid,long num);
MYLIBAPI long __stdcall ResumeProcessEx(long pid);
MYLIBAPI long __stdcall SuspendProcessEx(long pid);
#ifdef _WIN64
	MYLIBAPI  void* __stdcall GetSharedInfo();
	MYLIBAPI  HANDLE __stdcall StartListening();
	MYLIBAPI long FHPrint(char *format,...);
#else
	MYLIBAPI  long __stdcall SetAPIHook64(long pid,long callproc,FishHookTypes *pDLLid,long num);
	MYLIBAPI HANDLE __stdcall ListenOutput(ptOutputProc p);
	MYLIBAPI BOOL __stdcall IsWow64ProcessEx(HANDLE hProcess);
	MYLIBAPI long __stdcall SetCustomHook(char* oldName,char* oldMod, char* newName, char* newMod, char* oldProcAddr,long is64); /*10-25 new*/
	MYLIBAPI long __stdcall ResetCustomHook(long id,long is64);/*10-25 new*/	
#endif



/*
struct InjectInfo
{
	char DLLName[100]={0};
	char FuncName[100]={0};
}
*/
CustomHookInfo customhookinfo[CHOOK_NUM]={0};
long (__stdcall *CallBackProc)(SharedInfo*)=0;
SharedMemory3264* psm=0;
SharedInfo* psInfo64=0;
HANDLE hProcess64=0;
bool Status=0;
HANDLE hMod;
HHOOK hhook;
HANDLE hEvent=0;
HANDLE hEventBack=0;
#ifndef _WIN64
HANDLE hEvent64=0;
HANDLE hEventBack64=0;
HANDLE hEventRelease=0;
HANDLE hEventOutput=0;
HANDLE hEventHookBack=0;
HANDLE hEventHookBack64=0;
HANDLE hEProcess=0;
HANDLE hEProcessBack=0;
HANDLE hEProcess32=0;
HANDLE hEProcessBack32=0;
#else
HANDLE hEvent32=0;
HANDLE hEventBack32=0;
HANDLE hEProcess=0;
HANDLE hEProcessBack=0;
HANDLE hEProcess32=0;
HANDLE hEProcessBack32=0;
HANDLE hEventRelease=0;
HANDLE hEventOutput=0;
HANDLE hEventHookBack32=0;
HANDLE hEventHookBack64=0;
#endif

long breakpoint=0;
HANDLE hMapFile=0;
char CurrentDLLPath[255];
extern DLLHookInfo hinfo[REGDLLNUM];
long IsDebuger=0;
DWORD CurrentPid;
SECURITY_ATTRIBUTES SecAttr;  
SECURITY_DESCRIPTOR SecDesc;  
// RTLINITUNICODESTRING RtlInitUnicodeString;
 ZWSETVALUEKEY ZwSetValueKey;
 ZWOPENKEY ZwOpenKey;
 ZWCLOSE ZwClose;
LONG (WINAPI *pRtlUnicodeStringToAnsiString)(PVOID, PVOID, BOOL)=0;
NTSTATUS (WINAPI * pRtlAnsiStringToUnicodeString)(PVOID,PVOID,BOOL)=0;
ZWQUERYKEY ZwQueryKey;
char* PrintBuf;


extern HANDLE RunAsAdmin( HWND hWnd, WCHAR* pFile,WCHAR* lpParam,WCHAR* pDir);
extern long UnHook(void ** ppFun,PVOID pDetour);
extern DLLHookInfo hinfo[];



BOOL GetSID(WCHAR* inUserName ,WCHAR* csSID)
{
    BOOL bRes = FALSE;
    

    WCHAR acUserName[256];
    ::SecureZeroMemory(acUserName, sizeof(acUserName));

    DWORD dwLength = 256;  
	wcscpy(acUserName,inUserName);
    //bRes = ::GetUserNameA(acUserName, &dwLength);


        BYTE sidBuffer[100];
        ::SecureZeroMemory(acUserName, sizeof(sidBuffer));
        PSID psid = (PSID)&sidBuffer;
        DWORD sidBufferSize = 100;
        wchar_t domainBuffer[80];
        ::SecureZeroMemory(acUserName, sizeof(domainBuffer));
        DWORD domainBufferSize = 80;
        SID_NAME_USE snu;

        //Get SID
        bRes = LookupAccountNameW(0, acUserName, psid, &sidBufferSize, domainBuffer, &domainBufferSize, &snu);
        if (bRes)
        {
            WCHAR* cSid = NULL;
            bRes = ConvertSidToStringSidW(psid, &cSid);
            if (bRes)
            {
                wcscpy(csSID,cSid);
            }
            if (cSid)
            {                
                LocalFree((HLOCAL)cSid); // Release sid space
            }
        }
    

    return bRes;
}


void EnumKey()
{
	HKEY hKey;
	if(ERROR_SUCCESS==RegOpenKey(HKEY_USERS,"",&hKey))
	{
		WCHAR chKey[MAX_PATH];
		DWORD i=0 ,dwlen=MAX_PATH;
		while(ERROR_SUCCESS==RegEnumKeyW(hKey,i++,chKey,dwlen))
		{
			if (!wcsicmp(chKey,L".default"))
				continue;
			if(wcslen(chKey)<10)
				continue;
			//chKey[wcslen(chKey)-7]=0;
			if (!wcsicmp(L"classes",chKey+wcslen(chKey)-7))
			{
				if (Classcount<2)
				{
					wcscpy(pClasses[Classcount],L"\\registry\\user\\");
					wcscat(pClasses[Classcount],chKey);
#ifdef _WIN64
					wcscat(pClasses[Classcount],L"\\local settings\\muicache");
#endif
					//MessageBoxW(0,pClasses[Classcount],L"",64);
					//wcscat(pClasses[Classcount],L"\\local settings\\muicache");
					Classcount++;
				}
				else
				{
					continue;
				}
			}
			else
			{
				if (SIDcount<5)
				{
					wcscpy(pSIDs[SIDcount],L"\\registry\\user\\");
					wcscat(pSIDs[SIDcount],chKey);
					wcscat(pSIDs[SIDcount],L"\\Software\\Microsoft\\Windows");
					SIDcount++;
				}
				else
				{
					continue;
				}
			}

		}
		RegCloseKey(hKey);
	}
}



int GetAllUser()
{
LPUSER_INFO_1 pBuf = NULL;
LPUSER_INFO_1 pTmpBuf;
DWORD dwLevel = 1;
DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
DWORD dwEntriesRead = 0;
DWORD dwTotalEntries = 0;
DWORD dwResumeHandle = 0;
DWORD i;
DWORD dwTotalCount = 0;
NET_API_STATUS nStatus;
LPTSTR pszServerName = NULL;
int ii=0,ret=0;
do
{
   nStatus = NetUserEnum(NULL,
    dwLevel,
    FILTER_NORMAL_ACCOUNT, // global users
    (LPBYTE*)&pBuf,
    dwPrefMaxLen,
    &dwEntriesRead,
    &dwTotalEntries,
    &dwResumeHandle);
   //
   // If the call succeeds,
   //
   if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
   {
    if ((pTmpBuf = pBuf) != NULL)
    {
     for (i = 0; (i < dwEntriesRead); i++)
     {

      if (pTmpBuf == NULL)
      {
       
       break;
      }

          
      if(pTmpBuf->usri1_priv==USER_PRIV_ADMIN)
	  {
		  if (ii>=4) 
		  {
			  ret=12;
			  break;
		  }
		  GetSID(pTmpBuf->usri1_name,pSIDs[ii]); 
		  MsgboxW(pTmpBuf->usri1_name,0);
		  MsgboxW(pSIDs[ii],0);
		  ii++;
	  }

      pTmpBuf++;
      dwTotalCount++;
     }
    }
   }
   else{
    
   }
   if (pBuf != NULL)
   {
    NetApiBufferFree(pBuf);
    pBuf = NULL;
   }
}while(nStatus == ERROR_MORE_DATA);


SIDcount=ii;
return ret;
}






// 安全的取得真实系统信息
VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
    if (NULL==lpSystemInfo)    return;
    typedef VOID (WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
    LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress( GetModuleHandle("kernel32"), "GetNativeSystemInfo");;
    if (NULL != fnGetNativeSystemInfo)
    {
        fnGetNativeSystemInfo(lpSystemInfo);
    }
    else
    {
        GetSystemInfo(lpSystemInfo);
    }
}

// 获取操作系统位数
int GetSystemBits()
{
    SYSTEM_INFO si;
    SafeGetNativeSystemInfo(&si);
     if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )
    {
        return 64;
    }
    return 32;
}


#ifdef _WIN64
 HANDLE RunOpen( HWND hWnd, WCHAR* pFile,WCHAR* lpDirectory)
{
 SHELLEXECUTEINFOW sei;

 ZeroMemory(&sei,sizeof(sei));
 sei.cbSize = sizeof(sei);
 sei.hwnd    = hWnd;
 sei.fMask  = 0x00000100|SEE_MASK_FLAG_NO_UI ;
 sei.lpFile = pFile;
 sei.lpVerb = L"open";
 sei.lpDirectory=lpDirectory;
 //sei.lpParameters = PChar(aParameters);
 sei.nShow = SW_SHOWNORMAL;
 ShellExecuteExW(&sei);
 return sei.hProcess;
}


 int __stdcall myCreateProcessW2(LPCSTR lpApplicationName,int lpCommandLine,DWORD dwCreationFlags,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{

		void* aa=0;
	/*__asm
	{
		mov eax, [ebp+4]
		mov aa,eax
	}*/
	HMODULE hMod=GetModuleHandleW(L"ntdll.dll");
	PRtlGetCallersAddress pFun=(PRtlGetCallersAddress)GetProcAddress(hMod,"RtlGetCallersAddress");
	void* b1,*b2;
	pFun(&b1,&b2);
	aa=b1;
	INT64   i;
	long key,key2;
	bool ok=false;
	for (i=(long long)aa;i>=(long long)aa-0x000000200000;i--)
	{
		key=*(long*)i;
		if (key==0x90909090)
		{
			ok=true;
			break;
		}
	}

	if(ok)
	{
		i+=4;
		pSHCreateProcess=(PSHCreateProcess)i;
	}
	else
	{
		pSHCreateProcess=0;
	}

	return 0;
}


void* LocateFunc()
{
	HMODULE hMod=GetModuleHandleW(L"kernel32.dll");
	PVOID pFun=GetProcAddress(hMod,"CreateProcessW");
	PVOID pOld=pFun;

	Hook(&pOld,myCreateProcessW2);

	RunOpen(0,L"explorer.exe",0);
	UnHook(&pOld,myCreateProcessW2);

	return pSHCreateProcess;
}
#else
long myIsUserAnAdmin()
{
	void* aa=0;
	__asm
	{
		mov eax, [ebp+4]
		mov aa,eax
	}

	long i,key,key2;
	bool ok=false;
	for (i=(long)aa;i>=(long)aa-0x200000;i--)
	{
		key=*(long*)i;
		key2=*(long*)(i+4);
		if (key==0x8b144d8b && key2==0x8d890845 )
			break;
	}
	for (;i>=(long)aa-0x200000;i--)
	{
		key=*(long*)i;	
		if (key==0x90909090)
		{
			ok=true;
			break;
		}
	}
	if(ok)
	{
		i+=4;
		HMODULE hMod=GetModuleHandleW(L"shell32.dll");
		pSHCreateProcess =(PSHCreateProcess)i;
	}
	else
	{
		pSHCreateProcess =0;
	}


	return 1;

}
void* LocateFunc()
{
	HMODULE hMod=GetModuleHandleW(L"shell32.dll");
	PVOID pFun=GetProcAddress(hMod,"IsUserAnAdmin");
	PVOID pOld=pFun;

	//cout<<"mod "<<(long)hMod<<"   Addr:"<<(long)pFun<<endl;
	Hook(&pOld,myIsUserAnAdmin);
	TerminateProcess(RunAsAdmin(0,L"explorer.exe",0,0),0);
	UnHook(&pOld,myIsUserAnAdmin);
	return 	pSHCreateProcess;

}
#endif


typedef BOOL (__stdcall *PGetMonitorInfo)(HMONITOR      hMonitor,LPMONITORINFO lpmi);
PGetMonitorInfo oldGetMonitorInfo;
BOOL __stdcall myGetMonitorInfo(HMONITOR      hMonitor,LPMONITORINFO lpmi)
{
	void* aa=0;
#ifdef _WIN64
	HMODULE hMod=GetModuleHandleW(L"ntdll.dll");
	PRtlGetCallersAddress pFun=(PRtlGetCallersAddress)GetProcAddress(hMod,"RtlGetCallersAddress");
	void* b1,*b2;
	pFun(&b1,&b2);
	aa=b1;
#else
	__asm
	{
		mov eax, [ebp+4]
		mov aa,eax
	}
#endif
	long key,key2;
	char* i;
	bool ok=false;

	for (i=(char*)aa;i>=(char*)aa-0x200000;i--)
	{
		key=*(long*)i;	
		if (key==0xcccccccc)
		{
			ok=true;
			break;
		}
	}
	if(ok)
	{
		i+=4;
		HMODULE hMod=GetModuleHandleW(L"windows.storage.dll");
		pAicLaunchAdminProcess =(PAicLaunchAdminProcess)i;
		AicLaunchAdminProcess_offset=(char*)pAicLaunchAdminProcess-(char*)hMod;
	}
	else
	{
		AicLaunchAdminProcess_offset=0;
		pAicLaunchAdminProcess =0;
	}
	ExitProcess(0);
	return 0;
	//return oldGetMonitorInfo(hMonitor,lpmi);

}
void* LocateAicLaunchAdminProcess()
{
	HMODULE hMod=GetModuleHandleW(L"user32.dll");
	PVOID pFun=GetProcAddress(hMod,"GetMonitorInfoW");
	PVOID pOld=pFun;
	//cout<<"mod "<<(long)hMod<<"   Addr:"<<(long)pFun<<endl;
	Hook(&pOld,myGetMonitorInfo);
	oldGetMonitorInfo=(PGetMonitorInfo)pOld;
	TerminateProcess(RunAsAdmin(0,L"cmd.exe",0,0),0);
	UnHook(&pOld,myGetMonitorInfo);
	return 	pAicLaunchAdminProcess;

}

void BuildWindowsSecuAttr( SECURITY_ATTRIBUTES *pSecuAttr, SECURITY_DESCRIPTOR *pSecuDesc ) 
{ 
DWORD aclLength; 
PSID pAuthenticatedUsersSID = NULL; 
PACL pDACL = NULL; 
BOOL bResult = FALSE; 
PACCESS_ALLOWED_ACE pACE = NULL; 
SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY; 
SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION; 


/* 初始化Security Descriptor */ 
bResult = InitializeSecurityDescriptor( pSecuDesc, SECURITY_DESCRIPTOR_REVISION ); 

/* 获取认证用户组的sid */ 
bResult = AllocateAndInitializeSid( &siaNT, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &pAuthenticatedUsersSID ); 

/* 计算DACL长度，并分配内存 */ 
aclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pAuthenticatedUsersSID); // add space for Authenticated Users group ACE 
pDACL = (PACL)malloc( aclLength ); 

/* 初始化DACL */ 
bResult = InitializeAcl( pDACL, aclLength, ACL_REVISION); 

/* 给认证用户组ACE添加到带有全部权限的DACL中 */ 
bResult = AddAccessAllowedAce( pDACL, 
ACL_REVISION, 
GENERIC_ALL, 
//GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, 
pAuthenticatedUsersSID ); 

 bResult = SetSecurityDescriptorDacl( pSecuDesc, TRUE, pDACL, FALSE ); 
//bResult = SetSecurityDescriptorDacl( pSecuDesc, TRUE, NULL, FALSE ); //pDACL参数传NULL表示建立NULL DACL，允许所有的访问 

/* 初始化security attributes结构体 */ 
pSecuAttr->nLength = sizeof(SECURITY_ATTRIBUTES); 
pSecuAttr->lpSecurityDescriptor = pSecuDesc; 
pSecuAttr->bInheritHandle = FALSE; 

}


void* CreateSharedInfo(WCHAR* szName)
{
			
		    void * pBuf=0;
//SECURITY_ATTRIBUTES SecAttr;  
//SECURITY_DESCRIPTOR SecDesc;  
  
/*SecAttr.nLength = sizeof(SecAttr);  
SecAttr.bInheritHandle = TRUE;  
SecAttr.lpSecurityDescriptor = &SecDesc;  

InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);  
SetSecurityDescriptorDacl(&SecDesc, TRUE, 0, TRUE);  */
//BuildWindowsSecuAttr(&SecAttr,&SecDesc);
#ifdef _WIN64
#define HMU hMu64
#else
#define HMU hMu
#endif
			if (HMU!=0)
			{
				pBuf = MapViewOfFile(HMU,   // handle to map object
					FILE_MAP_ALL_ACCESS, // read/write permission
					0,
					0,
					sizeof(SharedMemory3264));

				if (pBuf != NULL)
				{
					hMapFile=HMU;
					return pBuf;
				}
				else
				{
//Msgbox("GGGG",(long)hMu);
				}
			}

			hMapFile = CreateFileMappingW(
				INVALID_HANDLE_VALUE,    // use paging file
				&SecAttr,                    // default security
				PAGE_READWRITE,          // read/write access
				0,                       // maximum object size (high-order DWORD)
				sizeof(SharedMemory3264),                // maximum object size (low-order DWORD)
				szName);                 // name of mapping object
			long Lasterr;
			if (hMapFile == NULL)
			{
				Lasterr=GetLastError();
				if (Lasterr==5)
				{
#ifdef _WIN64
					hMapFile = OpenFileMappingW(PAGE_READWRITE,TRUE,szName);
#else
					hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS,TRUE,szName);
#endif
					if (hMapFile==0)
					{
						Msgbox("Could not open file mapping object",GetLastError());
						return 0;
					}
				}
				else
				{
					Msgbox("Could not create file mapping object",Lasterr);
					return 0;
				}
				
			}
			pBuf = MapViewOfFile(hMapFile,   // handle to map object
				FILE_MAP_ALL_ACCESS, // read/write permission
				0,
				0,
				sizeof(SharedMemory3264));

			if (pBuf == NULL)
			{

				CloseHandle(hMapFile);
				Msgbox("Could not map view of file.",Lasterr);
				return 0;
			}
			return pBuf;
#undef HMU
}
#ifndef _WIN64
 DWORD WINAPI WatchOutputProc (LPVOID lpParam)
 { 
	 ptOutputProc p=(ptOutputProc)lpParam;
	 while(1)
	 {

		 WaitForSingleObject(hEventOutput,-1);
		 p(PrintBuf);
		 ResetEvent(hEventOutput);
		 
	 }
 }

HANDLE __stdcall ListenOutput(ptOutputProc p)
{
	return CreateThread(NULL,0,WatchOutputProc,p,0,NULL);
}


long __stdcall SetCustomHook(char* oldName,char* oldMod, char* newName, char* newMod, char* oldProcAddr,long is64) /*10-25 new*/
{
	CustomHook* ch;
	if(is64)
		ch=customHooks64;
	else
		ch=customHooks;
	int i;
	for(i=0;i<CHOOK_NUM;i++)
	{
		if(ch[i].oldName[0]==0)
		{
			goto found;
		}
	}
	return -1;
found:
	strncpy(ch[i].oldName,oldName,sizeof(ch[i].oldName)-1);
	strncpy(ch[i].oldMod,oldMod,sizeof(ch[i].oldMod)-1);
	strncpy(ch[i].newName,newName,sizeof(ch[i].newName)-1);
	strncpy(ch[i].newMod,newMod,sizeof(ch[i].newMod)-1);
	strncpy(ch[i].oldProcAddr,oldProcAddr,sizeof(ch[i].oldProcAddr)-1);
	return i;
}
long __stdcall ResetCustomHook(long id,long is64)/*10-25 new*/
{
	if (id>-1 && id <CHOOK_NUM)
	{
		if(is64)
			customHooks64[id].oldName[0]=0;
		else
			customHooks[id].oldName[0]=0;
	}
	return 0;
}


/*判断是否是x64进程
参  数:进程句柄
返回值:是x64进程返回TRUE,否则返回FALSE
*/
BOOL __stdcall IsWow64ProcessEx(HANDLE hProcess)
{
	/*判断ntdll中的导出函数,可知是否是64位OS*/
	HMODULE hMod=GetModuleHandle("ntdll.dll");
	FARPROC x64fun=::GetProcAddress(hMod,"ZwWow64ReadVirtualMemory64");
	if(!x64fun) return FALSE;
	
	/*利用IsWow64Process判断是否是x64进程*/
	typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE,PBOOL);
	pfnIsWow64Process fnIsWow64Process=NULL;
	
	hMod=GetModuleHandle("kernel32.dll");
	fnIsWow64Process=(pfnIsWow64Process)GetProcAddress(hMod,"IsWow64Process");
	if(!fnIsWow64Process) return FALSE;				//如果没有导出则判定为32位
	
	BOOL bX64;
	if(!fnIsWow64Process(hProcess,&bX64)) return FALSE;
	
	return !bX64;
}
 DWORD WINAPI HProc (LPVOID lpParam)
 {
	 Sleep(1000);
	 HookIt(hinfo[3].ModName,hinfo[3].ProcName,hinfo[3].pProc,hinfo[3].ppOld);
	 //Msgbox("",0);
	 
					//Msgbox("hh",HookIt(hinfo[3].ModName,hinfo[3].ProcName,hinfo[3].pProc,hinfo[3].ppOld));
	CreateProcessW(0,0,0,0,0,0,0,0,0,0);
					return 0;
 }


#endif

bool EnableDebugPrivilege()   
{   
    HANDLE hToken;   
    LUID sedebugnameValue;   
    TOKEN_PRIVILEGES tkp;   
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {   
        return   FALSE;   
    }   
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))  
    {   
        CloseHandle(hToken);   
        return false;   
    }   
    tkp.PrivilegeCount = 1;   
    tkp.Privileges[0].Luid = sedebugnameValue;   
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) 
    {   
        CloseHandle(hToken);   
        return false;   
    }   
    return true;   
}


#ifdef _WIN64
long __stdcall SetAPIHook32(long pid,int *pDLLid,long num)
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

		psInfo->type=108;
		psInfo->pid=pid;
		psInfo->data.intArray[0]=num;
		CopyMemory(&(psInfo->data.intArray[1]),pDLLid,num*sizeof(int));
		SetEvent(hEProcess32);

		WaitForSingleObject(hEProcessBack32,-1);
		ResetEvent(hEProcessBack32);
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
 DWORD WINAPI WatchProcessProc (LPVOID lpParam)
 { 
	 HANDLE hProcess=0;
	 HANDLE hMhook1 = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex64");
	 LPCSTR rlpDlls[1]={CurrentDLLPath};
	 long ret=0;
	 while(1)
	 {

		 WaitForSingleObject(hEProcess,-1);
		 switch(psInfo->type)
		 {
		 case 93:
			 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,psInfo->pid);
			 if (hProcess==0)
			 {
				psInfo->ret=213;
			 }
			 else
			 {

				WaitForSingleObject(hMhook1,-1);
				thInfo=autoHook;
				/*thInfo.count=3;
				thInfo.DLLid[0]=6;
				thInfo.DLLid[1]=8;
				thInfo.DLLid[2]=9;*/
				hMu64=(HANDLE)psInfo->data.Param2.p2;
				NeedToLoad=0;
				int i;
				for (i=0;i<128;i++)
				{
					if (toHookPid[i]==0)
					{
						toHookPid[i]=(HANDLE)psInfo->pid;
						break;
					}
				}
				HANDLE hE=hEventHookBack64;//CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC64");
				psInfo->ret=DetourUpdateProcessWithDll(hProcess,rlpDlls,1);

				HANDLE hTh=OpenThread(THREAD_SUSPEND_RESUME ,FALSE,psInfo->data.Param2.p1);
				if(hTh)
				{
					psm->suspend64=1;
					ResumeThread(hTh);
					WaitForSingleObject(hE,2000);//fix-me check time-out?
				}
				else
				{
					Msgbox("Fail to open the thread:",GetLastError());
				}
				toHookPid[i]=0;
				
				ReleaseMutex(hMhook1);
				CloseHandle(hProcess);
				SetEvent(hEProcessBack);
			    ResetEvent(hEProcess);
				//CloseHandle(hE);
			 }
			 break;
		 case 92:
			 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,sInfo.pid);
			 if (hProcess==0)
			 {
				sInfo.ret=213;
			 }
			 else
			 {

				//thInfo.DLLid[1]=2;

				sInfo.ret=DetourUpdateProcessWithDll(hProcess,rlpDlls,1);
				SetEvent(hEProcessBack);
		        ResetEvent(hEProcess);
				CloseHandle(hProcess);

			 }
			 break;
		 case 109:
			 if(sInfo.pid==-1)
			 {
				 	autoHook.count=sInfo.data.intArray[0];
					CopyMemory(autoHook.DLLid,&(sInfo.data.intArray[1]),autoHook.count*sizeof(int));
			 }
			 else
			 {
				 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,sInfo.pid);
				 ret=SetIATHookByAPC(hProcess,(HANDLE)sInfo.pid,(void*)1,(FishHookTypes*)&(sInfo.data.intArray[1]),sInfo.data.intArray[0]);
			 }
			 SetEvent(hEProcessBack);
			 ResetEvent(hEProcess);	
			 CloseHandle(hProcess);
			 break;
		 default:
			 sInfo.ret= 250;
			 SetEvent(hEProcessBack);
			 ResetEvent(hEProcess);	
		 }

		 
	 }
 }
 DWORD WINAPI WaitProcessProc (LPVOID lpParam)
 {
	 if(psm)
	 {
		 HANDLE hProcess=OpenProcess(SYNCHRONIZE,0,psm->DebugerPid);
		 WaitForSingleObject(hProcess,-1);
		 CloseHandle(hProcess);
		 SetEvent(hEventRelease);
		 ExitProcess(0);
	 }
	 return 0;
 }

 HANDLE __stdcall StartListening()
 {
	 HANDLE h;
	 h=CreateThread(NULL,0,WatchProcessProc,NULL,0,NULL);
	 CreateThread(NULL,0,WaitProcessProc,NULL,0,NULL);
	 return h;
 }
#else
 DWORD WINAPI WatchProcessProc (LPVOID lpParam)
 { 
	 HANDLE hProcess=0;
	 HANDLE hMhook1 = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex");
	 LPCSTR rlpDlls[1]={CurrentDLLPath};
	 long ret=0;
	 while(1)
	 {

		 WaitForSingleObject(hEProcess32,-1);
		 switch( psInfo64->type)
		 {
		 case 90:
			 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,psInfo64->pid);
			 if (hProcess==0)
			 {
				psInfo64->ret=213;
			 }
			 else
			 {

				psInfo64->ret=DetourUpdateProcessWithDll(hProcess,rlpDlls,1);
				SetEvent(hEProcessBack32);
			    ResetEvent(hEProcess32);
			 }
			break;
		 case 94:
			 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,psInfo64->pid);
			 if (hProcess==0)
			 {
				psInfo64->ret=213;
			 }
			 else
			 {

				WaitForSingleObject(hMhook1,-1);
				/*thInfo.count=3;
				thInfo.DLLid[0]=6;
				thInfo.DLLid[1]=8;
				thInfo.DLLid[2]=9;*/
				thInfo=autoHook;
				NeedToLoad=0;
				int i=0;
				for ( i=0;i<128;i++)
				{
					if (toHookPid[i]==0)
					{
						toHookPid[i]=(HANDLE)psInfo64->pid;
						break;
					}
				}
				hMu=(HANDLE)psInfo64->data.Param2.p2;
//				Logn("hmap in admin",psInfo64->data.Param2.p2);
				HANDLE hE=hEventHookBack;//CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
				psInfo64->ret=DetourUpdateProcessWithDll(hProcess,rlpDlls,1);
				HANDLE hTh=OpenThread(THREAD_SUSPEND_RESUME ,FALSE,psInfo64->data.Param2.p1);
				if(hTh)
				{
					psm->suspend32=1;
					ResumeThread(hTh);
					WaitForSingleObject(hE,-1);//fix-me check time-out? to2000
				}
				else
				{
					Msgbox("Fail to open the thread:",GetLastError());
				}
				toHookPid[i]=0;
						
				ReleaseMutex(hMhook1);
				CloseHandle(hProcess);
				SetEvent(hEProcessBack32);
			    ResetEvent(hEProcess32);
				//CloseHandle(hE);
			 }
			break;
		 case 108:
			 //Msgbox("32 hook",0);
			 hProcess= OpenProcess(PROCESS_ALL_ACCESS,0,psInfo64->pid);
			 if (hProcess!=0)
			 {

				 psInfo64->ret=SetIATHookByAPC(hProcess,(HANDLE)psInfo64->pid,(void*)1,(FishHookTypes*)&psInfo64->data.intArray[1],psInfo64->data.intArray[0]);
			 }
			 else
			 {
				psInfo64->ret=213;
			 }
			//Msgbox("32 hook ok",0);
			 SetEvent(hEProcessBack32);
			 ResetEvent(hEProcess32);	
			 CloseHandle(hProcess);
			 break;
		 case 121:
			 psInfo64->ret=ResumeProcess(psInfo64->data.Param2.p1,-1);
			 SetEvent(hEProcessBack32);
			 ResetEvent(hEProcess32);	
			 break;
		 case 122:
			 psInfo64->ret=SuspendProcess(psInfo64->data.Param2.p1,-1);
			 SetEvent(hEProcessBack32);
			 ResetEvent(hEProcess32);	
			 break;
		 default:
			 psInfo64->ret= 250;
			 SetEvent(hEProcessBack32);
			 ResetEvent(hEProcess32);
		 }

		 
	 }
 }

 
   DWORD WINAPI WatchProc64 (LPVOID lpParam)
 { 

	 while(1)
	 {

		 WaitForSingleObject(hEvent64,-1);
		 psInfo64->ret= CallBackProc(psInfo64);
		 ResetEvent(hEvent64);
		 SetEvent(hEventBack64);
		 //ResetEvent(hEventBack64);
		 
	 }
 }



#endif

    DWORD WINAPI ReleaseHookProc (LPVOID lpParam)
 {	 

	 WaitForSingleObject(hEventRelease,-1);

	 SuspendProcess(CurrentPid,GetCurrentThreadId());
	 int i;
	 for (i=0;i<REGDLLNUM;i++)
	 {
		 if(*hinfo[i].ppOld)
		 {
			 UnHook(hinfo[i].ppOld,hinfo[i].pProc);
			 
		 }
	 }
	 for(i=0;i<CHOOK_NUM;i++)
	 {
		 if(customhookinfo[i].hMod)
		 {
			 UnHook(&customhookinfo[i].pOld,customhookinfo[i].pNew);
		 }
	 }
	 for(i=0;i<CHOOK_NUM;i++)
	 {
		 if(customhookinfo[i].hMod)
		 {
			 FreeLibrary(customhookinfo[i].hMod);
			 FreeLibrary(customhookinfo[i].hMod);
		 }
	 }
	 ResumeProcess(CurrentPid,GetCurrentThreadId());
	 //FreeLibraryAndExitThread((HMODULE)hMod,0);
	 TrulyUnloadDLLAndExitThread((HMODULE)hMod,0);
	 return 0;
 }

 DWORD WINAPI WatchProc (LPVOID lpParam)
 { 

	 while(1)
	 {
		 //Msgbox("32!",0);
		 WaitForSingleObject(hEvent,-1);
		 sInfo.ret= CallBackProc(&sInfo);
		 SetEvent(hEventBack);
		 ResetEvent(hEvent);
		 
	 }
 }

#ifdef _WIN64
extern long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void * callproc,FishHookTypes *pDLLid,long num)
{
	if (num<=20)
	{
		
		HANDLE hMutex = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex64");
		WaitForSingleObject(hMutex,-1);
		char DLLPath[255];
		GetModuleFileName((HINSTANCE)hMod,DLLPath,255);

		if (callproc==0)
		{	
			psm->isWatching=0;
			 
		}
		else if(callproc!=(void*)1)
		{	
			CallBackProc=(long (__stdcall *)(SharedInfo*))callproc;
			CreateThread(NULL,0,WatchProc,NULL,0,NULL);
			psm->isWatching=1;			
		}
		for (int i=0;i<128;i++)
		{
			if (toHookPid[i]==0)
			{
				toHookPid[i]=PID;
				break;
			}
		}

		thInfo.count=num;
		CopyMemory(thInfo.DLLid,pDLLid,num*sizeof(int));
		autoHook=thInfo;
		hMu64=hMapFile;
		NeedToLoad=0;
		//thInfo.DLLid[0]=DLLid;
		HANDLE hE=hEventHookBack64;//CreateEvent(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC64");
		//long ret=InjectModuleToProcess(hProcess,PID,DLLPath);
		long ret=InjectDll((unsigned long)PID,DLLPath);
		if (ret)
		{
		
			long rtn=WaitForSingleObject(hE,5000);
			if(rtn==WAIT_TIMEOUT)
			{
					ReleaseMutex(hMutex);
					ret=123;
			}
			else
				ret=0;
			ReleaseMutex(hMutex);
		}
		else
		{
			ReleaseMutex(hMutex);
		}
		//CloseHandle(hE);
		CloseHandle(hMutex);

		return ret;
	}
	else
	{
		return 13;
	}
}
#else
 long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void* callproc,FishHookTypes* pDLLid,long num)
{
	HANDLE hMutex = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex");
	WaitForSingleObject(hMutex,-1);
	char DLLPath[255];
	GetModuleFileName((HINSTANCE)hMod,DLLPath,255);
	if (callproc==0)
	{
		psm->isWatching=0;
		
	}
	else if(callproc!=(void*)1)
	{
		CallBackProc=(long (__stdcall *)(SharedInfo*))callproc;
		CreateThread(NULL,0,WatchProc64,NULL,0,NULL);
	    CreateThread(NULL,0,WatchProc,NULL,0,NULL);
		psm->isWatching=1;		
	}

	for (int i=0;i<128;i++)
	{
		if (toHookPid[i]==0)
		{
			toHookPid[i]=PID;
			break;
		}
	}
	if (num<=20)
	{
		thInfo.count=num;
		CopyMemory(thInfo.DLLid,pDLLid,num*sizeof(int));
		autoHook=thInfo;
		//thInfo.DLLid[0]=DLLid;
		NeedToLoad=0;
	}
	else
	{
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
		return 13;
	}
	HANDLE hE=CreateEvent(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
	//long ret=InjectModuleToProcess(hProcess,PID,DLLPath);
	long ret=InjectDll((unsigned long)PID,DLLPath);
	if (ret)
	{
		
		long rtn=WaitForSingleObject(hE,5000);
		if(rtn==WAIT_TIMEOUT)
		{
			ret=123;
		}
		else
		{
			ret=0;
		}
		ReleaseMutex(hMutex);
	}
	else
	{
		ReleaseMutex(hMutex);
		//CloseHandle(hE);
		ret= 144;
	}
	//MessageBox(0,"","",64);
	CloseHandle(hE);
	CloseHandle(hMutex);

	if(GetSystemBits()==64)
		SetAPIHook64(-1,1,pDLLid,num);

	return ret;
}
#endif
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) 
{

  if (nCode!=HC_ACTION) return CallNextHookEx(hhook, nCode, wParam ,lParam);
   MSG	*msg=(MSG *)lParam;
//Logn("m",(long)msg->hwnd );
	if (msg->message==123450 )
	{   
		//Logn("haha",0);
		  //replace_IAT("User32.dll","MessageBoxW",HOOK_MessageBoxW,(void**)&oldmsgW);
#ifdef _WIN64
		  HANDLE hE= hEventHookBack64;
#else
		  HANDLE hE= OpenEventA(EVENT_ALL_ACCESS,FALSE,"Global\\HookDllAPC");
#endif
		  SetEvent(hE);
		  CloseHandle(hE);
		  int DLLid=0; 
		  HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS,FALSE,"Global\\HookDllMutex");
		  for (int j=0;j<thInfo.count;j++)
		  {
				DLLid=thInfo.DLLid[j];
			  HookIt(hinfo[DLLid].ModName,hinfo[DLLid].ProcName,hinfo[DLLid].pProc,hinfo[DLLid].ppOld);
		  }

		  thInfo.count=0;

          ReleaseMutex(hMutex);
          CloseHandle(hMutex);
		  
		return 0;
	}
	return ::CallNextHookEx(hhook, nCode, wParam ,lParam);
}


 BOOL __stdcall EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    unsigned	long pid=0;
	//Logn("hwnd",(long)hWnd);
    long tid= GetWindowThreadProcessId(hWnd,&pid);
	if (pid==(unsigned long)lParam)
	{

		//Logn("in",0);
		hhook=SetWindowsHookEx(WH_GETMESSAGE,HookProc,(HINSTANCE)hMod,tid);
		PostMessage(hWnd,123450,0,0);
		Status=(long)hhook;

		return 0;
	}
	return 1;
}

 long __stdcall SetIATHook(HANDLE PID,long bp,void* callproc,FishHookTypes DLLid)
{
	 breakpoint=bp;
	 Status=0;
	 if (callproc!=0)
	 {
         CallBackProc=(long (__stdcall *)(SharedInfo*))callproc;
	     CreateThread(NULL,0,WatchProc,NULL,0,NULL);
#ifndef _WIN64
		 CreateThread(NULL,0,WatchProc64,NULL,0,NULL);
#endif
	 }
#ifndef _WIN64
	HANDLE hMutex = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex");
#else
	 HANDLE hMutex = CreateMutex(&SecAttr,FALSE,"Global\\HookDllMutex64");
#endif
	WaitForSingleObject(hMutex,-1);
	thInfo.count=1;
	thInfo.DLLid[0]=DLLid;
	NeedToLoad=0;
#ifndef _WIN64
	HANDLE hE=CreateEvent(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC"); //fix-me?
#else
	HANDLE hE=hEventHookBack64; //fix-me?
#endif
	EnumWindows(EnumWindowsProc,(long )PID);
	//ReleaseMutex(hMutex);	
	if (Status) 
	{
		long rtn=WaitForSingleObject(hE,5000);
		
		if(rtn==WAIT_TIMEOUT)
		{
#ifdef _WIN64
			ReleaseMutex(hMutex);
#endif
				Status=123;
		}		
		ReleaseMutex(hMutex);
	}
	else
	{
			ReleaseMutex(hMutex);
	}
#ifndef _WIN64
	CloseHandle(hE);
#endif
	CloseHandle(hMutex);
	return Status;
}


 void InitNativeApi()
 {
 //获得 ZwSetValueKey的函数指针
 	*(FARPROC*)&pRtlUnicodeStringToAnsiString = GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlUnicodeStringToAnsiString");
	*(FARPROC*)&pRtlAnsiStringToUnicodeString = GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlAnsiStringToUnicodeString");
	ZwSetValueKey=(ZWSETVALUEKEY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"ZwSetValueKey");    
	 //获得 ZwOpenKey的函数指针
	ZwQueryKey=(ZWQUERYKEY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"ZwQueryKey");    
	ZwOpenKey=(ZWOPENKEY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"ZwOpenKey") ;
	 //获得 ZwClose的函数指针
	ZwClose=(ZWCLOSE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"ZwClose");
//	RtlInitUnicodeString=(RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlInitUnicodeString");

 }

 

void __stdcall InitFishHook()
{
	OSVERSIONINFOEX os; 
	os.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);  /*在调用函数前必须用sizeof(OSVERSIONINFOEXA)填充dwOSVersionInfoSize结构成员*/ 
	GetVersionEx((OSVERSIONINFO *)&os);
	if( os.dwMajorVersion==6 && os.dwMajorVersion>1 )   //if is win8/win10
	{ 
		system("runas /trustlevel:0x20000 \"rundll32 FishHook64.dll GetAddressProc\"");
		system("runas /trustlevel:0x20000 \"rundll32 FishHook32.dll GetAddressProc\"");
		int i=0;
		for(;i<100;i++)
		{
			if(AicLaunchAdminProcess_offset!=0)
			{
				break;
			}
			Sleep(50);
		}
		if(i==100)
			MessageBox(0,"Find address error","",64);
	}	

}



BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{

	bool IsNeedSHCreateProcess=false;
    if (hEvent==0)
	{
		SecAttr.nLength = sizeof(SecAttr);  
		SecAttr.bInheritHandle = TRUE;  
		SecAttr.lpSecurityDescriptor = &SecDesc;  

		InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);  
		SetSecurityDescriptorDacl(&SecDesc, TRUE, 0, FALSE);  
		InitNativeApi();
	}
#ifdef _WIN64
	if (hEvent32==0) hEvent32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookDllEvent");
	if (hEventBack32==0)hEventBack32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookEventBack");
	if (hEvent==0) hEvent=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookDllEvent64");
	if (hEventBack==0)hEventBack=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookEventBack64");
	if (hEProcess==0) hEProcess=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcess64");
	if (hEProcessBack==0)hEProcessBack=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcessBack64");
	if (hEProcess32==0) hEProcess32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcess32");
	if (hEProcessBack32==0)hEProcessBack32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcessBack32");
	if (hEventRelease==0)hEventRelease=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookEventRelease");
	if (hEventOutput==0)hEventOutput=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookEventOutput");
	if (hEventHookBack32==0)hEventHookBack32=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
	if (hEventHookBack64==0)hEventHookBack64=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC64");
#else
	if (hEvent==0) hEvent=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookDllEvent");
	if (hEventBack==0)hEventBack=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookEventBack");
	if (hEvent64==0) hEvent64=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookDllEvent64");
	if (hEventBack64==0)hEventBack64=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookEventBack64");	
	if (hEProcess==0) hEProcess=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcess64");
	if (hEProcessBack==0)hEProcessBack=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcessBack64");
	if (hEProcess32==0) hEProcess32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcess32");
	if (hEProcessBack32==0)hEProcessBack32=CreateEvent(&SecAttr,TRUE,FALSE,"Global\\HookCreateProcessBack32");
	if (hEventRelease==0)hEventRelease=CreateEventA(&SecAttr,TRUE,FALSE,"Global\\HookEventRelease");
	if (hEventOutput==0)hEventOutput=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookEventOutput");
	if (hEventHookBack==0)hEventHookBack=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC");
	if (hEventHookBack64==0)hEventHookBack64=CreateEventA(&SecAttr,FALSE,FALSE,"Global\\HookDllAPC64");
#endif
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//GetAllUser();
		//DbgPrint("DLL load");
		GetModuleFileName((HINSTANCE)hModule,CurrentDLLPath,255);
		OSVERSIONINFOEX os; 
		os.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);  /*在调用函数前必须用sizeof(OSVERSIONINFOEXA)填充dwOSVersionInfoSize结构成员*/ 
		GetVersionEx((OSVERSIONINFO *)&os);
		if( os.dwMajorVersion==6 && os.dwMajorVersion<=1 )   //if is vista/win 7
		{ 
					IsNeedSHCreateProcess=true;
		}

#ifdef _WIN64
		if(!stricmp("runas /trustlevel:0x20000 \"rundll32 FishHook64.dll GetAddressProc\"",GetCommandLineA()))
#else
		if(!stricmp("runas /trustlevel:0x20000 \"rundll32 FishHook32.dll GetAddressProc\"",GetCommandLineA()))
#endif
		{
			break;
		}
#ifdef _WIN64
		if (psInfo==0)
		{
			psm=(SharedMemory3264*)CreateSharedInfo(L"Global\\FishHookFileMappingObject");
			if (!psm)
			{			
				return 1;
			}
			psInfo=&(psm->si);
			//customHooks=sm->ch;
			customHooks=psm->ch64;
			PrintBuf=psm->PrintBuf;
			//Msgbox("ENTER",psm->isWatching);
		}
#else
		if (psInfo64==0)
		{
			SharedMemory3264* sm=(SharedMemory3264*)CreateSharedInfo(L"Global\\FishHookFileMappingObject");
			if (!sm)
			{		
				return 1;
			}
			psm=sm;
			psInfo64=&(sm->si);
			customHooks=sm->ch;
			customHooks64=sm->ch64;
			PrintBuf=sm->PrintBuf;
		}
#endif
		hMod=hModule;
		
		HANDLE pid;
		pid=(HANDLE)GetCurrentProcessId();
		CurrentPid=(DWORD)pid;
		int i;HANDLE hE;

		for (i=0;i<128;i++)
		{

			//Msgbox("toh",(long)toHookPid[i]);
			if (toHookPid[i]==pid)
			{
				
				//FHPrint("dll load : %d\n",GetCurrentProcessId());
				//Msgbox("INJ",(long)pid);
				PopHandles();
				//FHPrint("%d %d %d\n",thInfo.count,MAGIC1,MAGIC2);
				// if (hModA != NULL) 
				// {
				//	 FreeLibrary(hModA);
				// }
				//if (!IsWow64ProcessEx((HANDLE)-1))MessageBox(NULL,"32","",64);
				//HANDLE hMhook = CreateMutex(NULL,FALSE,"Global\\HookDllMutex64");
	            //HANDLE hMsInfo=CreateMutex(NULL,FALSE,"Global\\HookSharedInfoMutex64");
				int DLLid=0; 

				//HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS,FALSE,"Global\\HookDllMutex64");
				toHookPid[i]=0;
				for( int j=0;j<CHOOK_NUM;j++)
				{		
					if(customHooks[j].oldName[0]!=0)
					{
						
						HANDLE hMod_t=LoadLibrary(customHooks[j].oldMod),hMod_n=LoadLibrary(customHooks[j].newMod);
						if(!hMod_n || !hMod_t)
						{
							
							FHPrint("Custom Hook Error: Fail to load the new/old lib\n");
							continue;
						}
						//Msgbox(customHooks[j].oldName,0);
						VOID* pOld=GetProcAddress((HMODULE)hMod_t,customHooks[j].oldName);
						VOID* pNew=GetProcAddress((HMODULE)hMod_n,customHooks[j].newName);
						VOID** ppOldRet=(VOID**)(LONG_PTR)GetProcAddress((HMODULE)hMod_n,customHooks[j].oldProcAddr);
						void** pSharedMemory=(void**)(LONG_PTR)GetProcAddress((HMODULE)hMod_n,"pSharedMem");
						if(pSharedMemory && psm)
							*pSharedMemory=psm->CustomBuf;
						if(pOld && pNew && ppOldRet)
						{
							Hook(&pOld,pNew);
							*ppOldRet=pOld;
							customhookinfo[j].pOld=pOld;
							customhookinfo[j].hMod=(HMODULE)hMod_n;
							customhookinfo[j].pNew=pNew;

						}
						else
						{
							
							FHPrint("Custom Hook Error: Fail to get the functions' address %s %s %s\n",customHooks[j].oldName,
								customHooks[j].newName,customHooks[j].oldProcAddr);
						}
						//Msgbox(customHooks[j].oldName,(long)*ppOldRet);
					}
				}
				
				for (int j=0;j<thInfo.count;j++)
		        {
					DLLid=thInfo.DLLid[j];
					if (DLLid==9 && IsNeedSHCreateProcess && SHCreateProcess)
					{
						LoadLibrary("shell32.dll");
						VOID* pF=SHCreateProcess;
						Hook(&pF,hinfo[DLLid].pProc);
						*hinfo[DLLid].ppOld=pF;
					}
					else if(DLLid==11 && AicLaunchAdminProcess_offset)
					{
						pAicLaunchAdminProcess=(PAicLaunchAdminProcess)((char*)LoadLibraryA("windows.storage.dll")+AicLaunchAdminProcess_offset);
						VOID* pF=pAicLaunchAdminProcess;
						Hook(&pF,hinfo[DLLid].pProc);
						*hinfo[DLLid].ppOld=pF;
					}
					else
					{
						FHPrint("DLLid %d @ %d\n",DLLid,pid);
						HookIt(hinfo[DLLid].ModName,hinfo[DLLid].ProcName,hinfo[DLLid].pProc,hinfo[DLLid].ppOld);
					}
				}

				//MessageBox(0,"Inject Success!","FishHook",64);
				thInfo.count=0;		
				FHPrint("CHILD IN\n");
#ifdef _WIN64
				long sus=psm->suspend64;
				psm->suspend64=0;
				HANDLE hE= hEventHookBack64;//OpenEvent(EVENT_ALL_ACCESS,FALSE,"Global\\HookDllAPC64");
				SetEvent(hE);
#else
				long sus=psm->suspend32;
				psm->suspend32=0;
				HANDLE hE= hEventHookBack;//OpenEvent(EVENT_ALL_ACCESS,FALSE,"Global\\HookDllAPC");
				SetEvent(hE);
#endif
				if (NeedToLoad)
				{
					//Msgbox("loaad",0);
					LoadLibraryA(CurrentDLLPath);
				}

				if(sus)
					SuspendThread(GetCurrentThread());
				CreateThread(0,0,ReleaseHookProc,0,0,0);
				break;
			}

			
		}
		//Msgbox("DBG Ext?",IsDebugerExist);
		if (i==128) 
		{
			//Msgbox("32:",sizeof(SharedMemory3264));
			if (IsDebugerExist==0)
			{
				EnumKey();  //fix-me : Some say it may cause a deadlock
#ifndef _WIN64
				psm->si.type=12312;
				psm->DebugerPid=CurrentPid;
				CreateThread(NULL,0,WatchProcessProc,NULL,0,NULL);
				if (GetSystemBits()==64)
				{
					
					PROCESS_INFORMATION info;
					STARTUPINFO si;
					memset(&si,0,sizeof(si));

					si.cb=sizeof(si);
					si.wShowWindow =SW_SHOW;
					si.dwFlags=STARTF_USESHOWWINDOW;
					char path[MAX_PATH];
					GetWindowsDirectory(path,MAX_PATH);
					strcat_s(path,"\\sysnative\\rundll32.exe FishHook64.dll DLLEntry");
					long trnp;
					trnp=CreateProcess(NULL,path,NULL,NULL,0,CREATE_NEW_CONSOLE,NULL,NULL,&si,&info);
					if (trnp)
					{
						hProcess64=info.hProcess;
						psm->DebugerPid64=info.dwProcessId;
					}
				}
#endif
				EnableDebugPrivilege();
#ifdef _WIN64
				StartListening();
#endif
				IsDebugerExist=1;
				IsDebuger=1;
				if (GetModuleHandle("shell32.dll")==0)
					LoadLibrary("shell32.dll");
				
				if(IsNeedSHCreateProcess)
				{
					SHCreateProcess=(PSHCreateProcess)LocateFunc();
					if(!SHCreateProcess)
						MessageBox(0,"An error occurred when loacting function","FishHook",64);
				}

			}
			else
			{
				if(AicLaunchAdminProcess_offset!=0)
				{
					MessageBox(0,"Another FishHook instant is running!","FishHook",64);
					ExitProcess(0);
				}
			}

		}

		break;
	case DLL_PROCESS_DETACH:
#ifdef _WIN64
		IsDebugerExist=0;
#else
		if (IsDebuger)
		{
			//__asm int 3
			if (hProcess64!=0)
				TerminateProcess(hProcess64,0);
			IsDebugerExist=0;
			SetEvent(hEventRelease);
			if(psInfo64)
			{
				UnmapViewOfFile(psInfo64);
				CloseHandle(hMapFile);
			}
		}
#endif
		break;

	}
    return TRUE;
}


#ifndef _WIN64
long __stdcall SetAPIHook64(long pid,long callproc,FishHookTypes *pDLLid,long num)
{
	if (psInfo64==0)
		return 100;
	if (num<=20)
	{
		HANDLE hMsInfo=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
		long ret=WaitForSingleObject(hMsInfo,1000);
		if (ret==WAIT_TIMEOUT)
		{
			return 12;
		}
		if (callproc==0)
		{
			psm->isWatching=0;
		}
		else if(callproc!=1)
		{
			CallBackProc=(long (__stdcall *)(SharedInfo*))callproc;
			CreateThread(NULL,0,WatchProc64,NULL,0,NULL);
			CreateThread(NULL,0,WatchProc,NULL,0,NULL);
			psm->isWatching=1;
			//Msgbox("WAT",psm->isWatching);
			
		}
		psInfo64->type=109;
		psInfo64->pid=pid;
		psInfo64->data.intArray[0]=num;
		CopyMemory(&(psInfo64->data.intArray[1]),pDLLid,num*sizeof(int));
		autoHook.count=num;
		CopyMemory(autoHook.DLLid,pDLLid,num*sizeof(int));
		//MessageBox(0,"before hook","",64);
		SetEvent(hEProcess);

		WaitForSingleObject(hEProcessBack,-1);
		ResetEvent(hEProcessBack);
		ret=psInfo64->ret;
		ReleaseMutex(hMsInfo);
		CloseHandle(hMsInfo);
		return ret;
	}
	else
	{
		return 13;
	}
}

#endif


long __stdcall SuspendProcessEx(long pid)
{
#ifdef _WIN64
	if (psInfo==0)
		return 100;
#else
	if (psInfo64==0)
		return 100;
#endif
	HANDLE hMsInfo=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
	long ret=WaitForSingleObject(hMsInfo,1000);
	if (ret==WAIT_TIMEOUT)
	{
		return 12;
	}
#ifdef _WIN64
	psInfo->type=122;
	psInfo->data.Param2.p1=pid;
#else
	psInfo64->type=122;
	psInfo64->data.Param2.p1=pid;
#endif


	SetEvent(hEProcess32);

	WaitForSingleObject(hEProcessBack32,-1);
	ResetEvent(hEProcessBack32);
#ifdef _WIN64
	ret=psInfo->ret;
#else
	ret=psInfo64->ret;
#endif
	ret=psInfo64->ret;
	ReleaseMutex(hMsInfo);
	CloseHandle(hMsInfo);
	return ret;
}


long __stdcall ResumeProcessEx(long pid)
{
#ifdef _WIN64
	if (psInfo==0)
		return 100;
#else
	if (psInfo64==0)
		return 100;
#endif
	HANDLE hMsInfo=CreateMutex(&SecAttr,FALSE,"Global\\HookSharedInfoMutex64");
	long ret=WaitForSingleObject(hMsInfo,1000);
	if (ret==WAIT_TIMEOUT)
	{
		return 12;
	}
#ifdef _WIN64
	psInfo->type=121;
	psInfo->data.Param2.p1=pid;
#else
	psInfo64->type=121;
	psInfo64->data.Param2.p1=pid;
#endif
	SetEvent(hEProcess32);

	WaitForSingleObject(hEProcessBack32,-1);
	ResetEvent(hEProcessBack32);
#ifdef _WIN64
	ret=psInfo->ret;
#else
	ret=psInfo64->ret;
#endif

	ReleaseMutex(hMsInfo);
	CloseHandle(hMsInfo);
	return ret;
}

