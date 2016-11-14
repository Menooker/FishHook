#include "stdafx.h"
#include "var.h"
#include "exports.h"
#include <stdio.h>
#include "internals.h"
#include <WinSafer.h>

 long __stdcall GetDebugerPid(long* p32,long* p64)
 {
	 if(psm)
	 {
		 if(p32)
			 *p32=psm->DebugerPid;
		 if(p64)
			 *p64=psm->DebugerPid64;
		 return 1;
	 }
	 else
		return 0;
 }


 long __stdcall GetSharedInfo()
{
	return (long)&sInfo;
}


  long FHPrint(char *format,...)
 {

    va_list argptr; //声明一个转换参数的变量
    int cnt; 
    va_start(argptr, format); //初始化变量   
    cnt = vsnprintf(PrintBuf,500 ,format, argptr);

//将带参数的字符串按照参数列表格式化到buffer中
    va_end(argptr); //结束变量列表,和va_start成对使用  
	SetEvent(hEventOutput);
    return(cnt);


 }

  void* __stdcall GetCustomSharedMemory()
  {
	  return psm->CustomBuf;
  }



  // 获取Low或Medium（系统默认）安全级别的token
HANDLE DuplicateTokenLevel(BOOL bIsLowLevel)
{
	HANDLE hToken = NULL;
	HANDLE hDuplicatedToken = NULL;
 
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &hToken))
	{
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, 0, SecurityAnonymous, TokenPrimary, &hDuplicatedToken))
		{
			SID sid = {0};
			sid.Revision = SID_REVISION;
			sid.SubAuthorityCount = 1;
			sid.IdentifierAuthority.Value[5] = 16;
			sid.SubAuthority[0] = bIsLowLevel ? SECURITY_MANDATORY_LOW_RID : SECURITY_MANDATORY_MEDIUM_RID;
			TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {0};
			tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
			tokenIntegrityLevel.Label.Sid = &sid;
			SetTokenInformation(hDuplicatedToken,
				TokenIntegrityLevel,
				&tokenIntegrityLevel,
				sizeof (TOKEN_MANDATORY_LABEL) + GetLengthSid(&sid));
		}
	}
 
	if (hToken)
		CloseHandle(hToken);
 
	return hDuplicatedToken;
}


HANDLE DupExplorerToken()
{
	DWORD dwPid = 0;
	HWND hwnd = FindWindow("Shell_TrayWnd", NULL);
	if (NULL == hwnd)
		return NULL;
	GetWindowThreadProcessId(hwnd, &dwPid);
	if (dwPid == 0)
		return NULL;
	HANDLE hExplorer = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
	if (hExplorer == NULL)
		return NULL;
	HANDLE hToken = NULL;
	OpenProcessToken(hExplorer, TOKEN_DUPLICATE, &hToken);
	CloseHandle(hExplorer);

	HANDLE hNewToken = NULL;
	DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
	CloseHandle(hToken);
	return hNewToken;

}
HANDLE CreateNormalUserToken()
{
  SAFER_LEVEL_HANDLE hLevel = NULL;
  if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &hLevel, NULL))
  {
      return NULL;
  }

  HANDLE hRestrictedToken = NULL;
  if (!SaferComputeTokenFromLevel(hLevel, NULL, &hRestrictedToken, 0, NULL))
  {
      hRestrictedToken = NULL;
  }
  SaferCloseLevel(hLevel);
  return hRestrictedToken;
};

  long __stdcall CreateNormalProcess(WCHAR* path,HANDLE* pProcess)
  {
	  HANDLE hToken=DupExplorerToken();
	  //HANDLE hToken=CreateNormalUserToken();
	  //HANDLE hToken=DuplicateTokenLevel(1);
	  if(!hToken)
		  return FH_TOKEN_ERROR;
	  PROCESS_INFORMATION info;
	  STARTUPINFOW si;
	  memset(&si,0,sizeof(si));
	  si.cb=sizeof(si);
	  si.wShowWindow =SW_SHOW;
	  si.dwFlags=STARTF_USESHOWWINDOW;
	  if(CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE,0,path,0,0,0,&si,&info))
	  {
		  CloseHandle(hToken);
		  *pProcess=info.hProcess;
		  return 0;
	  }
	  CloseHandle(hToken);
	  return FH_CREATE_PROCESS_ERROR;
  }


  long __stdcall CreateSyncBlock(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo,OUT SyncBlock* psb)
  {
	  psb->hEvent=CreateEventW(&SecAttr,FALSE,FALSE,lpEvent);
	  psb->hEventBack=CreateEventW(&SecAttr,FALSE,FALSE,lpEventBack);
	  psb->lpMutex=lpMutex;
	  psb->psinfo=psinfo;

	  //if(!psb->hEvent)
	  //  MsgboxW(L"ERR When creating event",GetLastError());
	  //MsgboxW(lpEvent,(long)psb->hEvent);
	  //MsgboxW(lpEventBack,(long)psb->hEventBack);
	  SetObjectToLowIntegrity(psb->hEvent);
	  SetObjectToLowIntegrity(psb->hEventBack);
	  return psb->hEvent && psb->hEventBack;
  }

  HANDLE __stdcall EnterSharedMemory(SyncBlock* psb)
  {
	  /// int 3
	  HANDLE hM=CreateMutexW(&SecAttr,FALSE,psb->lpMutex);
	  WaitForSingleObject(hM,-1);
//__asm int 3
	  return hM;
  }

  long __stdcall LeaveSharedMemory(HANDLE hM,SyncBlock* psb)
  {
	  //ResetEvent(psb->hEventBack);
	  long ret=ReleaseMutex(hM);
	  CloseHandle(hM);
	  return ret;
  }


  long __stdcall CallFilter(SyncBlock* psb)
  {
//	  __asm int 3
  		 SetEvent(psb->hEvent);
		 
//		 __asm int 3
		 return WaitForSingleObject(psb->hEventBack,1000);
  }

  extern long (__stdcall *CallBackProc)(SharedInfo*);
  DWORD WINAPI WatchSyncProc (LPVOID lpParam)
 { 
	 SyncBlock* psb=(SyncBlock*)lpParam;
	 while(1)
	 {
		 //Msgbox("32!",0);
		 WaitForSingleObject(psb->hEvent,-1);
		 psb->psinfo->ret= CallBackProc(psb->psinfo);
		 SetEvent(psb->hEventBack);
		 //ResetEvent(psb->hEvent);
		 
	 }
	 return 0;
 }
 long __stdcall CreateFilterPort(WCHAR* lpEvent,WCHAR* lpEventBack,WCHAR* lpMutex,SharedInfo* psinfo)
 {
	 
	  SyncBlock* psb=new SyncBlock; //fix-me: may cause memory leak!
	  if(!CreateSyncBlock(lpEvent,lpEventBack,lpMutex,psinfo,psb))
		return 12;
	  if(!CreateThread(0,0,WatchSyncProc,psb,0,0))
		  return 13;
	  
	  return 0;		

 }