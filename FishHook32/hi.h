// ITAHook.cpp : Defines the entry point for the console application.
//
#pragma once
#include "stdafx.h"



 #include <windows.h>
#include <imagehlp.h>

 //#include <Dbghelp.h>

 #pragma comment(lib,"imagehlp.lib")
 #pragma comment(lib,"User32.lib")

 




int replace_IAT(const char *pDllName,const char *pApiName,void *pNew,PVOID * pOld)
 {

  HANDLE hProcess = ::GetModuleHandle (NULL);
  DWORD dwSize = 0;
  PIMAGE_IMPORT_DESCRIPTOR pImageImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hProcess,TRUE,
   IMAGE_DIRECTORY_ENTRY_IMPORT,&dwSize);
  if (NULL == pImageImport)
   return 1;
  PIMAGE_IMPORT_BY_NAME pImageImportByName = NULL;
  PIMAGE_THUNK_DATA  pImageThunkOriginal = NULL;
  PIMAGE_THUNK_DATA  pImageThunkReal  = NULL;
  while (pImageImport->Name)
  {
   if (0 == strcmpi((char*)((PBYTE)hProcess+pImageImport->Name),pDllName))
   {
    break;
   }
   ++pImageImport;
  }
  if (! pImageImport->Name)
   return 2;
  pImageThunkOriginal = (PIMAGE_THUNK_DATA)((PBYTE)hProcess+pImageImport->OriginalFirstThunk  );
  pImageThunkReal = (PIMAGE_THUNK_DATA)((PBYTE)hProcess+pImageImport->FirstThunk   );
  while (pImageThunkOriginal->u1.Function)
  {
   if ((pImageThunkOriginal->u1 .Ordinal & IMAGE_ORDINAL_FLAG) != IMAGE_ORDINAL_FLAG)
   {
    pImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hProcess+(long)pImageThunkOriginal->u1 .AddressOfData );
    //MessageBox(0,(char*)pImageImportByName->Name,"",64);
	if (0 == strcmpi(pApiName,(char*)pImageImportByName->Name))
    {

     MEMORY_BASIC_INFORMATION mbi_thunk;
     VirtualQuery(pImageThunkReal, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION)); 
     VirtualProtect(mbi_thunk.BaseAddress,mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect); 

      *pOld =(PVOID) pImageThunkReal->u1.Function; 
      pImageThunkReal->u1.Function = (DWORD)pNew;
      	
     DWORD dwOldProtect; 
     VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &dwOldProtect); 

     break;
    }
   }
   ++pImageThunkOriginal;
   ++pImageThunkReal;
  }
  return 0;
 }

 int chk_IAT(const char *pDllName,const char *pApiName ,void** pOut)
 {

  HANDLE hProcess = ::GetModuleHandle (NULL);
  DWORD dwSize = 0;
  PIMAGE_IMPORT_DESCRIPTOR pImageImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hProcess,TRUE,
   IMAGE_DIRECTORY_ENTRY_IMPORT,&dwSize);
  if (NULL == pImageImport)
   return 1;
  PIMAGE_IMPORT_BY_NAME pImageImportByName = NULL;
  PIMAGE_THUNK_DATA  pImageThunkOriginal = NULL;
  PIMAGE_THUNK_DATA  pImageThunkReal  = NULL;
  while (pImageImport->Name)
  {
   if (0 == strcmpi((char*)((PBYTE)hProcess+pImageImport->Name),pDllName))
   {
    break;
   }
   ++pImageImport;
  }
  if (! pImageImport->Name)
   return 2;
  pImageThunkOriginal = (PIMAGE_THUNK_DATA)((PBYTE)hProcess+pImageImport->OriginalFirstThunk  );
  pImageThunkReal = (PIMAGE_THUNK_DATA)((PBYTE)hProcess+pImageImport->FirstThunk   );
  while (pImageThunkOriginal->u1.Function)
  {
   if ((pImageThunkOriginal->u1 .Ordinal & IMAGE_ORDINAL_FLAG) != IMAGE_ORDINAL_FLAG)
   {
    pImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hProcess+(long)pImageThunkOriginal->u1 .AddressOfData );
    //MessageBox(0,(char*)pImageImportByName->Name,"",64);
	if (0 == strcmpi(pApiName,(char*)pImageImportByName->Name))
    {
		
	    *pOut=(PVOID) pImageThunkReal->u1.Function; 

     break;
    }
   }
   ++pImageThunkOriginal;
   ++pImageThunkReal;
  }
  return 0;
 }

 