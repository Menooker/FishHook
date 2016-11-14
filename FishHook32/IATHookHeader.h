#include <windows.h>
#include <imagehlp.h>


typedef long (__stdcall *pf0)();
typedef long (__stdcall *pf1)(long);
typedef long (__stdcall *pf2)(long,long);
typedef long (__stdcall *pf3)(long,long,long);
typedef long (__stdcall *pf4)(long,long,long,long);
typedef long (__stdcall *pf5)(long,long,long,long,long);
typedef long (__stdcall *pf6)(long,long,long,long,long,long);
typedef long (__stdcall *pf7)(long,long,long,long,long,long,long);
typedef long (__stdcall *pf8)(long,long,long,long,long,long,long,long);
typedef long (__stdcall *pf9)(long,long,long,long,long,long,long,long,long);
typedef long (__stdcall *pf10)(long,long,long,long,long,long,long,long,long,long);
typedef long (__stdcall *pf11)(long,long,long,long,long,long,long,long,long,long,long);


     long __stdcall p0();
     long __stdcall p1(long a1);
     long __stdcall p2(long a1,long a2);
     long __stdcall p3(long a1,long a2,long a3);
     long __stdcall p4(long a1,long a2,long a3,long a4);
     long __stdcall p5(long a1,long a2,long a3,long a4,long a5);
     long __stdcall p6(long a1,long a2,long a3,long a4,long a5,long a6);
     long __stdcall p7(long a1,long a2,long a3,long a4,long a5,long a6,long a7);
     long __stdcall p8(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8);
     long __stdcall p9(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8,long a9);
     long __stdcall p10(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8,long a9,long a10);


struct IATHook
{
    // pf0 pNew0;
     pf1 pNew1;
     pf2 pNew2;
     pf3 pNew3;
     pf4 pNew4;
     pf5 pNew5;
     pf6 pNew6;
     pf7 pNew7;
     pf8 pNew8;
     pf9 pNew9;
     pf10 pNew10;
     pf11 pNew11;

	 pf0 pOld0;
     pf1 pOld1;
     pf2 pOld2;
     pf3 pOld3;
     pf4 pOld4;
     pf5 pOld5;
     pf6 pOld6;
     pf7 pOld7;
     pf8 pOld8;
     pf9 pOld9;
     pf10 pOld10;
     int num;
    
};

long InitIATHook(char *pDllName,const char *pApiName ,void *pNew,int num)
    {
	    IATHook *p=malloc(sizeof(IATHook));
        funptr[0]=(PVOID)p0;
        funptr[1]=(PVOID)p1;
        funptr[2]=(PVOID)p2;
        funptr[3]=(PVOID)p3;
        funptr[4]=(PVOID)p4;
        funptr[5]=(PVOID)p5;
        funptr[6]=(PVOID)p6;
        funptr[7]=(PVOID)p7;
        funptr[8]=(PVOID)p8;
        funptr[9]=(PVOID)p9;
        funptr[10]=(PVOID)p10;
        void** ppNew[10]={&p->pNew1,&pNew2,&pNew3,&pNew4,&pNew5,&pNew6,&pNew7,&pNew8,&pNew9,&pNew10,&pNew11};
        void** ppOld[10]={&p->pOld0,&p->pOld1,&p->pOld2,&p->pOld3,&p->pOld4,&p->pOld5,&p->pOld6,&p->pOld7,&p->pOld8,&p->pOld9,&p->pOld10};
        replace_IAT_a(pDllName,pApiName,funptr[num],ppOld[num]);


    }


int replace_IAT_a(const char *pDllName,const char *pApiName,void *pNew,PVOID * pOld)
 {
  HANDLE hProcess = GetModuleHandle (NULL);
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
    if (0 == strcmpi(pApiName,(char*)pImageImportByName->Name))
    {
     MEMORY_BASIC_INFORMATION mbi_thunk;
     VirtualQuery(pImageThunkReal, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));
     VirtualProtect(mbi_thunk.BaseAddress,mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect);

      *pOld = pImageThunkReal->u1.Function;
      pImageThunkReal->u1.Function = (DWORD*)pNew;
      MessageBox(NULL, pApiName,"in",64);
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



     long __stdcall p0()
    {
        return pNew1((long)pOld0);
    }


     long __stdcall p1(long a1)
    {
        return pNew2((long)pOld1,a1);
    }

     long __stdcall p2(long a1,long a2)
    {
        return pNew3((long)pOld2,a1,a2);
    }

     long __stdcall p3(long a1,long a2,long a3)
    {
        return pNew4((long)pOld3,a1,a2,a3);
    }

     long __stdcall p4(long a1,long a2,long a3,long a4)
    {
        return pNew5((long)pOld4,a1,a2,a3,a4);
    }

     long __stdcall p5(long a1,long a2,long a3,long a4,long a5)
    {
        return pNew6((long)pOld5,a1,a2,a3,a4,a5);
    }


     long __stdcall p6(long a1,long a2,long a3,long a4,long a5,long a6)
    {
        return pNew7((long)pOld6,a1,a2,a3,a4,a5,a6);
    }

     long __stdcall p7(long a1,long a2,long a3,long a4,long a5,long a6,long a7)
    {
        return pNew8((long)pOld7,a1,a2,a3,a4,a5,a6,a7);
    }

     long __stdcall p8(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8)
    {
        return pNew9((long)pOld8,a1,a2,a3,a4,a5,a6,a7,a8);
    }

     long __stdcall p9(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8,long a9)
    {
        return pNew10((long)pOld9,a1,a2,a3,a4,a5,a6,a7,a8,a9);
    }

     long __stdcall p10(long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8,long a9,long a10)
    {
        return pNew11((long)pOld10,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10);
    }


