#include <Windows.h>
#pragma once
 #define OBJ_CASE_INSENSITIVE 0x00000040L
typedef LONG  NTSTATUS;
#include <winternl.h>
//#define long NTSTATUS
/* typedef struct _UNICODE_STRING 
{
     USHORT Length;
     USHORT MaximumLength;
     PWSTR  Buffer;
 } UNICODE_STRING, *PUNICODE_STRING;
 typedef struct _OBJECT_ATTRIBUTES {
     ULONG           Length;
     HANDLE          RootDirectory;
     PUNICODE_STRING ObjectName; 

    ULONG           Attributes;
     PVOID           SecurityDescriptor;
     PVOID           SecurityQualityOfService;
 } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;*/
 typedef long (WINAPI *ZWOPENKEY)
 (
     __out  PHANDLE KeyHandle,
     __in   ACCESS_MASK DesiredAccess,
     __in   POBJECT_ATTRIBUTES ObjectAttributes
 );
 typedef NTSTATUS (WINAPI *ZWSETVALUEKEY)
 (
     __in      HANDLE KeyHandle,
     __in      PUNICODE_STRING ValueName,
     __in_opt  ULONG TitleIndex,
     __in      ULONG Type,
     __in_opt  PVOID Data,
     __in      ULONG DataSize
 );
 typedef NTSTATUS (WINAPI *ZWCLOSE)
 (  
     __in  HANDLE Handle
 );
 typedef VOID (WINAPI *RTLINITUNICODESTRING)
 (
     __inout   PUNICODE_STRING DestinationString,
     __in_opt  PCWSTR SourceString
 );


 typedef enum _KEY_INFORMATION_CLASS { 
  KeyBasicInformation           = 0,
  KeyNodeInformation            = 1,
  KeyFullInformation            = 2,
  KeyNameInformation            = 3,
  KeyCachedInformation          = 4,
  KeyFlagsInformation           = 5,
  KeyVirtualizationInformation  = 6,
  KeyHandleTagsInformation      = 7,
  MaxKeyInfoClass               = 8
} KEY_INFORMATION_CLASS;


 typedef NTSTATUS (WINAPI *ZWQUERYKEY)(
  _In_       HANDLE KeyHandle,
  _In_       KEY_INFORMATION_CLASS KeyInformationClass,
  _Out_opt_  PVOID KeyInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
);
  typedef struct _KEY_NAME_INFORMATION {
  ULONG NameLength;
  WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef NTSTATUS (WINAPI *NTCREATEFILE)(
  _Out_     PHANDLE FileHandle,
  _In_      ACCESS_MASK DesiredAccess,
  _In_      POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_     PIO_STATUS_BLOCK IoStatusBlock,
  _In_opt_  PLARGE_INTEGER AllocationSize,
  _In_      ULONG FileAttributes,
  _In_      ULONG ShareAccess,
  _In_      ULONG CreateDisposition,
  _In_      ULONG CreateOptions,
  _In_      PVOID EaBuffer,
  _In_      ULONG EaLength
);







 /*

 //设置 ObjectAttributes的值
 VOID InitializeObjectAttributes (OUT POBJECT_ATTRIBUTES
 InitializedAttributes, IN PUNICODE_STRING ObjectName, IN ULONGAttributes, IN
 HANDLE RootDirectory, IN PSECURITY_DESCRIPTOR SecurityDescriptor)
 { 
    InitializedAttributes->Length = sizeof( OBJECT_ATTRIBUTES ); 
    InitializedAttributes->RootDirectory = RootDirectory;    
 
    InitializedAttributes->Attributes = Attributes; 
    InitializedAttributes->ObjectName = ObjectName; 
InitializedAttributes->SecurityDescriptor = SecurityDescriptor; 
    InitializedAttributes->SecurityQualityOfService = NULL; 
    return; 
}
 //初始化用到的api
 void InitApi()
 {
 //获得 ZwSetValueKey的函数指针
 
ZwSetValueKey=(ZWSETVALUEKEY)GetProcAddress(LoadLibraryW(L"ntdll.dll"),"ZwS
 etValueKey");    
 //获得 ZwOpenKey的函数指针
 
ZwOpenKey=(ZWOPENKEY)GetProcAddress(LoadLibraryW(L"ntdll.dll"),"ZwOpenKey")
 ;
 //获得 ZwClose的函数指针
     ZwClose=(ZWCLOSE)GetProcAddress(LoadLibraryW(L"ntdll.dll"),"ZwClose");
 RtlInitUnicodeString=(RTLINITUNICODESTRING)GetProcAddress(LoadLibraryW(L"nt
 dll.dll"),"RtlInitUnicodeString");

 }*/