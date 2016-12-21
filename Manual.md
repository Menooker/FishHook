# FishHook API

## First thing first
You should call InitFishHook() before you call any FishHook APIs in debugger!

## APIs only for debugger
These APIs should only be called in x86 debugger.
### SetIATHookByAPC
C prototype
```c
long __stdcall SetIATHookByAPC(HANDLE hProcess, HANDLE PID,void * callproc,FishHookTypes *pHookid,long num);
```
Description: Use remote thread to inject FishHook DLL into the target 32-bit process, and set the custom hooks and filter hooks specified in parameter pHookid.

Parameters:

  hProcess : the handle to the target process. The handle should have full access to the process.
  
  PID : the PID of the target process
  
  callproc : the user-defined filter callback function, can be null if you don't want to filter the functions.
  
  pHookid : the array of APIs to hook for the user-defined filter, FishHookTypes is defined in "def.h"
  
  num : the number of elements in pHookid
  
Returns: 0 for success.

If you what to hook all process created by a target process, whether you want to filter the "CreateProcess" event or not, you should set {HOOK_CreateProcessInternalW,HOOK_SHCreateProcess} in Windows 7 or {HOOK_CreateProcessInternalW,HOOK_AicLaunchAdminProcess} in Windows 10. If these hooks are set, FishHook will automatically inject into the newly created processes of the hooked process and set the filters and custome hooks specified by SetIATHookByAPC or SetAPIHook64. 

### SetAPIHook64
C prototype
```c
long __stdcall SetAPIHook64(long pid,long callproc,FishHookTypes *pDLLid,long num);
```
Description: Use remote thread to inject FishHook DLL into the target 64-bit process.

Returns: 0 for success.

### SetCustomHook
C prototype
```c
long __stdcall SetCustomHook(char* oldName,char* oldMod, char* newName, char* newMod, char* oldProcAddr,long is64);
```
Description: Register the custom hook in FishHook. Note that the custom hooks are not committed in the target process until SetIATHookByAPC or SetAPIHook64 is called. 

Parameters: 

  oldName : the name of the API to hook
  
  oldMod : the name of DLL where the API to hook is in
  
  newName : the exported name of the custom "fake" API to replace the target API in DLL. You should use the dumpbin tool to see your fake API's exported name in your DLL
  
  newMod : the name of DLL where you fake API is in
  
  oldProcAddr : the exported name of the variable to hold the address of the true API replaced by FishHook. You should export a function pointer variable in your DLL. FishHook will set the variable to hold the address of true API function.
  
  is64 : Is the DLL 64-bit or 32-bit? Set to 1 if true,  otherwise set to 0.

### ListenOutput
C prototype
```c
HANDLE __stdcall ListenOutput(ptOutputProc p);
typedef void (__stdcall *ptOutputProc)(char*);
```
Description: Create a thread to listen the debug output of hooked processes.

## Utility APIs
These APIs can be called in both hooked processes and the debugger.

### GetCustomSharedMemory
```c
void* __stdcall GetCustomSharedMemory();
```
Description: Get the address of the memory shared by all hooked processes and the debugger. The size of shared memory is 1024+sizeof(SharedInfo) bytes.

###FHPrint
```c
long FHPrint(char *format,...);
```
Description: printf like debug output function. The output will be listened by the thread and the callback specified by ListenOutput in the debugger.
You can call GetProcAddress(GetModuleHandle("FishHook32.dll"),"FHPrint") to get the address of this API in hooked function
