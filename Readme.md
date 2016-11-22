# FishHook
FishHook is a Windows inline hook platform, which supports x86 and x64 environment. You can write filter routines to monitor or alter the behavior of other programs's API. Also, you can write your own "fake" APIs in your own DLL, and FishHook will inject your DLL into the process and replace the target API with your "fake" one. Besides, FishHook provides a function to hook the child-processes created by a "hooked" process, which is useful for building a "sandbox" environment.

## How to build
### Dependencies
 * Visual Studio 2010. The community version is free.
 * Detours Express 3.0 x86
 * Detours x64. Original Detours x64 is charged. [Here](http://bbs.pediy.com/showthread.php?t=156369) is a third-party-made Detours x64 lib, which is based on mhook.
### Build me
This repo includes a VS2010 solution. Open FishHook32.sln. Build x86 version of the project "FishHook32". This generates "FishHook32.dll". Then switch to x64 mode and build the project "FishHook32" again. This generates "FishHook64.dll". Finally, switch to x86 mode and build and run project FishHookTest, which is an example of FishHook.

## How FishHook works
A process that initializes FishHook and filters the API calls of hooked processes is called "debugger". Only one debugger is running at a time, and a debugger is a 32-bit process. This means even though you run FishHook on a 64 bit system, usually you should call FishHook APIs in a 32-bit debugger. (However, your custom "fake" APIs can be written in x64 code.)
The easiest way to use FishHook is to implement a filter. FishHook has implemented some "fake" APIs, such as CreateProcessInternalW and ZwSetValueKey. You should give FishHook a process-id to hook and the list of identifiers of the built-in "fake" APIs you want to hook. In addition, you should write a filter program in your 32-bit debugger. FishHook will replace the APIs with its built-in "fake" APIs. Once the hooked process calls the hooked API, the user-defined filter routine will be called, and you can monitor or alter the behavoir of the API in your filter.
The other way to utilize FishHook is to use custom hooks. You should write the your "fake" APIs in DLLs, and pass the DLL and a process-id to FishHook. FishHook will inject your DLL and replace the target API with yours. Now you can do whatever you want.
Some may want to hook the child-process created by a hooked process, which is a common way to build a sandbox or a monitor program. FishHook provides built-in "fake" APIs which will automatically hook the newly created process launched by a hooked program. 