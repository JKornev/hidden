# Hidden

This toolset is developed like a solution for my reverse engineering and researching tasks. This is a windows driver with a usermode interface which is used for hidding specific environment on VMs, like installed rce programs (ex. procmon, wireshark), vm infrastracture (ex. vmware tools) and etc. 

**Features**

- hide registry keys and values
- hide files and directories
- protect specific processes using ObRegisterCallbacks
- exclude specific processes from hidding and protection features
- usermode interface (lib and cli) for working with driver

and so on

**System requirements**

Works on Windows Vista and above, x86 and x64

**Recommended build environment**

- Visual Studio 2013 and above
- Windows Driver Kit 8.1 and above

**Building**

Following guide explains how to make a release win32 build
1. Open Hidden.sln using Visual Studio
2. Build **Hidden Package** project with configurations Release, Win32
3. Open build results folder **\<ProjectDir\>\Release**

**Installing**

1. Disable a digital signature enforcement on a test machine (bcdedit /set TESTSIGNING ON)
2. Copy files from **\<ProjectDir\>\Release\Hidden Package** to a test machine
3. Right mouse click on **Hidden.inf** and choose **Install**
4. Start a driver (sc start hidden)
5. Make sure service is running (sc query hidden)

**Hiding**

A command line tool **hiddencli** is used for managing a driver. You are able to use it for hiding and unhiding objects, changing a driver state and so on.

To hide a calc.exe try this one
```
hiddencli /hide file c:\Windows\System32\calc.exe
```

Want to hide directory? No problems
```
hiddencli /hide dir "c:\Program Files\VMWare"
```

Registry key?
```
hiddencli /hide regkey "HKCU\Software\VMware, Inc."
```

To get a full help just type
```
hiddencli /help
```
