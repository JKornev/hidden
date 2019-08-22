# Hidden

This toolset is developed like a solution for my reverse engineering and researching tasks. This is a windows driver with a usermode interface which is used for hidding specific environment on VMs, like installed rce programs (ex. procmon, wireshark), vm infrastracture (ex. vmware tools) and etc. 

**Features**

- hide registry keys and values
- hide files and directories
- protect specific processes using ObRegisterCallbacks
- exclude specific processes from hidding and protection features
- usermode interface (lib and cli) for working with driver

and so on

**Recommended build environment**

- Visual Studio 2013 and above
- Windows Driver Kit 8.1

**Building**

Following guide explains how to make a release win32 build
1. Open Hidden.sln using Visual Studio 2013
2. Build **Hidden Package** project with configurations Release, Win32
3. Open build results folder **%ProjectDir%\Release**

**Installing**

0. Disable a digital signature enforcement on a test machine (bcdedit /set TESTSIGNING ON)
1. Copy files from **%ProjectDir%\Release\Hidden Package** to a test machine
2. Right mouse click on **Hidden.inf** and choose **Install**
3. Start a driver (sc start hidden)
