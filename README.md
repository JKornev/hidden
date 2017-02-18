# Hidden

This toolset is developed like as solution for my reverse engineering and researching tasks. This is a windows driver with a usermode interface which is used for hidding specific environment on VMs, like installed rce programs (ex. procmon, wireshark), vm infrastracture (ex. vmware tools) and etc. 

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
