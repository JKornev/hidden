# Hidden

This toolset developed like a solution for my reverse engineering and researching tasks. This is a very simple windows driver with a usermode interface which uses for hidding specific environment on VMs, like installed rce programs (ex. procmon, wireshark), vm infrastracture (ex. vmware tools) and etc. 

Features:
- hide registry keys and values
- hide files and directories
- protect specific processes using ObRegisterCallbacks
- exclude specific processes from hidding and protection features
- usermode interface (lib and cli) for working with driver

and so on
