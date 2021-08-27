#pragma once

#include <Ntddk.h>

VOID InitializeKernelAnalyzer();
VOID DestroyKernelAnalyzer();

PVOID GetPspCidTablePointer();

PLIST_ENTRY GetActiveProcessLinksList(PEPROCESS Process);