#pragma once

#include <Ntddk.h>

VOID InitializeKernelAnalyzer();
VOID DestroyKernelAnalyzer();

PVOID GetPspCidTablePointer();
