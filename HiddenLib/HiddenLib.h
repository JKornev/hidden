#pragma once

typedef unsigned long long HidStatus;

#define HID_STATUS_SUCCESSFUL(status)                     (status & 1)
#define HID_STATUS_CODE(status)             (unsigned int)(status >> 1)

#define HID_SET_STATUS(state, code)   (unsigned long long)((unsigned long long)code << 1 | (state ? 1 : 0))

#define HID_NORMALIZATION_OVERHEAD                         100

#define _API __cdecl

typedef void*       HidContext;
typedef HidContext* PHidContext;

typedef unsigned long long HidObjId;

typedef unsigned long HidProcId;

enum class HidActiveState
{
	StateDisabled = 0,
	StateEnabled
};

// Important note:
// This enum should be equal to PsRuleInheritTypes (PsRules.h)
enum class HidPsInheritTypes
{
	WithoutInherit = 0,
	InheritAlways,
	InheritOnce,
	InheritMax
};

enum class HidRegRootTypes
{
	RegHKCU,
	RegHKLM,
	RegHKU
};

HidStatus _API Hid_InitializeWithNoConnection();
HidStatus _API Hid_Initialize(PHidContext pcontext, const wchar_t* deviceName = 0);
void _API Hid_Destroy(HidContext context);

HidStatus _API Hid_SetState(HidContext context, HidActiveState state);
HidStatus _API Hid_GetState(HidContext context, HidActiveState* pstate);

// Fs\Reg

HidStatus _API Hid_AddHiddenRegKey(HidContext context, HidRegRootTypes root, const wchar_t* regKey, HidObjId* objId);
HidStatus _API Hid_RemoveHiddenRegKey(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllHiddenRegKeys(HidContext context);

HidStatus _API Hid_AddHiddenRegValue(HidContext context, HidRegRootTypes root, const wchar_t* regValue, HidObjId* objId);
HidStatus _API Hid_RemoveHiddenRegValue(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllHiddenRegValues(HidContext context);

HidStatus _API Hid_AddHiddenFile(HidContext context, const wchar_t* filePath, HidObjId* objId);
HidStatus _API Hid_RemoveHiddenFile(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllHiddenFiles(HidContext context);

HidStatus _API Hid_AddHiddenDir(HidContext context, const wchar_t* dirPath, HidObjId* objId);
HidStatus _API Hid_RemoveHiddenDir(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllHiddenDirs(HidContext context);

// Ps

HidStatus _API Hid_AddExcludedImage(HidContext context, const wchar_t* imagePath, HidPsInheritTypes inheritType, bool applyForProcess, HidObjId* objId);
HidStatus _API Hid_RemoveExcludedImage(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllExcludedImages(HidContext context);
HidStatus _API Hid_GetExcludedState(HidContext context, HidProcId procId, HidActiveState* state, HidPsInheritTypes* inheritType);
HidStatus _API Hid_AttachExcludedState(HidContext context, HidProcId procId, HidPsInheritTypes inheritType);
HidStatus _API Hid_RemoveExcludedState(HidContext context, HidProcId procId);

HidStatus _API Hid_AddProtectedImage(HidContext context, const wchar_t* imagePath, HidPsInheritTypes inheritType, bool applyForProcess, HidObjId* objId);
HidStatus _API Hid_RemoveProtectedImage(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllProtectedImages(HidContext context);
HidStatus _API Hid_GetProtectedState(HidContext context, HidProcId procId, HidActiveState* state, HidPsInheritTypes* inheritType);
HidStatus _API Hid_AttachProtectedState(HidContext context, HidProcId procId, HidPsInheritTypes inheritType);
HidStatus _API Hid_RemoveProtectedState(HidContext context, HidProcId procId);

HidStatus _API Hid_AddHiddenImage(HidContext context, const wchar_t* imagePath, HidPsInheritTypes inheritType, bool applyForProcess, HidObjId* objId);
HidStatus _API Hid_RemoveHiddenImage(HidContext context, HidObjId objId);
HidStatus _API Hid_RemoveAllHiddenImages(HidContext context);
HidStatus _API Hid_RemoveAllHiddenProcesses(HidContext context);
HidStatus _API Hid_GetHiddenState(HidContext context, HidProcId procId, HidActiveState* state, HidPsInheritTypes* inheritType);
HidStatus _API Hid_AttachHiddenState(HidContext context, HidProcId procId, HidPsInheritTypes inheritType);
HidStatus _API Hid_RemoveHiddenState(HidContext context, HidProcId procId);

// Misc

HidStatus _API Hid_NormalizeFilePath(const wchar_t* filePath, wchar_t* normalized, size_t normalizedLen);
HidStatus _API Hid_NormalizeRegistryPath(HidRegRootTypes root, const wchar_t* regPath, wchar_t* normalized, size_t normalizedLen);
