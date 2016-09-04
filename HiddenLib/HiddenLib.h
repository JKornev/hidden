#pragma once

typedef unsigned int HidStatus;

#define HID_STATUS_SUCCESSFUL(status) (status & 1)
#define HID_STATUS_CODE(status)       (status >> 1)

#define HID_SET_STATUS(state, code)   (code << 1 | (state ? 1 : 0))

typedef void*       HidContext;
typedef HidContext* PHidContext;

typedef unsigned long long HidObjId;

HidStatus Hid_Initialize(PHidContext pcontext);
void Hid_Destroy(HidContext context);

HidStatus Hid_SetState(HidContext context, int state);
HidStatus Hid_GetState(HidContext context, int* pstate);

HidStatus Hid_AddHiddenRegKey(HidContext context, wchar_t* regKey, HidObjId* objId);
HidStatus Hid_RemoveHiddenRegKey(HidContext context, HidObjId objId);
HidStatus Hid_RemoveAllHiddenRegKeys(HidContext context);

HidStatus Hid_AddHiddenRegValue(HidContext context, wchar_t* regValue, HidObjId* objId);
HidStatus Hid_RemoveHiddenRegValue(HidContext context, HidObjId objId);
HidStatus Hid_RemoveAllHiddenRegValues(HidContext context);

HidStatus Hid_AddHiddenFile(HidContext context, wchar_t* filePath, HidObjId* objId);
HidStatus Hid_RemoveHiddenFile(HidContext context, HidObjId objId);
HidStatus Hid_RemoveAllHiddenFiles(HidContext context);

HidStatus Hid_AddHiddenDir(HidContext context, wchar_t* dirPath, HidObjId* objId);
HidStatus Hid_RemoveHiddenDir(HidContext context, HidObjId objId);
HidStatus Hid_RemoveAllHiddenDirs(HidContext context);
