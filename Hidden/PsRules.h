#pragma once

#include <Ntddk.h>

typedef PVOID PsRulesContext;
typedef PsRulesContext* PPsRulesContext;

typedef ULONGLONG PsRuleEntryId;
typedef PsRuleEntryId* PPsRuleEntryId;

enum PsRuleInheritTypes {
	PsRuleTypeWithoutInherit = 0,
	PsRuleTypeInherit,
	PsRuleTypeInheritOnce,
	PsRuleTypeMax
};

typedef struct _PsRuleEntry {
	ULONGLONG      guid;
	UNICODE_STRING imagePath;
	ULONG          inheritType;
	ULONG          len;
} PsRuleEntry, *PPsRuleEntry;

NTSTATUS InitializePsRuleListContext(PPsRulesContext pRuleContext);
VOID DestroyPsRuleListContext(PsRulesContext RuleContext);

NTSTATUS AddRuleToPsRuleList(PsRulesContext RuleContext, PUNICODE_STRING ImgPath, ULONG InheritType, PPsRuleEntryId EntryId);

NTSTATUS RemoveRuleFromPsRuleList(PsRulesContext RuleContext, PsRuleEntryId EntryId);
NTSTATUS RemoveAllRulesFromPsRuleList(PsRulesContext RuleContext);

NTSTATUS CheckInPsRuleList(PsRulesContext RuleContext, PCUNICODE_STRING ImgPath, PPsRuleEntry Rule, ULONG RuleSize, PULONG OutSize);
BOOLEAN FindInheritanceInPsRuleList(PsRulesContext RuleContext, PCUNICODE_STRING ImgPath, PULONG pInheritance);
