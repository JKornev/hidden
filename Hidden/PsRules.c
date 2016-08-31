#include "PsRules.h"

#define PSRULE_ALLOC_TAG 'lRsP'

typedef struct _PsRulesInternalContext {
	RTL_AVL_TABLE table;
	ULONGLONG     idCounter;
	KSPIN_LOCK    tableLock;
} PsRulesInternalContext, *PPsRulesInternalContext;

RTL_GENERIC_COMPARE_RESULTS ComparePsRuleEntry(struct _RTL_AVL_TABLE  *Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	PPsRuleEntry first = (PPsRuleEntry)FirstStruct;
	PPsRuleEntry second = (PPsRuleEntry)SecondStruct;
	INT res;

	UNREFERENCED_PARAMETER(Table);

	res = RtlCompareUnicodeString(&first->imagePath, &second->imagePath, TRUE);

	if (res > 0)
		return GenericGreaterThan;

	if (res < 0)
		return GenericLessThan;

	return GenericEqual;
}

PVOID AllocatePsRuleEntry(struct _RTL_AVL_TABLE  *Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, PSRULE_ALLOC_TAG);
}

VOID FreePsRuleEntry(struct _RTL_AVL_TABLE  *Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, PSRULE_ALLOC_TAG);
}

NTSTATUS InitializePsRuleListContext(PPsRulesContext pRuleContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	PPsRulesInternalContext context;

	context = (PPsRulesInternalContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(PsRulesInternalContext), PSRULE_ALLOC_TAG);
	if (!context)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't allocate memory\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	context->idCounter = 0;
	KeInitializeSpinLock(&context->tableLock);
	RtlInitializeGenericTableAvl(&context->table, ComparePsRuleEntry, AllocatePsRuleEntry, FreePsRuleEntry, NULL);

	*pRuleContext = context;
	return status;
}

VOID DestroyPsRuleListContext(PsRulesContext RuleContext)
{
	RemoveAllRulesFromPsRuleList(RuleContext);
	ExFreePoolWithTag(RuleContext, PSRULE_ALLOC_TAG);
}

NTSTATUS AddRuleToPsRuleList(PsRulesContext RuleContext, PUNICODE_STRING ImgPath, ULONG InheritType, PPsRuleEntryId EntryId)
{
	PPsRulesInternalContext context = (PPsRulesInternalContext)RuleContext;
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG guid;
	PPsRuleEntry entry;
	ULONG entryLen;
	BOOLEAN newElem;
	PVOID buf;

	if (InheritType > PsRuleTypeMax)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": invalid inherit type: %d\n", InheritType);
		return STATUS_INVALID_PARAMETER_3;
	}

	entryLen = sizeof(PsRuleEntry) + ImgPath->Length;
	entry = (PPsRuleEntry)ExAllocatePoolWithTag(NonPagedPool, entryLen, PSRULE_ALLOC_TAG);
	if (!entry)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't allocate memory\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	entry->inheritType = InheritType;
	entry->len = entryLen;
	entry->imagePath.Buffer = (PWCH)(entry + 1);
	entry->imagePath.Length = 0;
	entry->imagePath.MaximumLength = ImgPath->Length;
	RtlCopyUnicodeString(&entry->imagePath, ImgPath);

	KeAcquireInStackQueuedSpinLock(&context->tableLock, &lockHandle);
	buf = RtlInsertElementGenericTableAvl(&context->table, entry, entryLen, &newElem);
	guid = context->idCounter++;
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	if (!buf)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't allocate memory for a new element\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (!newElem)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": this path already in a rules list\n");
		return STATUS_DUPLICATE_NAME;
	}

	*EntryId = guid;
	return status;
}

NTSTATUS RemoveRuleFromPsRuleList(PsRulesContext RuleContext, PsRuleEntryId EntryId)
{
	PPsRulesInternalContext context = (PPsRulesInternalContext)RuleContext;
	NTSTATUS status = STATUS_NOT_FOUND;
	KLOCK_QUEUE_HANDLE lockHandle;
	PPsRuleEntry entry;
	PVOID restartKey = NULL;

	KeAcquireInStackQueuedSpinLock(&context->tableLock, &lockHandle);

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey))
	{
		if (entry->guid == EntryId)
		{
			if (!RtlDeleteElementGenericTableAvl(&context->table, entry))
				DbgPrint("FsFilter1!" __FUNCTION__ ": can't remove element from process rules table, looks like memory leak\n");

			status = STATUS_SUCCESS;
			break;
		}
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return status;
}

NTSTATUS RemoveAllRulesFromPsRuleList(PsRulesContext RuleContext)
{
	PPsRulesInternalContext context = (PPsRulesInternalContext)RuleContext;
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	PPsRuleEntry entry;
	PVOID restartKey = NULL;

	KeAcquireInStackQueuedSpinLock(&context->tableLock, &lockHandle);

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey))
	{
		if (!RtlDeleteElementGenericTableAvl(&context->table, entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't remove element from process rules table, looks like memory leak\n");

		restartKey = NULL; // reset enum
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return status;
}

NTSTATUS CheckInPsRuleList(PsRulesContext RuleContext, PCUNICODE_STRING ImgPath, PPsRuleEntry Rule, ULONG RuleSize, PULONG OutSize)
{
	PPsRulesInternalContext context = (PPsRulesInternalContext)RuleContext;
	NTSTATUS status = STATUS_NOT_FOUND;
	KLOCK_QUEUE_HANDLE lockHandle;
	PPsRuleEntry entry;
	PVOID restartKey = NULL;

	KeAcquireInStackQueuedSpinLock(&context->tableLock, &lockHandle);

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey);
		 entry != NULL;
		 entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey))
	{
		if (RtlCompareUnicodeString(&entry->imagePath, ImgPath, TRUE) == 0)
		{
			*OutSize = entry->len;

			if (RuleSize < entry->len)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			RtlCopyMemory(Rule, entry, entry->len);
			status = STATUS_SUCCESS;
			break;
		}
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return status;
}

BOOLEAN FindInheritanceInPsRuleList(PsRulesContext RuleContext, PCUNICODE_STRING ImgPath, PULONG pInheritance)
{
	PPsRulesInternalContext context = (PPsRulesInternalContext)RuleContext;
	KLOCK_QUEUE_HANDLE lockHandle;
	PPsRuleEntry entry;
	PVOID restartKey = NULL;
	BOOLEAN result = FALSE;

	KeAcquireInStackQueuedSpinLock(&context->tableLock, &lockHandle);

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey);
		 entry != NULL;
		 entry = RtlEnumerateGenericTableWithoutSplayingAvl(&context->table, &restartKey))
	{
		if (RtlCompareUnicodeString(&entry->imagePath, ImgPath, TRUE) == 0)
		{
			*pInheritance = entry->inheritType;
			result = TRUE;
			break;
		}
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}
