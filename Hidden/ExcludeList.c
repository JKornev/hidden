#include "ExcludeList.h"
//#include <Ntifs.h>

#define EXCLUDE_ALLOC_TAG 'LcxE'

typedef struct _EXCULE_FILE_PATH {
	UNICODE_STRING fullPath;
	UNICODE_STRING dirName;
	UNICODE_STRING fileName;
} EXCULE_FILE_PATH, *PEXCULE_FILE_PATH;

typedef struct _EXCLUDE_FILE_LIST_ENTRY {
	LIST_ENTRY       list;
	ULONGLONG        guid;
	ULONGLONG        parentGuid;
	EXCULE_FILE_PATH path;
} EXCLUDE_FILE_LIST_ENTRY, *PEXCLUDE_FILE_LIST_ENTRY;

typedef struct _EXCLUDE_FILE_CONTEXT {
	LIST_ENTRY       listHead;
	FAST_MUTEX       listLock;
	ULONGLONG        guidCounter;
	UINT32           childCounter;
	UINT32           type;
} EXCLUDE_FILE_CONTEXT, *PEXCLUDE_FILE_CONTEXT;

NTSTATUS AddExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FilePath, UINT32 Type, PExcludeEntryId EntryId, ExcludeEntryId ParentId);

BOOLEAN FillDirectoryFromPath(PEXCULE_FILE_PATH path, PUNICODE_STRING filePath);

unsigned int GetCrc32(void* buf, unsigned int size, unsigned int ivect);

NTSTATUS RtlDowncaseUnicodeString(
	PUNICODE_STRING  DestinationString,
	_In_ PCUNICODE_STRING SourceString,
	_In_ BOOLEAN          AllocateDestinationString
);

// ==========================================================================================

NTSTATUS InitializeExcludeListContext(PExcludeContext Context, UINT32 Type)
{
	PEXCLUDE_FILE_CONTEXT cntx;

	if (Type >= ExcludeMaxType)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, invalid exclude list type: %d\n", Type);
		return STATUS_INVALID_MEMBER;
	}

	cntx = (PEXCLUDE_FILE_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(EXCLUDE_FILE_CONTEXT), EXCLUDE_ALLOC_TAG);
	if (!cntx)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate memory for context: %p\n", Context);
		return STATUS_ACCESS_DENIED;
	}

	InitializeListHead(&cntx->listHead);
	ExInitializeFastMutex(&cntx->listLock);
	cntx->guidCounter = 1;
	cntx->childCounter = 0;
	cntx->type = Type;

	*Context = cntx;

	return STATUS_SUCCESS;
}

VOID DestroyExcludeListContext(ExcludeContext Context)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	RemoveAllExcludeListEntries(Context);
	ExFreePoolWithTag(cntx, EXCLUDE_ALLOC_TAG);
}

NTSTATUS AddExcludeListFile(ExcludeContext Context, PUNICODE_STRING FilePath, PExcludeEntryId EntryId, ExcludeEntryId ParentId)
{
	return AddExcludeListEntry(Context, FilePath, ExcludeFile, EntryId, ParentId);
}

NTSTATUS AddExcludeListDirectory(ExcludeContext Context, PUNICODE_STRING DirPath, PExcludeEntryId EntryId, ExcludeEntryId ParentId)
{
	return AddExcludeListEntry(Context, DirPath, ExcludeDirectory, EntryId, ParentId);
}

NTSTATUS AddExcludeListRegistryKey(ExcludeContext Context, PUNICODE_STRING KeyPath, PExcludeEntryId EntryId, ExcludeEntryId ParentId)
{
	return AddExcludeListEntry(Context, KeyPath, ExcludeRegKey, EntryId, ParentId);
}

NTSTATUS AddExcludeListRegistryValue(ExcludeContext Context, PUNICODE_STRING ValuePath, PExcludeEntryId EntryId, ExcludeEntryId ParentId)
{
	return AddExcludeListEntry(Context, ValuePath, ExcludeRegValue, EntryId, ParentId);
}

NTSTATUS AddExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FilePath, UINT32 Type, PExcludeEntryId EntryId, ExcludeEntryId ParentId)
{
	enum { MAX_PATH_SIZE = 1024 };
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry, head;
	UNICODE_STRING temp;
	SIZE_T size;

	if (cntx->type != Type)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": warning, type isn't equal: %d != %d\n", cntx->type, Type);
		return STATUS_INVALID_MEMBER;
	}

	if (FilePath->Length == 0 || FilePath->Length >= MAX_PATH_SIZE)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": warning, invalid string size : %d\n", (UINT32)FilePath->Length);
		return STATUS_ACCESS_DENIED;
	}

	// Allocate and fill new list entry
	
	size = sizeof(EXCLUDE_FILE_LIST_ENTRY) + FilePath->Length + sizeof(WCHAR);
	entry = ExAllocatePoolWithTag(NonPagedPool, size, EXCLUDE_ALLOC_TAG);
	if (entry == NULL)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": warning, exclude file list is not NULL : %p\n", cntx);
		return STATUS_ACCESS_DENIED;
	}

	RtlZeroMemory(entry, size);

	temp.Buffer = (PWCH)((PCHAR)entry + sizeof(EXCLUDE_FILE_LIST_ENTRY));
	temp.Length = 0;
	temp.MaximumLength = FilePath->Length;

	RtlCopyUnicodeString(&temp, FilePath);

	if (!FillDirectoryFromPath(&entry->path, &temp))
	{
		ExFreePoolWithTag(entry, EXCLUDE_ALLOC_TAG);
		DbgPrint("FsFilter1!" __FUNCTION__ ": warning, exclude file list is not NULL : %p\n", cntx);
		return STATUS_ACCESS_DENIED;
	}

	// Push new list entry to context

	if (Type == ExcludeRegKey || Type == ExcludeRegValue)
	{
		// We should add new entry in alphabet order
		head = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
		while (head != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
		{
			INT res = RtlCompareUnicodeString(&entry->path.fullPath, &head->path.fullPath, TRUE);
			if (res <= 0)
				break;

			head = (PEXCLUDE_FILE_LIST_ENTRY)head->list.Flink;
		}
	}
	else
	{
		head = (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead;
	}

	// Parent GUID is used when we want to link few entries in a group with one master,
	// in this case parent GUID should be any valid entry GUID. When we remove parent entry
	// all it's children will be removed too
	entry->parentGuid = ParentId;
	
	ExAcquireFastMutex(&cntx->listLock);
	
	if (entry->parentGuid)
		cntx->childCounter++;

	entry->guid = cntx->guidCounter++;
	InsertTailList((PLIST_ENTRY)head, (PLIST_ENTRY)entry);
	
	ExReleaseFastMutex(&cntx->listLock);

	*EntryId = entry->guid;

	return STATUS_SUCCESS;
}

NTSTATUS RemoveExcludeListEntry(ExcludeContext Context, ExcludeEntryId EntryId)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		if (EntryId == entry->guid)
		{
			RemoveEntryList((PLIST_ENTRY)entry);
			ExFreePoolWithTag(entry, EXCLUDE_ALLOC_TAG);
			status = STATUS_SUCCESS;
			break;
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}
	
	if (cntx->childCounter)
	{
		entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
		while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
		{
			PEXCLUDE_FILE_LIST_ENTRY remove = entry;
			entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;

			if (EntryId == remove->parentGuid)
			{
				ASSERT(cntx->childCounter > 0);
				cntx->childCounter--;
				RemoveEntryList((PLIST_ENTRY)remove);
				ExFreePoolWithTag(remove, EXCLUDE_ALLOC_TAG);
			}
			
		}
	}

	ExReleaseFastMutex(&cntx->listLock);

	return status;
}

NTSTATUS RemoveAllExcludeListEntries(ExcludeContext Context)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		PEXCLUDE_FILE_LIST_ENTRY remove = entry;
		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
		if (remove->parentGuid)
		{
			ASSERT(cntx->childCounter > 0);
			cntx->childCounter--;
		}
		RemoveEntryList((PLIST_ENTRY)remove);
		ExFreePoolWithTag(remove, EXCLUDE_ALLOC_TAG);
	}

	ASSERT(cntx->childCounter == 0);

	ExReleaseFastMutex(&cntx->listLock);

	return STATUS_SUCCESS;
}

BOOLEAN CheckExcludeListFile(ExcludeContext Context, PCUNICODE_STRING Path)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;
	BOOLEAN result = FALSE;

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		if (RtlCompareUnicodeString(&entry->path.fullPath, Path, TRUE) == 0)
		{
			result = TRUE;
			break;
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&cntx->listLock);

	return result;
}

BOOLEAN CheckExcludeListDirectory(ExcludeContext Context, PCUNICODE_STRING Path)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;
	UNICODE_STRING Directory, dir;
	BOOLEAN result = FALSE;

	Directory = *Path;
	if (Directory.Length > 0 && Directory.Buffer[Directory.Length / sizeof(WCHAR) - 1] == L'\\')
		Directory.Length -= sizeof(WCHAR);

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		dir = Directory;

		if (dir.Length >= entry->path.fullPath.Length)
		{
			BOOLEAN compare = TRUE;

			if (dir.Length > entry->path.fullPath.Length)
			{
				if (dir.Buffer[entry->path.fullPath.Length / sizeof(WCHAR)] != L'\\')
					compare = FALSE;
				else
					dir.Length = entry->path.fullPath.Length;
			}

			if (compare && RtlCompareUnicodeString(&entry->path.fullPath, &dir, TRUE) == 0)
			{
				result = TRUE;
				break;
			}
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&cntx->listLock);

	return result;
}

BOOLEAN CheckExcludeListDirFile(ExcludeContext Context, PCUNICODE_STRING Dir, PCUNICODE_STRING File)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;
	UNICODE_STRING Directory;
	BOOLEAN result = FALSE;

	Directory = *Dir;

	if (Directory.Length > 0 && Directory.Buffer[Directory.Length / sizeof(WCHAR) - 1] == L'\\')
		Directory.Length -= sizeof(WCHAR);

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		if (RtlCompareUnicodeString(&entry->path.dirName, &Directory, TRUE) == 0
		 && RtlCompareUnicodeString(&entry->path.fileName, File, TRUE) == 0)
		{
			result = TRUE;
			break;
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&cntx->listLock);

	return result;
}

BOOLEAN CheckExcludeListRegKey(ExcludeContext Context, PUNICODE_STRING Key)
{
	return CheckExcludeListDirectory(Context, Key);
}

BOOLEAN CheckExcludeListRegKeyValueName(ExcludeContext Context, PUNICODE_STRING Key, PUNICODE_STRING Name, PUINT32 Increament)
{
	PEXCLUDE_FILE_CONTEXT cntx = (PEXCLUDE_FILE_CONTEXT)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;
	UNICODE_STRING Directory;
	BOOLEAN result = FALSE;

	Directory = *Key;
	*Increament = 0;

	if (Directory.Length > 0 && Directory.Buffer[Directory.Length / sizeof(WCHAR)-1] == L'\\')
		Directory.Length -= sizeof(WCHAR);

	ExAcquireFastMutex(&cntx->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)cntx->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&cntx->listHead)
	{
		if (RtlCompareUnicodeString(&entry->path.dirName, &Directory, TRUE) == 0)
		{
			INT res;

			res = RtlCompareUnicodeString(&entry->path.fileName, Name, TRUE);
			if (res == 0)
			{
				(*Increament)++;
				result = TRUE;
				break;
			}
			else if (res < 0)
			{
				(*Increament)++;
			}
			else if (res > 0)
			{	
				break;
			}
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&cntx->listLock);

	return result;
}

// ==========================================================================================

BOOLEAN FillDirectoryFromPath(PEXCULE_FILE_PATH path, PUNICODE_STRING filePath)
{
	USHORT i, count;
	LPWSTR buffer = filePath->Buffer;

	count = filePath->Length / sizeof(WCHAR);
	if (count < 1)
		return FALSE;

	i = count;
	do
	{
		i--;

		if (buffer[i] == L'\\')
		{
			if (i + 1 >= count)
				return FALSE;

			path->fileName.Buffer = buffer + i + 1;
			path->fileName.Length = (count - i - 1) * sizeof(WCHAR);
			path->fileName.MaximumLength = path->fileName.Length;

			path->fullPath = *filePath;

			path->dirName.Buffer = filePath->Buffer;
			path->dirName.Length = i * sizeof(WCHAR);
			path->dirName.MaximumLength = path->dirName.Length;

			return TRUE;
		}
	}
	while (i > 0);

	return FALSE;
}

// code from wikipedia.org
static const unsigned int g_crc32Table [256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
	0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
	0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D,
	0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
	0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
	0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC,
	0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
	0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
	0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB,
	0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
	0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE,
	0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
	0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
	0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
	0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
	0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268,
	0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0,
	0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8,
	0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
	0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
	0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
	0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE,
	0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
	0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
	0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D,
	0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
	0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
	0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

unsigned int GetCrc32(void* buf, unsigned int size, unsigned int ivect)
{
	unsigned char *src = (unsigned char*)buf;
	unsigned int crc = ~ivect;

	while (size--)
		crc = (crc >> 8) ^ g_crc32Table[(crc ^ *src++) & 0xFF];

	return 0xFFFFFFFF ^ crc;
}
