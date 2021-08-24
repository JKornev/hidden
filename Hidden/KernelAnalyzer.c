#include "KernelAnalyzer.h"
#include "Helper.h"
#include <Zydis/Zydis.h>

typedef struct _KernelInternals {
	ULONG ActiveProcessLinksOffset;
	PVOID PspActiveProcessLock;
	PVOID PspCidTable;
} KernelInternals, *PKernelInternals;

static KernelInternals s_NTinternals;

static ZydisDecoder s_disasmDecoder;
static ZydisFormatter s_disasmFormatter;

// =========================================================================================

PVOID GetPspCidTablePointer()
{
	return s_NTinternals.PspCidTable;
}

// =========================================================================================

BOOLEAN Disassemble(PVOID fn, SIZE_T size, BOOLEAN(*InstructionCallback)(ZyanU64,ZydisDecodedInstruction*,PVOID), PVOID params)
{
	LogInfo("Routine %p", fn);

	__try
	{
		ZydisDecodedInstruction instruction;
		SIZE_T offset = 0;
		UINT_PTR target = (UINT_PTR)fn;
		CHAR printBuffer[128];

		do
		{
			ZyanStatus status = ZydisDecoderDecodeBuffer(&s_disasmDecoder, (PVOID)(target + offset), size - offset, &instruction);
			if (!ZYAN_SUCCESS(status))
				break;

			const ZyanU64 address = (ZyanU64)(target + offset);
			ZydisFormatterFormatInstruction(&s_disasmFormatter, &instruction, printBuffer, sizeof(printBuffer), address);

			LogInfo("\t+%-4X 0x%-16llX\t\t%hs", (ULONG)offset, address, printBuffer);

			if (!InstructionCallback(address, &instruction, params))
				break;

			offset += instruction.length;
		} 
		while (offset <= size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LogWarning("Exception while disassemblying %p", fn);
		return FALSE;
	}

	return TRUE;
}

// =========================================================================================

//
// Case #1 Win7
// Solution: Disassemble a code before we meet 'MOV REG, PspCidTable'
//
// PAGE : 0065B960 _PsLookupProcessByProcessId@8 proc near
// PAGE : 0065B960    mov     edi, edi
// PAGE : 0065B962    push    ebp
// PAGE : 0065B963    mov     ebp, esp
// PAGE : 0065B965    sub     esp, 0Ch
// PAGE : 0065B968    push    ebx
// PAGE : 0065B969    push    esi
// PAGE : 0065B96A    mov     esi, large fs : 124h
// PAGE : 0065B971    xor     ebx, ebx
// PAGE : 0065B973    dec     word ptr[esi + 84h]
// PAGE : 0065B97A    push    edi
// PAGE : 0065B97B    push    [ebp + arg_0]
// PAGE : 0065B97E    mov     edi, _PspCidTable   <----- Looking for this
//
// Case #2 Win10
// Solution: Disassemble before we meet first a call to not-exported PspReferenceCidTableEntry 
//           enter it and disassemble before 'MOV REG, PspCidTable'
//
// PAGE : 006C98E0 _PsLookupProcessByProcessId@8 proc near
// PAGE : 006C98E0    mov     edi, edi
// PAGE : 006C98E2    push    ebp
// PAGE : 006C98E3    mov     ebp, esp
// PAGE : 006C98E5    push    ecx
// PAGE : 006C98E6    push    ebx
// PAGE : 006C98E7    push    esi
// PAGE : 006C98E8    push    edi                              .---->  PAGE : 006C99B0 _PspReferenceCidTableEntry@8 proc near
// PAGE : 006C98E9    mov     edi, large fs : 124h             |       PAGE : 006C99B0     mov     edi, edi
// PAGE : 006C98F0    dec     word ptr[edi + 13Eh]             |       PAGE : 006C99B2     push    ebp
// PAGE : 006C98F7    mov     ecx, [ebp + arg_0]               |       PAGE : 006C99B3     mov     ebp, esp
// PAGE : 006C98FA    mov     dl, 3                            |       PAGE : 006C99B5     mov     eax, ds : _PspCidTable   <----- Looking for this
// PAGE : 006C98FC    call    _PspReferenceCidTableEntry@8 ----'       PAGE : 006C99BA     sub     esp, 0Ch
// 

BOOLEAN LookForPspCidTableCallback(ZyanU64 address, ZydisDecodedInstruction* instruction, PVOID params)
{
	BOOLEAN EnterCalls = *(BOOLEAN*)params;

	if (instruction->mnemonic == ZYDIS_MNEMONIC_RET)
		return FALSE; // Stop scan if the function is ended

	if (instruction->mnemonic == ZYDIS_MNEMONIC_MOV)
	{
		ZyanU64 pointer = 0;

		ZyanStatus status = ZydisCalcAbsoluteAddress(instruction, instruction->operands + 1, address, &pointer);
		if (!ZYAN_SUCCESS(status))
			return TRUE;

		//TODO: validate PspCidTable

		if (instruction->operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
			return TRUE;

#if _M_AMD64
		if (instruction->operands[1].mem.segment == ZYDIS_REGISTER_GS)
#else
		if (instruction->operands[1].mem.segment == ZYDIS_REGISTER_FS)
#endif
			return TRUE;

		s_NTinternals.PspCidTable = *(PVOID*)(ULONG_PTR)pointer;
		LogInfo("PspCidTable address: %p", pointer);
		// Stop scanning if we found a PspCidTable
		return FALSE;
	}

	if (EnterCalls && instruction->mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		ZyanU64 callAddress = 0;

		if (!instruction->operand_count)
			return FALSE; // This should never happens

		ZyanStatus status = ZydisCalcAbsoluteAddress(instruction, instruction->operands, address, &callAddress);
		if (!ZYAN_SUCCESS(status))
			return TRUE;

		EnterCalls = FALSE;
		Disassemble((PVOID)(ULONG_PTR)callAddress, 0x20, &LookForPspCidTableCallback, &EnterCalls);
		// Stop scan after a first entering a call instruction
		return FALSE;
	}

	// Scan next command
	return TRUE;
}

VOID LookForPspCidTable()
{
	BOOLEAN EnterCalls = TRUE;

	s_NTinternals.PspCidTable = 0;

	Disassemble((PVOID)PsLookupProcessByProcessId, 0x40, LookForPspCidTableCallback, &EnterCalls);

	if (!s_NTinternals.PspCidTable)
	{
		LogWarning("Failed to find PspCidTable");
		return;
	}
}

VOID LookActiveProcessLock()
{
	//Disassemble()
}

// =========================================================================================

BOOLEAN InitializeDisasm()
{
	if (ZydisGetVersion() != ZYDIS_VERSION)
	{
		LogWarning("Error, invalid disasm version");
		return FALSE;
	}

#ifdef _M_AMD64
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&s_disasmDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)))
#else
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&s_disasmDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32)))
#endif
	{
		LogWarning("Error, failed to initialize disasm decoder");
		return FALSE;
	}

	//TODO: mb we need to remove it
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&s_disasmFormatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		return FALSE;

	return TRUE;
}

VOID InitializeKernelAnalyzer()
{
	RtlZeroMemory(&s_NTinternals, sizeof(s_NTinternals));

	if (!InitializeDisasm())
		return;

	LookForPspCidTable();
	LookActiveProcessLock();
}

VOID DestroyKernelAnalyzer()
{
	//TODO: do we need this routine?
}
