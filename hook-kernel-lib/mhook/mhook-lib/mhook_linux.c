#include <scheme.h>

#ifndef __OS_KERNEL__
	#include <unistd.h>
	#include <sys/mman.h>
	#include <errno.h>
#else
	#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
		#include <asm/pgtable.h>
	#endif

#endif

#include "mhook.h"
#include "../disasm-lib/disasm.h"

//!defined(__ASSEMBLY__) for GLH 2.6.25.14 liudan 2019-7-9
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || !defined(__ASSEMBLY__)

#undef PAGE_KERNEL_EXEC
#undef __PAGE_KERNEL_EXEC

	#ifndef _PAGE_GLOBAL
	#define _PAGE_GLOBAL	0x100	/* Global TLB entry */
	#endif

#define __PAGE_KERNEL_EXEC  (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)

#define PAGE_KERNEL_EXEC __pgprot(__PAGE_KERNEL_EXEC | _PAGE_GLOBAL)

#endif
//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a
//copy of this software and associated documentation files (the "Software"),
//to deal in the Software without restriction, including without limitation
//the rights to use, copy, modify, merge, publish, distribute, sublicense,
//and/or sell copies of the Software, and to permit persons to whom the
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//IN THE SOFTWARE.


#ifdef __OS_KERNEL__

#define printf printk
//#define printk

#ifndef X86_CR0_WP
#define X86_CR0_WP	0x00010000 /* Write Protect */
#endif


unsigned int __skip_nopl_instruction(unsigned char * addr);

// Thanks Dan
inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable();
}

#endif

//=========================================================================
#ifndef cntof
#define cntof(a) (sizeof(a)/sizeof(a[0]))
#endif

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a!=INVALID_HANDLE_VALUE)&&(a!=NULL))
#endif

//=========================================================================
#ifndef __OS_KERNEL__
#ifndef gle
// -- #define gle GetLastError
#define gle() errno
#endif
#endif

//#define _DEBUG

#ifdef _DEBUG
#define ODPRINTF(fmt, arg...) printk(KERN_INFO fmt, ##arg)
#else
//#define ODPRINTF(a)
#define ODPRINTF(fmt, ...)
#endif
//=========================================================================

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES	32
#define MHOOKS_MAX_RIPS			 4


//=========================================================================
// The trampoline structure - stores every bit of info about a hook
typedef struct __MHOOKS_TRAMPOLINE MHOOKS_TRAMPOLINE;
struct __MHOOKS_TRAMPOLINE {
	PBYTE	pSystemFunction;								// the original system function
	DWORD	cbOverwrittenCode;								// number of bytes overwritten by the jump
	PBYTE	pHookFunction;									// the hook function that we provide
	BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// placeholder for code that jumps to the hook function
	BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// placeholder for code that holds the first few
															//   bytes from the system function and a jump to the remainder
															//   in the original location
	BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// placeholder for unmodified original code
															//   (we patch IP-relative addressing)
};

typedef struct __MHOOKS_TRAMPOLINE_SLAB MHOOKS_TRAMPOLINE_SLAB;
struct __MHOOKS_TRAMPOLINE_SLAB
{
	MHOOKS_TRAMPOLINE trampoline;
	unsigned int index;
	unsigned char occupied; // -- 是否已经分配；
};

//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
typedef struct __MHOOKS_RIPINFO
{
	DWORD	dwOffset;
	S64		nDisplacement;
}MHOOKS_RIPINFO;

typedef struct __MHOOKS_PATCHDATA
{
	S64				nLimitUp;
	S64				nLimitDown;
	DWORD			nRipCnt;
	MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS];
}MHOOKS_PATCHDATA;

//=========================================================================
// Global vars
static BOOL g_bVarsInitialized = FALSE;
// -- static CRITICAL_SECTION g_cs;
static MHOOKS_TRAMPOLINE* g_pHooks[MHOOKS_MAX_SUPPORTED_HOOKS];

static MHOOKS_TRAMPOLINE_SLAB * g_pHookMem = NULL; // -- MHOOKS_MAX_SUPPORTED_HOOKS of MHOOKS_TRAMPOLINE_SLAB
static DWORD g_nHooksInUse = 0;
static HANDLE* g_hThreadHandles = NULL;
static DWORD g_nThreadHandles = 0;
static unsigned long m_nPageSize = 0; // -- = PAGESIZE;



#define MHOOK_JMPSIZE 5

//=========================================================================
// Toolhelp defintions so the functions can be dynamically bound to

//=========================================================================
// Bring in the toolhelp functions from kernel32
// -- __OS_KERNEL__

#if 0
10.int main(int argc, char** argv)
11.{
12.    extern int errno;
13.    struct mem_t* mem = (struct mem_t*)malloc(sizeof(struct mem_t));
14.    mem->func = (fuc)0xFFFF;
15.    void* p = &mem->func;
16.    if(mprotect((void*)(unsigned long(p) & (~PAGESIZE - 1)), 1024, PROT_READ) == -1)
17.    {
18.        printf("%d\n", errno);
19.        return 0;
20.    }
21.    mem->i = 1;
22.    mem->j = 2;
23.    mem->func = (fuc)0xFFEE;
24.    printf("%x\n", mem->func);
25.    return 1;
26.}
#endif

int memProtect(unsigned char * addr, long length)
{
#ifndef __OS_KERNEL__
	int retval = -1;
	unsigned long start = 0, end = 0;
	unsigned long oldlen = length;
	// -- unsigned char * to = addr + length;
	end = ((unsigned long)addr) + length;
	start = ((unsigned long)addr) & (~(m_nPageSize - 1));
	// -- end = ((unsigned long)to) & (~m_nPageSize - 1);
	length = (end - start);
	if(mprotect((void*)start, length, PROT_READ | PROT_WRITE  | PROT_EXEC) == -1){
		printf("%d:%s(0x%lx) (%ld)(%ld)(%ld)\n", errno, strerror(errno), start, length, oldlen, m_nPageSize);
		goto DONE;
	}else{
		printf("mprotect success:(0x%lx) (%ld)(%ld)(%ld)\n", start, length, oldlen, m_nPageSize);
	}
	retval = 0;
DONE:
	return retval;
#else
	return 0;
#endif

}

 MHOOKS_TRAMPOLINE * __allocTrampoline(void)
 {
	MHOOKS_TRAMPOLINE * retval = NULL;
	MHOOKS_TRAMPOLINE_SLAB * slab = g_pHookMem;
	int i;
	for(i = 0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++){
		if(slab[i].occupied) continue;
		slab[i].occupied = 1;
		retval = &slab[i].trampoline;
		slab[i].index = i;
		break;
	}

	return retval;
 }

void __freeTrampoline(MHOOKS_TRAMPOLINE * trampoline)
{
	MHOOKS_TRAMPOLINE_SLAB * slab = (MHOOKS_TRAMPOLINE_SLAB *)trampoline;
	slab->occupied = 0;
	return;
}

#ifdef __OS_KERNEL__
void *__vmalloc_exec(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
}
#endif

static int __mhook_init(void)
{
	int retval = -1;
	void * start = NULL;
#ifndef __OS_KERNEL__
	int fd = -1;
#endif
	unsigned int siz = 0;
#ifndef __OS_KERNEL__
	printf("__mhook_init\n");
	m_nPageSize = sysconf(_SC_PAGE_SIZE);
	if (m_nPageSize == -1){
		// -- handle_error("sysconf");
		printf("get-page size error.\n");
		goto DONE;
	}

#else
	m_nPageSize = PAGE_SIZE;
#endif
	// -- 映射到内存中的文件描述符。如果使用匿名内存映射时，即flags中设置了MAP_ANONYMOUS，fd设为-1。
	// -- 有些系统不支持匿名内存映射，则可以使用fopen打开/dev/zero文件，然后对该文件进行映射，可以
	// -- 同样达到匿名内存映射的效果。
	siz = sizeof(MHOOKS_TRAMPOLINE_SLAB) * MHOOKS_MAX_SUPPORTED_HOOKS;
#ifndef __OS_KERNEL__
	fd = -1; // -- fd = open( "/dev/zero" , O_RDWR) ;
	start = mmap(NULL, siz, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, fd, 0);
	if(start == ((void *)-1)){
		start = NULL;
	}
#else
	// -- start = kmalloc(siz, GFP_ATOMIC);
	start = __vmalloc_exec(siz);
#endif
	if(!start){
		printf("mmap faile.\n");
		goto DONE;
	}

	g_pHookMem = (MHOOKS_TRAMPOLINE_SLAB *)start;
	if(start){
		memset(start, 0, siz);
	}
	retval = 0;
DONE:
#ifndef __OS_KERNEL__
	if(fd>=0){
		close(fd);
	}
#endif
#ifndef __OS_KERNEL__

	printf("__mhook_init exit(%p)\n", g_pHookMem);
#else
printk(KERN_INFO "__mhook_init exit(%p)\n", g_pHookMem);

#endif
	return retval;
}
//=========================================================================
static VOID EnterCritSec(void) {
	//printf("EnterCritSec.(%d)(%d)\n", g_bVarsInitialized, FALSE);
	if (!g_bVarsInitialized) {
		// -- InitializeCriticalSection(&g_cs);
		__mhook_init();
		memset(g_pHooks, 0, sizeof(g_pHooks));
		// -- ZeroMemory(g_pHooks, sizeof(g_pHooks));
		g_bVarsInitialized = TRUE;
	}
	// -- EnterCriticalSection(&g_cs);
}

//=========================================================================
static VOID LeaveCritSec(void) {
	// -- LeaveCriticalSection(&g_cs);
	ODPRINTF("LeaveCritSec.\n");
}

//=========================================================================
// Internal function:
//
// Skip over jumps that lead to the real function. Gets around import
// jump tables, etc.
//=========================================================================
static PBYTE SkipJumps(PBYTE pbCode) {
#ifdef _M_IX86_X64
	if (pbCode[0] == 0xff && pbCode[1] == 0x25) {
#ifdef _M_IX86
		// on x86 we have an absolute pointer...
		PBYTE pbTarget = *(PBYTE *)&pbCode[2];
		// ... that shows us an absolute pointer.
		return SkipJumps(*(PBYTE *)pbTarget);
#elif defined _M_X64
		// on x64 we have a 32-bit offset...
		INT32 lOffset = *(INT32 *)&pbCode[2];
		// ... that shows us an absolute pointer
		return SkipJumps(*(PBYTE*)(pbCode + 6 + lOffset));
#endif
	} else if (pbCode[0] == 0xe9) {
		// here the behavior is identical, we have...
		// ...a 32-bit offset to the destination.
		return SkipJumps(pbCode + 5 + *(INT32 *)&pbCode[1]);
	} else if (pbCode[0] == 0xeb) {
		// and finally an 8-bit offset to the destination
		return SkipJumps(pbCode + 2 + *(CHAR *)&pbCode[1]);
	}
#else
#error unsupported platform
#endif
	return pbCode;
}

//=========================================================================
// Internal function:
//
// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xff 0x25 ....) can take up 14 bytes.
//=========================================================================
static PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo) {
#ifdef _M_IX86_X64
	PBYTE pbJumpFrom = pbCode + 5;
	SIZE_T cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
#ifdef _M_IX86
	ODPRINTF("mhooks: EmitJump: Jumping from %p to %p, diff is %lu\n", pbJumpFrom, pbJumpTo, cbDiff);
#elif defined _M_X64
	ODPRINTF("mhooks: EmitJump: Jumping from %p to %p, diff is %llu\n", pbJumpFrom, pbJumpTo, cbDiff);
#endif
	if (cbDiff <= 0x7fff0000) {
		pbCode[0] = 0xe9;
		pbCode += 1;
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbJumpTo - pbJumpFrom);
		pbCode += sizeof(DWORD);
	} else {
		pbCode[0] = 0xff;
		pbCode[1] = 0x25;
		pbCode += 2;
#ifdef _M_IX86
		// on x86 we write an absolute address (just behind the instruction)
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbCode + sizeof(DWORD));
#elif defined _M_X64
		// on x64 we write the relative address of the same location
		*((PDWORD)pbCode) = (DWORD)0;
#endif
		pbCode += sizeof(DWORD);
		*((PDWORD_PTR)pbCode) = (DWORD_PTR)(pbJumpTo);
		pbCode += sizeof(DWORD_PTR);
	}
#else
#error unsupported platform
#endif
	return pbCode;
}

//=========================================================================
// Internal function:
//
// Will try to allocate the trampoline structure within 2 gigabytes of
// the target function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineAlloc(PBYTE pSystemFunction, S64 nLimitUp, S64 nLimitDown)
{
	DWORD i = 0;
	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// do we have room to store this guy?
	// -- if (g_nHooksInUse >= MHOOKS_MAX_SUPPORTED_HOOKS) return NULL;

	pTrampoline = __allocTrampoline();
	// found and allocated a trampoline?
	if (pTrampoline) {
        pTrampoline->pSystemFunction = pSystemFunction;
		// put it into our list so we know we'll have to free it
		for (i=0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
			if (g_pHooks[i] == NULL) {
				g_pHooks[i] = pTrampoline;
				g_nHooksInUse++;
				break;
			}
		}
	}


	return pTrampoline;
}

//=========================================================================
// Internal function:
//
// Return the internal trampoline structure that belongs to a hooked function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction)
{
	DWORD i;
	for (i = 0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
		if (g_pHooks[i]) {
			if (g_pHooks[i]->codeTrampoline == pHookedFunction)
				return g_pHooks[i];
		}
	}
	return NULL;
}

//=========================================================================
// Internal function:
//
// Free a trampoline structure.
//=========================================================================
static VOID TrampolineFree(MHOOKS_TRAMPOLINE* pTrampoline, BOOL bNeverUsed)
{
	DWORD i;
	for (i = 0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
		if (g_pHooks[i] == pTrampoline) {
			g_pHooks[i] = NULL;
			// It might be OK to call VirtualFree, but quite possibly it isn't:
			// If a thread has some of our trampoline code on its stack
			// and we yank the region from underneath it then it will
			// surely crash upon returning. So instead of freeing the
			// memory we just let it leak. Ugly, but safe.
			if (bNeverUsed){
				__freeTrampoline(pTrampoline);
				// -- VirtualFree(pTrampoline, 0, MEM_RELEASE);
			}
			g_nHooksInUse--;
			break;
		}
	}
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//=========================================================================
static HANDLE SuspendOneThread(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
	HANDLE hThread = NULL;
	return hThread;
}

//=========================================================================
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//=========================================================================
static VOID ResumeOtherThreads(void) {

}

//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their
// instruction pointer is not in the given range.
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
	BOOL bRet = FALSE;
	bRet = TRUE;
	return bRet;
}

//=========================================================================
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
static void FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
#if defined _M_X64
	DWORD i;
	S64 diff = pbNew - pbOriginal;
	ODPRINTF("FixupIPRelativeAddressing: 64bit system.\n");
	for (i = 0; i < pdata->nRipCnt; i++) {
		DWORD dwNewDisplacement = (DWORD)(pdata->rips[i].nDisplacement - diff);
		ODPRINTF("mhooks: fixing up RIP instruction operand for code at 0x%p: "
			"old displacement: 0x%8.8x, new displacement: 0x%8.8x\n",
			pbNew + pdata->rips[i].dwOffset,
			(DWORD)pdata->rips[i].nDisplacement,
			dwNewDisplacement);
		*(PDWORD)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
	}
#endif
}

//=========================================================================
// Examine the machine code at the target function's entry point, and
// skip bytes in a way that we'll always end on an instruction boundary.
// We also detect branches and subroutine calls (as well as returns)
// at which point disassembly must stop.
// Finally, detect and collect information on IP-relative instructions
// that we can patch.
// -- unsigned int __skip_nopl_instruction(unsigned char * addr)
static DWORD DisassembleAndSkip(PVOID pFunction, DWORD dwMinLen, MHOOKS_PATCHDATA* pdata) {
	DWORD dwRet = 0;
	ARCHITECTURE_TYPE arch;
	DISASSEMBLER dis;
	U8* pLoc = (U8*)pFunction;
	int __nopLen = 0;
#if defined _M_X64
    BOOL bProcessRip = FALSE;
#endif

	pdata->nLimitDown = 0;
	pdata->nLimitUp = 0;
	pdata->nRipCnt = 0;

	__nopLen = __skip_nopl_instruction(pLoc);
	pLoc += __nopLen;
	dwRet += __nopLen;
#ifdef _M_IX86
	arch = ARCH_X86;
#elif defined _M_X64
	arch = ARCH_X64;
#else
	#error unsupported platform
#endif
	ODPRINTF("mhooks: DisassembleAndSkip <enter>\n");
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL;
		DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT;

		ODPRINTF("mhooks: DisassembleAndSkip: Disassembling %p\n", pLoc);
		while ( (dwRet < dwMinLen) && (pins = GetInstruction(&dis, (ULONG_PTR)pLoc, pLoc, dwFlags)) ) {
			ODPRINTF("mhooks: DisassembleAndSkip: %p: %s\n", pLoc, pins->String);
			if (pins->Type == ITYPE_RET		){
				ODPRINTF("mhooks: DisassembleAndSkip: ITYPE_RET\n");
				break;
			}
			if (pins->Type == ITYPE_BRANCH	){
				ODPRINTF("mhooks: DisassembleAndSkip: ITYPE_BRANCH\n");
				break;
			}
			if (pins->Type == ITYPE_BRANCHCC){
				ODPRINTF("mhooks: DisassembleAndSkip: ITYPE_BRANCHCC\n");
				break;
			}
			if (pins->Type == ITYPE_CALL	){
				ODPRINTF("mhooks: DisassembleAndSkip: ITYPE_CALL\n");
				break;
			}
			if (pins->Type == ITYPE_CALLCC	){
				ODPRINTF("mhooks: DisassembleAndSkip: ITYPE_CALLCC\n");
				break;
			}

			#if defined _M_X64
				//BOOL bProcessRip = FALSE;
				// mov or lea to register from rip+imm32
				if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[1].Flags & OP_IPREL) && (pins->Operands[1].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov reg, [rip+imm32]"
					ODPRINTF("mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)\n", 1, pins->X86.Displacement, *(PDWORD)(pLoc+3));
					bProcessRip = TRUE;
				}
				// mov or lea to rip+imm32 from register
				else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov [rip+imm32], reg"
					ODPRINTF("mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)\n", 0, pins->X86.Displacement, *(PDWORD)(pLoc+3));
					bProcessRip = TRUE;
				}
				else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
				{
					DWORD i = 0;
					// unsupported rip-addressing
					ODPRINTF("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d\n", 0);
					// dump instruction bytes to the debug output
					for (i = 0; i<pins->Length; i++) {
						ODPRINTF("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x\n", i, pLoc[i]);
					}
					break;
				}
				else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
				{
					DWORD i = 0;
					// unsupported rip-addressing
					ODPRINTF("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d\n", 1);
					// dump instruction bytes to the debug output
					for (; i<pins->Length; i++) {
						ODPRINTF("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x\n", i, pLoc[i]);
					}
					break;
				}
				else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
				{
					DWORD i = 0;
					// unsupported rip-addressing
					ODPRINTF("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d\n", 2);
					// dump instruction bytes to the debug output
					for (; i<pins->Length; i++) {
						ODPRINTF("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x\n", i, pLoc[i]);
					}
					break;
				}
				// follow through with RIP-processing if needed
				if (bProcessRip) {
					// calculate displacement relative to function start
					S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
					// store displacement values furthest from zero (both positive and negative)
					if (nAdjustedDisplacement < pdata->nLimitDown)
						pdata->nLimitDown = nAdjustedDisplacement;
					if (nAdjustedDisplacement > pdata->nLimitUp)
						pdata->nLimitUp = nAdjustedDisplacement;
					// store patch info
					if (pdata->nRipCnt < MHOOKS_MAX_RIPS) {
						pdata->rips[pdata->nRipCnt].dwOffset = dwRet + 3;
						pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
						pdata->nRipCnt++;
					} else {
						// no room for patch info, stop disassembly
						break;
					}
				}
			#endif

			dwRet += pins->Length;
			pLoc  += pins->Length;
		}

		CloseDisassembler(&dis);
	}
	ODPRINTF("mhooks: DisassembleAndSkip <exit> %d\n", dwRet);
	return dwRet;
}

//=========================================================================

/*
2 bytes 66 NOP 66 90H
 3 bytes NOP DWORD ptr [EAX] 0F 1F 00H
 4 bytes NOP DWORD ptr [EAX + 00H] 0F 1F 40 00H
 5 bytes NOP DWORD ptr [EAX + EAX*1 + 00H] 0F 1F 44 00 00H
 6 bytes 66 NOP DWORD ptr [EAX + EAX*1 + 00H] 66 0F 1F 44 00 00H
 7 bytes NOP DWORD ptr [EAX + 00000000H] 0F 1F 80 00 00 00 00H
 8 bytes NOP DWORD ptr [EAX + EAX*1 + 00000000H] 0F 1F 84 00 00 00 00 00H
 9 bytes 66 NOP DWORD ptr [EAX + EAX*1 + 66 0F 1F 84 00 00 00 00 00000000H]
	Length   Assembly                                   Byte Sequence
	2 bytes  66 NOP                                     66 90 H
	3 bytes  NOP DWORD ptr [EAX]                        0F 1F 00H
	4 bytes  NOP DWORD ptr [EAX + 00H]                  0F 1F 40 00H
	5 bytes  NOP DWORD ptr [EAX + EAX*1 + 00H]          0F 1F 44 00 00H
	6 bytes  66 NOP DWORD ptr [EAX + EAX*1 + 00H]       66 0F 1F 44 00 00H
	7 bytes  NOP DWORD ptr [EAX + 00000000H]            0F 1F 80 00 00 00 00H
	8 bytes  NOP DWORD ptr [EAX + EAX*1 + 00000000H]    0F 1F 84 00 00 00 00 00H
	9 bytes  66 NOP DWORD ptr [EAX + EAX*1 + 00000000H] 66 0F 1F 84 00 00 00 00 00H
*/
unsigned int __skip_nopl_instruction(unsigned char * addr)
{
	unsigned char op1 = addr[0];
	unsigned char op2 = addr[1];
	unsigned char op3 = addr[2];
	unsigned char op4 = addr[3];
	unsigned int oplen = 0;
	if(0x66 == op1){
		if(0x90 == op2){
			oplen = 2;
			goto DONE;
		}else if(0x0F == op2){
			oplen ++;
		}else{
			goto DONE;
		}
		// -- skip prefix byte
		addr ++;
		op1 = addr[0];
		op2 = addr[1];
		op3 = addr[2];
		op4 = addr[3];
	}
	ODPRINTF("__skip_nopl_instruction enter\n");
	if(0x0F != op1){
		oplen = 0;
		goto DONE;
	}
	if(0x1F != op2){
		oplen = 0;
		goto DONE;
	}
	if(0x00 == op3) {
		oplen += 3;
		goto DONE;
	}else if(0x40 == op3){
		oplen += 4;
		goto DONE;
	}else if(0x44 == op3){
		oplen += 5;
		goto DONE;
	}else if(0x80 == op3){
		oplen += 7;
		goto DONE;
	}else if(0x84 == op3){
		oplen += 8;
		goto DONE;
	}else{
		oplen = 0;
	}
DONE:
	ODPRINTF("__skip_nopl_instruction exit (oplen:%d)\n", oplen);
	return oplen;
}

static BOOL __mhookSetHook(PVOID *ppSystemFunction, PVOID pHookFunction, unsigned int offset);
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction)
{
	return __mhookSetHook(ppSystemFunction, pHookFunction, 0);
}

BOOL Mhook_SetHookOffset(PVOID *ppSystemFunction, PVOID pHookFunction, unsigned int offset)
{
	return __mhookSetHook(ppSystemFunction, pHookFunction, offset);
}

BOOL __mhookSetHook(PVOID *ppSystemFunction, PVOID pHookFunction, unsigned int offset)
{
#ifdef __OS_KERNEL__
    unsigned long o_cr0;
#endif

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;
	PVOID pSystemFunction = *ppSystemFunction;
	// ensure thread-safety
	MHOOKS_PATCHDATA patchdata = {0}, tmppatch = {0};
	DWORD dwInstructionLength;
	unsigned int skip = 0; // -- jmpSize = MHOOK_JMPSIZE + offset;
	unsigned char * addr = (unsigned char *)pSystemFunction;
	EnterCritSec();

#ifdef __OS_KERNEL__
	o_cr0 = disable_wp();
#endif

	ODPRINTF("mhooks: Mhook_SetHook: Started on the job: %p / %p\n", pSystemFunction, pHookFunction);
	// find the real functions (jump over jump tables, if any)

	if(offset > 0){
		skip = DisassembleAndSkip(pSystemFunction, offset, &tmppatch);
		if(skip < offset){
			goto DONE;
		}
		pSystemFunction = (unsigned char *)pSystemFunction + skip;
	}

	pSystemFunction = SkipJumps((PBYTE)pSystemFunction);
	pHookFunction   = SkipJumps((PBYTE)pHookFunction);
	ODPRINTF("mhooks: Mhook_SetHook: Started on the job: %p / %p\n", pSystemFunction, pHookFunction);
	// figure out the length of the overwrite zone
	ODPRINTF("[*] Mhook_SetHook [%02x][%02x][%02x][%02x]\n", ((unsigned char *)pSystemFunction)[0], ((unsigned char *)pSystemFunction)[1], ((unsigned char *)pSystemFunction)[2], ((unsigned char *)pSystemFunction)[3]);

	dwInstructionLength = DisassembleAndSkip(pSystemFunction, MHOOK_JMPSIZE, &patchdata);

	if (dwInstructionLength >= MHOOK_JMPSIZE) {
		ODPRINTF("mhooks: Mhook_SetHook: disassembly signals %d bytes\n", dwInstructionLength);
		// suspend every other thread in this process, and make sure their IP
		// is not in the code we're about to overwrite.
		SuspendOtherThreads((PBYTE)pSystemFunction, dwInstructionLength);
		// allocate a trampoline structure (TODO: it is pretty wasteful to get
		// VirtualAlloc to grab chunks of memory smaller than 100 bytes)
		pTrampoline = TrampolineAlloc((PBYTE)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);
		if (pTrampoline) {
			DWORD dwOldProtectSystemFunction = 0;
			DWORD dwOldProtectTrampolineFunction = 0;
			ODPRINTF("mhooks: Mhook_SetHook: allocated structure at %p\n", pTrampoline);
			// open ourselves so we can VirtualProtectEx
			// -- HANDLE hProc = GetCurrentProcess();
			// set the system function to PAGE_EXECUTE_READWRITE
			ODPRINTF("Mhook_SetHook 1\n");
			// -- if (VirtualProtectEx(hProc, pSystemFunction, dwInstructionLength, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
			if(0 == memProtect(pSystemFunction, dwInstructionLength)){
				DWORD i = 0;
				PBYTE pbCode = NULL;
				DWORD_PTR dwDistance;

				ODPRINTF("Mhook_SetHook 2\n");
				ODPRINTF("mhooks: Mhook_SetHook: readwrite set on system function\n");
				// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
				// -- if (VirtualProtectEx(hProc, pTrampoline, sizeof(MHOOKS_TRAMPOLINE), PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction))
				{
					i = 0;
					ODPRINTF("mhooks: Mhook_SetHook: readwrite set on trampoline structure\n");

					// create our trampoline function
					pbCode = pTrampoline->codeTrampoline;
					// save original code..
					for (i = 0; i<dwInstructionLength; i++) {
						pTrampoline->codeUntouched[i] = pbCode[i] = ((PBYTE)pSystemFunction)[i];
					}
					pbCode += dwInstructionLength;
					// plus a jump to the continuation in the original location
					pbCode = EmitJump(pbCode, ((PBYTE)pSystemFunction) + dwInstructionLength);
					ODPRINTF("mhooks: Mhook_SetHook: updated the trampoline\n");

					// fix up any IP-relative addressing in the code
					FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (PBYTE)pSystemFunction, &patchdata);

					dwDistance = (PBYTE)pHookFunction < (PBYTE)pSystemFunction ?
						(PBYTE)pSystemFunction - (PBYTE)pHookFunction : (PBYTE)pHookFunction - (PBYTE)pSystemFunction;
					if (dwDistance > 0x7fff0000) {
						printf("Mhook_SetHook 5\n");
						// create a stub that jumps to the replacement function.
						// we need this because jumping from the API to the hook directly
						// will be a long jump, which is 14 bytes on x64, and we want to
						// avoid that - the API may or may not have room for such stuff.
						// (remember, we only have 5 bytes guaranteed in the API.)
						// on the other hand we do have room, and the trampoline will always be
						// within +/- 2GB of the API, so we do the long jump in there.
						// the API will jump to the "reverse trampoline" which
						// will jump to the user's hook code.
						pbCode = pTrampoline->codeJumpToHookFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
						ODPRINTF("mhooks: Mhook_SetHook: created reverse trampoline\n");
						// -- FlushInstructionCache(hProc, pTrampoline->codeJumpToHookFunction, pbCode - pTrampoline->codeJumpToHookFunction);

						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
					} else {
						ODPRINTF("Mhook_SetHook 6\n");
						// the jump will be at most 5 bytes so we can do it directly
						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
					}

					// update data members
					pTrampoline->cbOverwrittenCode = dwInstructionLength;
					pTrampoline->pSystemFunction = (PBYTE)pSystemFunction;
					pTrampoline->pHookFunction = (PBYTE)pHookFunction;

					// flush instruction cache and restore original protection
					// -- FlushInstructionCache(hProc, pTrampoline->codeTrampoline, dwInstructionLength);
					// -- VirtualProtectEx(hProc, pTrampoline, sizeof(MHOOKS_TRAMPOLINE), dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
				}
				// flush instruction cache and restore original protection
				// -- FlushInstructionCache(hProc, pSystemFunction, dwInstructionLength);
				// -- VirtualProtectEx(hProc, pSystemFunction, dwInstructionLength, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			} else {
				#ifndef __OS_KERNEL__
				printf("mhooks: Mhook_SetHook: failed VirtualProtectEx 1: %d\n", gle());
				#else
				ODPRINTF("mhooks: Mhook_SetHook: failed VirtualProtectEx 1:\n");
				#endif
			}
			if (pTrampoline->pSystemFunction) {
				// this is what the application will use as the entry point
				// to the "original" unhooked function.
				*ppSystemFunction = pTrampoline->codeTrampoline;
				ODPRINTF("Mhook_SetHook 8\n");
				ODPRINTF("mhooks: Mhook_SetHook: Hooked the function!\n");
			} else {
				// if we failed discard the trampoline (forcing VirtualFree)
				TrampolineFree(pTrampoline, TRUE);
				pTrampoline = NULL;
			}
		}
		// resume everybody else
		ResumeOtherThreads();
	} else {
#ifndef __OS_KERNEL__
		printf("mhooks: disassembly signals %d bytes (unacceptable)\n", dwInstructionLength);
#else
		ODPRINTF("<1> mhooks: disassembly signals %d bytes (unacceptable)\n", dwInstructionLength);
#endif
	}
DONE:
	LeaveCritSec();

#ifdef __OS_KERNEL__
   restore_wp(o_cr0);
#endif

	ODPRINTF("Mhook_SetHook exit 3\n");
	return (pTrampoline != NULL);
}

//=========================================================================
BOOL Mhook_Unhook(PVOID *ppHookedFunction)
{

#ifdef __OS_KERNEL__
    unsigned long o_cr0;
#endif

	BOOL bRet = FALSE;
	MHOOKS_TRAMPOLINE * pTrampoline;
	ODPRINTF("mhooks: Mhook_Unhook: %p\n", *ppHookedFunction);
	EnterCritSec();

#ifdef __OS_KERNEL__
    o_cr0 = disable_wp();
#endif

	// get the trampoline structure that corresponds to our function
	pTrampoline = TrampolineGet((PBYTE)*ppHookedFunction);
	if (pTrampoline) {
		DWORD dwOldProtectSystemFunction = 0;
		// make sure nobody's executing code where we're about to overwrite a few bytes
		SuspendOtherThreads(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
		ODPRINTF("mhooks: Mhook_Unhook: found struct at %p\n", pTrampoline);
		// open ourselves so we can VirtualProtectEx
		// -- HANDLE hProc = GetCurrentProcess();

		// make memory writable

		// -- if (VirtualProtectEx(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
		// -- int memProtect(unsigned char * addr, long length)
		if(0 == memProtect(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode)){
			DWORD i = 0;
			PBYTE pbCode;
			ODPRINTF("mhooks: Mhook_Unhook: readwrite set on system function\n");
			pbCode = (PBYTE)pTrampoline->pSystemFunction;
			for (i = 0; i<pTrampoline->cbOverwrittenCode; i++) {
				pbCode[i] = pTrampoline->codeUntouched[i];
			}
			// flush instruction cache and make memory unwritable
			// -- FlushInstructionCache(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
			// -- VirtualProtectEx(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			// return the original function pointer
			*ppHookedFunction = pTrampoline->pSystemFunction;
			bRet = TRUE;
			ODPRINTF("mhooks: Mhook_Unhook: sysfunc: %p\n", *ppHookedFunction);
			// free the trampoline while not really discarding it from memory
			TrampolineFree(pTrampoline, FALSE);
			ODPRINTF("mhooks: Mhook_Unhook: unhook successful");
		} else {
			#ifndef __OS_KERNEL__
				ODPRINTF(("mhooks: Mhook_Unhook: failed VirtualProtectEx 1: %d\n", gle()));
			#else
				ODPRINTF("mhooks: Mhook_Unhook: failed VirtualProtectEx 1\n");
			#endif
		}
		// make the other guys runnable
		ResumeOtherThreads();
	}
	LeaveCritSec();

#ifdef __OS_KERNEL__
    restore_wp(o_cr0);
#endif

	return bRet;
}

//=========================================================================
