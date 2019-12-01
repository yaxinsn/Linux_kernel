// Copyright (C) 2002, Matt Conover (mconover@gmail.com)
#ifndef __MISC_H__
#define __MISC_H__
#ifdef __cplusplus
extern "C" {
#endif


#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// NOTE: start is inclusive, end is exclusive (as in start <= x < end)
#define IS_IN_RANGE(x, s, e) \
( \
	((ULONG_PTR)(x) == (ULONG_PTR)(s) && (ULONG_PTR)(x) == (ULONG_PTR)(e)) || \
	((ULONG_PTR)(x) >= (ULONG_PTR)(s) && (ULONG_PTR)(x) < (ULONG_PTR)(e)) \
)

#ifdef WIN32
	#if _MSC_VER >= 1400
	#pragma warning(disable:4996)
	#endif
#endif

#ifdef WIN32
	#if defined(__X86_64__)
		#define VALID_ADDRESS_MAX 0x7FFEFFFFFFFFFFFF // Win64 specific
		// -- typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
	#else
		#define VALID_ADDRESS_MAX 0x7FFEFFFF // Win32 specific
		// -- typedef unsigned int ULONG_PTR, *PULONG_PTR;
	#endif
#else
	// -- for linux
	#ifdef __X86_64__
		#define VALID_ADDRESS_MAX 0x7FFEFFFFFFFFFFFF // Win64 specific
	#else
		#define VALID_ADDRESS_MAX 0x7FFEFFFF // Win32 specific
	#endif
	
#endif

#ifdef WIN32
	#ifndef DECLSPEC_ALIGN
		#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
			#define DECLSPEC_ALIGN(x) __declspec(align(x))
		#else
			#define DECLSPEC_ALIGN(x)
		#endif
	#endif
#else
	#define DECLSPEC_ALIGN(x)
#endif

#define VALID_ADDRESS_MIN 0x10000    // Win32 specific
#define IS_VALID_ADDRESS(a) IS_IN_RANGE(a, VALID_ADDRESS_MIN, VALID_ADDRESS_MAX+1)

BOOL IsHexChar(BYTE ch);
BYTE *HexToBinary(char *Input, DWORD InputLength, DWORD *OutputLength);

#ifdef __cplusplus
}
#endif
#endif // MISC_H
