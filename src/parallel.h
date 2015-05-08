// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#ifndef parallel_h
#define parallel_h

#include <stdio.h>
#include <inttypes.h>
#include "arch.h"

#ifdef _WIN32
	#pragma warning(disable:4996)
#endif

#define __STDC_CONSTANT_MACROS
#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS


#define SWAP_ENDIAN_32_(x) \
	( \
		 ((x) << 24) | \
		(((x) <<  8) & 0x00ff0000) | \
		(((x) >>  8) & 0x0000ff00) | \
		 ((x) >> 24) \
	)
#define SWAP_ENDIAN_32(x)  SWAP_ENDIAN_32_(((uint32_t) (x)))
#define SWAP_ENDIAN_64_(x) \
	( \
		 ((x) << 56) | \
		(((x) << 40) & UINT64_C(0x00ff000000000000)) | \
		(((x) << 24) & UINT64_C(0x0000ff0000000000)) | \
		(((x) <<  8) & UINT64_C(0x000000ff00000000)) | \
		(((x) >>  8) & UINT64_C(0x00000000ff000000)) | \
		(((x) >> 24) & UINT64_C(0x0000000000ff0000)) | \
		(((x) >> 40) & UINT64_C(0x000000000000ff00)) | \
		 ((x) >> 56) \
	)
#define SWAP_ENDIAN_64(x)  SWAP_ENDIAN_64_(((uint64_t) (x)))

#ifdef ARCH_LITTLE_ENDIAN
	#define READ_LITTLE_ENDIAN_32(n)                (n)
	#define READ_BIG_ENDIAN_32(n)     SWAP_ENDIAN_32(n)
	#define WRITE_LITTLE_ENDIAN_32(n)               (n)
	#define WRITE_BIG_ENDIAN_32(n)    SWAP_ENDIAN_32(n)

	#define READ_LITTLE_ENDIAN_64(n)                (n)
	#define READ_BIG_ENDIAN_64(n)     SWAP_ENDIAN_64(n)
	#define WRITE_LITTLE_ENDIAN_64(n)               (n)
	#define WRITE_BIG_ENDIAN_64(n)    SWAP_ENDIAN_64(n)
#else
	#define READ_LITTLE_ENDIAN_32(n)  SWAP_ENDIAN_32(n)
	#define READ_BIG_ENDIAN_32(n)                   (n)
	#define WRITE_LITTLE_ENDIAN_32(n) SWAP_ENDIAN_32(n)
	#define WRITE_BIG_ENDIAN_32(n)                  (n)

	#define READ_LITTLE_ENDIAN_64(n)  SWAP_ENDIAN_64(n)
	#define READ_BIG_ENDIAN_64(n)                   (n)
	#define WRITE_LITTLE_ENDIAN_64(n) SWAP_ENDIAN_64(n)
	#define WRITE_BIG_ENDIAN_64(n)                  (n)
#endif

int PARALLEL(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int cost);


#endif
