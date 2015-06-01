/*
* The MIT License (MIT)
* 
* Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of
* this software and associated documentation files (the "Software"), to deal in
* the Software without restriction, including without limitation the rights to
* use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
* the Software, and to permit persons to whom the Software is furnished to do so,
* subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
* COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
* IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* modified in 2015 by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
* my parallel.h is based on original files: parallel.h and common.h
*/

#ifndef parallel_h
#define parallel_h

#include <stdio.h>
#include <inttypes.h>
#include "arch.h"

#ifdef _WIN32
	#pragma warning(disable:4996)
#endif

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

#if ARCH_LITTLE_ENDIAN==1

	#define READ_LITTLE_ENDIAN_64(n)                (n)
	#define READ_BIG_ENDIAN_64(n)     SWAP_ENDIAN_64(n)
	#define WRITE_LITTLE_ENDIAN_64(n)               (n)
	#define WRITE_BIG_ENDIAN_64(n)    SWAP_ENDIAN_64(n)
#else

	#define READ_LITTLE_ENDIAN_64(n)  SWAP_ENDIAN_64(n)
	#define READ_BIG_ENDIAN_64(n)                   (n)
	#define WRITE_LITTLE_ENDIAN_64(n) SWAP_ENDIAN_64(n)
	#define WRITE_BIG_ENDIAN_64(n)                  (n)
#endif

inline uint64_t calcLoopCount(uint32_t cost);

int PARALLEL(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int s_loops, unsigned int p_loops);


#endif
