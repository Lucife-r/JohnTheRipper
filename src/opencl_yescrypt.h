/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2015 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#ifndef _OPENCL_YESCRYPT_H
#define _OPENCL_YESCRYPT_H


/* These are tunable */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

/* Derived values.  Not tunable on their own. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint64_t))
#define Swords (Sbytes / sizeof(uint64_t))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define Smask2 (((uint64_t)Smask << 32) | Smask)
#define rmin ((PWXbytes + 127) / 128)

#if PWXbytes % 32 != 0
#error "blkcpy() and blkxor() currently work on multiples of 32."
#endif

#define Sbytes (3 * (1 << Swidth) * PWXsimple * 8)

typedef struct {
	uint64_t *S0, *S1, *S2;
	uint w;
} pwxform_ctx_t_;

#define Salloc_ (Sbytes + ((sizeof(pwxform_ctx_t_) + 63) & ~63U))

typedef struct {
	void * base, * aligned;
	size_t base_size, aligned_size;
} region_t_;

/**
 * Types for shared (ROM) and thread-local (RAM) data structures.
 */
typedef region_t_ yescrypt_shared_t;
typedef region_t_ yescrypt_local_t;

/**
 * Possible values for yescrypt_init_shared()'s flags argument.
 */
typedef enum {
	YESCRYPT_SHARED_DEFAULTS = 0,
	YESCRYPT_SHARED_PREALLOCATED = 0x100
} yescrypt_init_shared_flags_t;

/**
 * Possible values for the flags argument of yescrypt_kdf(),
 * yescrypt_gensalt_r(), yescrypt_gensalt().  These may be OR'ed together,
 * except that YESCRYPT_WORM and YESCRYPT_RW are mutually exclusive.
 * Please refer to the description of yescrypt_kdf() below for the meaning of
 * these flags.
 */
typedef enum {
/* public */
	YESCRYPT_WORM = 2,
	YESCRYPT_RW = 1,
/* private */
	__YESCRYPT_INIT_SHARED_1 = 0x10000,
	__YESCRYPT_INIT_SHARED_2 = 0x20000,
	__YESCRYPT_INIT_SHARED = 0x30000,
	__YESCRYPT_PREHASH = 0x100000
} yescrypt_flags_t;

#define YESCRYPT_KNOWN_FLAGS \
	(YESCRYPT_WORM | YESCRYPT_RW | \
	__YESCRYPT_INIT_SHARED | __YESCRYPT_PREHASH)
	

extern int yescrypt_init_shared(yescrypt_shared_t * __shared,
    const uint8_t * __param, size_t __paramlen,
    uint64_t __N, uint32_t __r, uint32_t __p,
    yescrypt_init_shared_flags_t __flags,
    uint8_t * __buf, size_t __buflen);
extern int yescrypt_free_shared(yescrypt_shared_t * _shared);
extern int yescrypt_init_local(yescrypt_local_t * _local);

#endif
