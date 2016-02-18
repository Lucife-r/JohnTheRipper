/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2015 Alexander Peslyak
 * Copyright 2015-2016 Agnieszka Bielec
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


#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_yescrypt.h"
#include "opencl_hmac_sha256.h"

// BINARY_SIZE, SALT_SIZE, HASH_SIZE, PLAINTEXT_LENGTH, KEY_SIZE is passed with -D during build

#define NULL 0

struct yescrypt_salt {
	char salt[SALT_SIZE];
	uint salt_length;
	uint64_t N;
	uint r, p, t, g;
	uint flags;
	//ROM
	char ROM;
	char key[KEY_SIZE];
	uint64_t rom_size;
	uint64_t rom_N;
	uint rom_r, rom_p;
};

typedef struct {
	__global uint64_t *S0, *S1, *S2;
	size_t w;
} pwxform_ctx_t;

#define Salloc (Sbytes + ((sizeof(pwxform_ctx_t) + 63) & ~63U))

inline void blkcpy_pg(ulong *dest, __global ulong * src, uint count)
{
	ulong4 * dest4=(ulong4 *) dest;
	__global ulong4 * src4=(__global ulong4 *) src;
	do {
		*dest4++ = *src4++;
	} while (count -= 4);
}

inline void blkcpy_gp(__global ulong *dest, ulong * src, uint count)
{
	__global ulong8 * dest8=(__global ulong8 *) dest;
	ulong8 * src8=(ulong8 *) src;
	do {
		*dest8++ = *src8++;
	} while (count -= 8);
}

inline void blkcpy_gg(__global ulong *dest, __global ulong * src, uint count)
{
	__global ulong8 * dest8=(__global ulong8 *) dest;
	__global ulong8 * src8=(__global ulong8 *) src;
	do {
		*dest8++ = *src8++;
	} while (count -= 8);
}

inline void blkxor_gg(__global ulong * dest, __global ulong * src, uint count)
{
	__global ulong4 * dest4=(__global ulong4 *) dest;
	__global ulong4 * src4=(__global ulong4 *) src;
	do {
		*dest4++ ^= *src4++;		
	} while (count -= 4);
}

inline void blkxor_pg(ulong * dest, __global ulong * src, uint count)
{
	ulong4 * dest4=(ulong4 *) dest;
	__global ulong4 * src4=(__global ulong4 *) src;
	do {
		*dest4++ ^= *src4++;		
	} while (count -= 4);
}

inline void blkxor_gp(__global ulong * dest, ulong * src, uint count)
{
	__global ulong4 * dest4=(__global ulong4 *) dest;
	ulong4 * src4=(ulong4 *) src;
	do {
		*dest4++ ^= *src4++;		
	} while (count -= 4);
}

inline void blkcpy_and_xor_ggg(__global ulong *dest, __global ulong * src1, __global ulong * src2, uint count)
{
	__global ulong8 * dest8=(__global ulong8 *) dest;
	__global ulong8 * src1_8=(__global ulong8 *) src1;
	__global ulong8 * src2_8=(__global ulong8 *) src2;
	do {
		*dest8++ = *src1_8++ ^ *src2_8++;
	} while (count -= 8);
}

inline void blkcpy_and_xor_ggp(__global ulong *dest, __global ulong * src1, ulong * src2, uint count)
{
	__global ulong8 * dest8=(__global ulong8 *) dest;
	__global ulong8 * src1_8=(__global ulong8 *) src1;
	ulong8 * src2_8=(ulong8 *) src2;
	do {
		*dest8++ = *src1_8++ ^ *src2_8++;
	} while (count -= 4);
}

typedef union {
	uint w[16];
	uint64_t d[8];
} salsa20_blk_t;

inline void salsa20_shuffle_gg(__global salsa20_blk_t * Bin, __global salsa20_blk_t * Bout)
{
#define COMBINE(out, in1, in2) \
	Bout->d[out] = Bin->w[in1 * 2] | ((uint64_t)Bin->w[in2 * 2 + 1] << 32);
	COMBINE(0, 0, 2)
	COMBINE(1, 5, 7)
	COMBINE(2, 2, 4)
	COMBINE(3, 7, 1)
	COMBINE(4, 4, 6)
	COMBINE(5, 1, 3)
	COMBINE(6, 6, 0)
	COMBINE(7, 3, 5)
#undef COMBINE
}

inline void salsa20_shuffle_pp(salsa20_blk_t * Bin, salsa20_blk_t * Bout)
{
#define COMBINE(out, in1, in2) \
	Bout->d[out] = Bin->w[in1 * 2] | ((uint64_t)Bin->w[in2 * 2 + 1] << 32);
	COMBINE(0, 0, 2)
	COMBINE(1, 5, 7)
	COMBINE(2, 2, 4)
	COMBINE(3, 7, 1)
	COMBINE(4, 4, 6)
	COMBINE(5, 1, 3)
	COMBINE(6, 6, 0)
	COMBINE(7, 3, 5)
#undef COMBINE
}


inline void salsa20_unshuffle_gp(__global salsa20_blk_t * Bin, salsa20_blk_t * Bout)
{
#define UNCOMBINE(out, in1, in2) \
	Bout->w[out * 2] = Bin->d[in1]; \
	Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
	UNCOMBINE(0, 0, 6)
	UNCOMBINE(1, 5, 3)
	UNCOMBINE(2, 2, 0)
	UNCOMBINE(3, 7, 5)
	UNCOMBINE(4, 4, 2)
	UNCOMBINE(5, 1, 7)
	UNCOMBINE(6, 6, 4)
	UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}

inline void salsa20_unshuffle_pp(salsa20_blk_t * Bin, salsa20_blk_t * Bout)
{
#define UNCOMBINE(out, in1, in2) \
	Bout->w[out * 2] = Bin->d[in1]; \
	Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
	UNCOMBINE(0, 0, 6)
	UNCOMBINE(1, 5, 3)
	UNCOMBINE(2, 2, 0)
	UNCOMBINE(3, 7, 5)
	UNCOMBINE(4, 4, 2)
	UNCOMBINE(5, 1, 7)
	UNCOMBINE(6, 6, 4)
	UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}


inline void salsa20_unshuffle_gg(__global salsa20_blk_t * Bin, __global salsa20_blk_t * Bout)
{
#define UNCOMBINE(out, in1, in2) \
	Bout->w[out * 2] = Bin->d[in1]; \
	Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
	UNCOMBINE(0, 0, 6)
	UNCOMBINE(1, 5, 3)
	UNCOMBINE(2, 2, 0)
	UNCOMBINE(3, 7, 5)
	UNCOMBINE(4, 4, 2)
	UNCOMBINE(5, 1, 7)
	UNCOMBINE(6, 6, 4)
	UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}

/**
 * salsa20(B):
 * Apply the Salsa20 core to the provided block.
 */
static void
salsa20(__global uint64_t *B[8], uint32_t doublerounds)
{
	salsa20_blk_t X;
	uint64_t b[8];
	for(int i=0;i<8;i++)
	  b[i]=B[i];
#define x X.w

	salsa20_unshuffle_pp((salsa20_blk_t *)b, &X);

	do {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		/* Operate on rows */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
	} while (--doublerounds);
#undef x

	{
		uint32_t i;
		salsa20_blk_t Y;
		salsa20_shuffle_pp(&X, &Y);
		for (i = 0; i < 16; i += 4) {
			((salsa20_blk_t *)b)->w[i] += Y.w[i];
			((salsa20_blk_t *)b)->w[i + 1] += Y.w[i + 1];
			((salsa20_blk_t *)b)->w[i + 2] += Y.w[i + 2];
			((salsa20_blk_t *)b)->w[i + 3] += Y.w[i + 3];
		}
	}
	
	for(int i=0;i<8;i++)
	  B[i]=b[i];
}

/**
 * blockmix_salsa8(Bin, Bout, X, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.  The
 * temporary space X must be 64 bytes.
 */
void blockmix_salsa8_ggg(__global uint64_t * Bin, __global uint64_t * Bout, __global uint64_t * X, uint r)
{
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy_gg(X, &Bin[(2 * r - 1) * 8], 8);

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < 2 * r; i += 2) {
		/* 3: X <-- H(X \xor B_i) */
		blkxor_gg(X, &Bin[i * 8], 8);
		salsa20(X, 4);

		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		blkcpy_gg(&Bout[i * 4], X, 8);

		/* 3: X <-- H(X \xor B_i) */
		blkxor_gg(X, &Bin[i * 8 + 8], 8);
		salsa20(X, 4);

		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		blkcpy_gg(&Bout[i * 4 + r * 8], X, 8);
	}
}

/**
 * pwxform(B):
 * Transform the provided block using the provided S-boxes.
 */
void pwxform(__global uint64_t * B, __global pwxform_ctx_t * ctx)
{
	__global uint64_t (*X)[PWXsimple] = (__global uint64_t (*)[PWXsimple])B;
	__global uint64_t *S0 = ctx->S0, *S1 = ctx->S1, *S2 = ctx->S2;
	size_t w = ctx->w;
	size_t i, j;
#if PWXsimple > 2
	size_t k;
#endif

	/* 2: for j = 0 to PWXgather - 1 do */
	for (j = 0; j < PWXgather; j++) {
		__global uint64_t *Xj = X[j];
		uint64_t x0 = Xj[0];
#if PWXsimple > 1
		uint64_t x1 = Xj[1];
#endif

		/* 1: for i = 0 to PWXrounds - 1 do */
		for (i = 0; i < PWXrounds; i++) {
			uint64_t x = x0 & Smask2;
			__global uint64_t *p0, *p1;

			/* 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8) */
			p0 = (__global uint64_t *)((__global uint8_t *)S0 + (uint32_t)x);
			/* 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8) */
			p1 = (__global uint64_t *)((__global uint8_t *)S1 + (x >> 32));

			/* 5: for k = 0 to PWXsimple - 1 do */
			/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k} */
			x0 = (uint64_t)(x0 >> 32) * (uint32_t)x0;
			x0 += p0[0];
			x0 ^= p1[0];

#if PWXsimple > 1
			/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k} */
			x1 = (uint64_t)(x1 >> 32) * (uint32_t)x1;
			x1 += p0[1];
			x1 ^= p1[1];
#endif

#if PWXsimple > 2
			/* 5: for k = 0 to PWXsimple - 1 do */
			for (k = 2; k < PWXsimple; k++) {
				/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k} */
				x = Xj[k];

				x = (uint64_t)(x >> 32) * (uint32_t)x;
				x += p0[k];
				x ^= p1[k];

				Xj[k] = x;
			}
#endif

			/* 8: if (i != 0) and (i != PWXrounds - 1) */
			if ((i - 1) < PWXrounds - 2) {
				/* 9: S2_w <-- B_j */
				/* 10: w <-- w + 1 */
				__global uint64_t *p2 = (__global uint64_t *)((__global uint8_t *)S2 + w);
				w += PWXbytes;
				p2[0] = x0;
#if PWXsimple > 1
				p2[1] = x1;
#endif
#if PWXsimple > 2
				for (k = 2; k < PWXsimple; k++)
					p2[k] = Xj[k];
#endif
			}
		}

		Xj[0] = x0;
#if PWXsimple > 1
		Xj[1] = x1;
#endif

		w -= (PWXrounds - 2) * PWXbytes - PWXsimple * 8;
	}

	/* 14: (S0, S1, S2) <-- (S2, S0, S1) */
	ctx->S0 = S2;
	ctx->S1 = S0;
	ctx->S2 = S1;
	/* 15: w <-- w mod 2^Swidth */
	ctx->w = (w + (PWXrounds - 3) * PWXbytes) & Smask;
}

/**
 * blockmix_pwxform(Bin, Bout, S, r):
 * Compute Bout = BlockMix_pwxform{salsa20/2, ctx, r}(Bin).  The input Bin must
 * be 128r bytes in length; the output Bout must also be the same size.
 */
static void
blockmix_pwxform_ggg(__global uint64_t * Bin, __global uint64_t * Bout,
    __global pwxform_ctx_t * ctx, size_t r)
{
	size_t r1, r2, i;

	/* Convert 128-byte blocks to PWXbytes blocks */
	/* 1: r_1 <-- 128r / PWXbytes */
	r1 = r * 128 / PWXbytes;

	/* 2: X <-- B'_{r_1 - 1} */
	blkcpy_gg(Bout, &Bin[(r1 - 1) * PWXwords], PWXwords);

	/* 3: for i = 0 to r_1 - 1 do */
	/* 4: if r_1 > 1 */
	if (r1 > 1) {
		/* 5: X <-- X \xor B'_i */
		blkxor_gg(Bout, Bin, PWXwords);
	}

	/* 7: X <-- pwxform(X) */
	/* 8: B'_i <-- X */
	pwxform(Bout, ctx);

	/* 3: for i = 0 to r_1 - 1 do */
	for (i = 1; i < r1; i++) {
		/* 5: X <-- X \xor B'_i */
		blkcpy_gg(&Bout[i * PWXwords], &Bout[(i - 1) * PWXwords],
		    PWXwords);
		blkxor_gg(&Bout[i * PWXwords], &Bin[i * PWXwords], PWXwords);

		/* 7: X <-- pwxform(X) */
		/* 8: B'_i <-- X */
		pwxform(&Bout[i * PWXwords], ctx);
	}

#if PWXbytes > 128
	/*
	 * Handle partial blocks.  If we were using just one buffer, like in
	 * the algorithm specification, the data would already be there, but
	 * since we use separate input and output buffers, we may have to copy
	 * some data over (which will then be processed by the Salsa20/8
	 * invocations below) in this special case - that is, when 128r is not
	 * a multiple of PWXbytes.  Since PWXgather and PWXsimple must each be
	 * a power of 2 (per the specification), PWXbytes is also a power of 2.
	 * Thus, 128r is obviously a multiple of valid values of PWXbytes up to
	 * 128, inclusive.  When PWXbytes is larger than that (thus, 256 or
	 * larger) we perform this extra check.
	 */
	if (i * PWXwords < r * 16)
		blkcpy_gg(&Bout[i * PWXwords], &Bin[i * PWXwords],
		    r * 16 - i * PWXwords);
#endif

	/* 10: i <-- floor((r_1 - 1) * PWXbytes / 64) */
	i = (r1 - 1) * PWXbytes / 64;

	/* Convert 128-byte blocks to 64-byte blocks */
	r2 = r * 2;

	/* 11: B_i <-- H(B_i) */
	salsa20(&Bout[i * 8], 1);

	for (i++; i < r2; i++) {
		/* 13: B_i <-- H(B_i \xor B_{i-1}) */
		blkxor_gg(&Bout[i * 8], &Bout[(i - 1) * 8], 8);
		salsa20(&Bout[i * 8], 1);
	}
}


/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
inline uint64_t integerify(__global uint64_t * B, uint r)
{
/*
 * Our 64-bit words are in host byte order, and word 6 holds the second 32-bit
 * word of B_{2r-1} due to SIMD shuffling.  The 64-bit value we return is also
 * in host byte order, as it should be.
 */
	__global uint64_t * X = &B[(2 * r - 1) * 8];
	uint lo = X[0];
	uint hi = X[6] >> 32;
	return ((uint64_t)hi << 32) + lo;
}

/**
 * smix1(B, r, N, flags, V, NROM, VROM, XY, ctx):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.  The value N must be even and
 * no smaller than 2.
 */
void smix1(__global uint64_t * B, uint r, uint64_t N, uint flags,
    __global uint64_t * V, uint64_t NROM, __global uint64_t * VROM,
    __global uint64_t * XY, __global pwxform_ctx_t * ctx)
{
	uint s = 16 * r;
	__global uint64_t * X = V;
	__global uint64_t * Y = &XY[s];
	__global uint64_t * Z = &XY[2 * s];
	uint64_t n, i, j;
	size_t k;

	/* 1: X <-- B */
	/* 3: V_i <-- X */
	for (i = 0; i < 2 * r; i++) {
		__global salsa20_blk_t *src = (__global salsa20_blk_t *)&B[i * 8];
		__global salsa20_blk_t *tmp = (__global salsa20_blk_t *)Y;
		__global salsa20_blk_t *dst = (__global salsa20_blk_t *)&X[i * 8];
		for (k = 0; k < 16; k++)
			tmp->w[k] = le32dec(&src->w[k]);
		salsa20_shuffle_gg(tmp, dst);
	}

	/* 4: X <-- H(X) */
	/* 3: V_i <-- X */
	if (ctx)
		blockmix_pwxform_ggg(X, Y, ctx, r);
	else
		blockmix_salsa8_ggg(X, Y, Z, r);
	blkcpy_gg(&V[s], Y, s);

	X = XY;

	if (VROM) {
		/* j <-- Integerify(X) mod NROM */
		j = integerify(Y, r) & (NROM - 1);

		/* X <-- H(X \xor VROM_j) */
		blkxor_gg(Y, &VROM[j * s], s);

		blockmix_pwxform_ggg(Y, X, ctx, r);

		/* 2: for i = 0 to N - 1 do */
		for (n = 1, i = 2; i < N; i += 2) {
			/* 3: V_i <-- X */
			blkcpy_gg(&V[i * s], X, s);

			if ((i & (i - 1)) == 0)
				n <<= 1;

			/* j <-- Wrap(Integerify(X), i) */
			j = integerify(X, r) & (n - 1);
			j += i - n;

			/* X <-- X \xor V_j */
			blkxor_gg(X, &V[j * s], s);

			/* 4: X <-- H(X) */
			blockmix_pwxform_ggg(X, Y, ctx, r);

			/* 3: V_i <-- X */
			blkcpy_gg(&V[(i + 1) * s], Y, s);

			/* j <-- Integerify(X) mod NROM */
			j = integerify(Y, r) & (NROM - 1);

			/* X <-- H(X \xor VROM_j) */
			blkxor_gg(Y, &VROM[j * s], s);

			blockmix_pwxform_ggg(Y, X, ctx, r);
		}
	} else if (flags & YESCRYPT_RW) {
		/* 4: X <-- H(X) */
		blockmix_pwxform_ggg(Y, X, ctx, r);

		/* 2: for i = 0 to N - 1 do */
		for (n = 1, i = 2; i < N; i += 2) {
			/* 3: V_i <-- X */
			blkcpy_gg(&V[i * s], X, s);

			if ((i & (i - 1)) == 0)
				n <<= 1;

			/* j <-- Wrap(Integerify(X), i) */
			j = integerify(X, r) & (n - 1);
			j += i - n;

			/* X <-- X \xor V_j */
			blkxor_gg(X, &V[j * s], s);

			/* 4: X <-- H(X) */
			blockmix_pwxform_ggg(X, Y, ctx, r);

			/* 3: V_i <-- X */
			blkcpy_gg(&V[(i + 1) * s], Y, s);

			/* j <-- Wrap(Integerify(X), i) */
			j = integerify(Y, r) & (n - 1);
			j += (i + 1) - n;

			/* X <-- X \xor V_j */
			blkxor_gg(Y, &V[j * s], s);

			/* 4: X <-- H(X) */
			blockmix_pwxform_ggg(Y, X, ctx, r);
		}
	} else {
		/* 4: X <-- H(X) */
		blockmix_salsa8_ggg(Y, X, Z, r);

		/* 2: for i = 0 to N - 1 do */
		for (n = 1, i = 2; i < N; i += 2) {
			/* 3: V_i <-- X */
			blkcpy_gg(&V[i * s], X, s);

			/* 4: X <-- H(X) */
			blockmix_salsa8_ggg(X, Y, Z, r);

			/* 3: V_i <-- X */
			blkcpy_gg(&V[(i + 1) * s], Y, s);

			/* 4: X <-- H(X) */
			blockmix_salsa8_ggg(Y, X, Z, r);
		}
	}

	/* B' <-- X */
	for (i = 0; i < 2 * r; i++) {
		__global salsa20_blk_t *src = (__global salsa20_blk_t *)&X[i * 8];
		__global salsa20_blk_t *tmp = (__global salsa20_blk_t *)Y;
		__global salsa20_blk_t *dst = (__global salsa20_blk_t *)&B[i * 8];
		for (k = 0; k < 16; k++)
			le32enc(&tmp->w[k], src->w[k]);
		salsa20_unshuffle_gg(tmp, dst);
	}
}



/**
 * smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, ctx):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.  The value N must be a
 * power of 2 greater than 1.  The value Nloop must be even.
 */
static void
smix2(__global uint64_t * B, size_t r, uint64_t N, uint64_t Nloop,
    yescrypt_flags_t flags,
    __global uint64_t * V, uint64_t NROM, __global uint64_t * VROM,
    __global uint64_t * XY, __global pwxform_ctx_t * ctx)
{
	size_t s = 16 * r;
	__global uint64_t * X = XY;
	__global uint64_t * Y = &XY[s];
	uint64_t i, j;

	if (Nloop == 0)
		return;

	/* X <-- B' */
	for (i = 0; i < 2 * r; i++) {
		__global salsa20_blk_t *src = (__global salsa20_blk_t *)&B[i * 8];
		__global salsa20_blk_t *tmp = (__global salsa20_blk_t *)Y;
		__global salsa20_blk_t *dst = (__global salsa20_blk_t *)&X[i * 8];
		size_t k;
		for (k = 0; k < 16; k++)
			tmp->w[k] = le32dec(&src->w[k]);
		salsa20_shuffle_gg(tmp, dst);
	}

	if (VROM) {
		yescrypt_flags_t rw = flags & YESCRYPT_RW;

		/* 6: for i = 0 to N - 1 do */
		for (i = 0; i < Nloop; i += 2) {
			/* 7: j <-- Integerify(X) mod N */
			j = integerify(X, r) & (N - 1);

			/* 8: X <-- H(X \xor V_j) */
			blkxor_gg(X, &V[j * s], s);
			/* V_j <-- Xprev \xor V_j */
			if (rw)
				blkcpy_gg(&V[j * s], X, s);
			blockmix_pwxform_ggg(X, Y, ctx, r);

			/* j <-- Integerify(X) mod NROM */
			j = integerify(Y, r) & (NROM - 1);

			/* X <-- H(X \xor VROM_j) */
			blkxor_gg(Y, &VROM[j * s], s);

			blockmix_pwxform_ggg(Y, X, ctx, r);
		}
	} else if (ctx) {
		yescrypt_flags_t rw = flags & YESCRYPT_RW;

		/* 6: for i = 0 to N - 1 do */
		i = Nloop / 2;
		do {
			/* 7: j <-- Integerify(X) mod N */
			j = integerify(X, r) & (N - 1);

			/* 8: X <-- H(X \xor V_j) */
			blkxor_gg(X, &V[j * s], s);
			/* V_j <-- Xprev \xor V_j */
			if (rw)
				blkcpy_gg(&V[j * s], X, s);
			blockmix_pwxform_ggg(X, Y, ctx, r);

			/* 7: j <-- Integerify(X) mod N */
			j = integerify(Y, r) & (N - 1);

			/* 8: X <-- H(X \xor V_j) */
			blkxor_gg(Y, &V[j * s], s);
			/* V_j <-- Xprev \xor V_j */
			if (rw)
				blkcpy_gg(&V[j * s], Y, s);
			blockmix_pwxform_ggg(Y, X, ctx, r);
		} while (--i);
	} else {
		__global uint64_t * Z = &XY[2 * s];

		/* 6: for i = 0 to N - 1 do */
		i = Nloop / 2;
		do {
			/* 7: j <-- Integerify(X) mod N */
			j = integerify(X, r) & (N - 1);

			/* 8: X <-- H(X \xor V_j) */
			blkxor_gg(X, &V[j * s], s);
			/* V_j <-- Xprev \xor V_j */
			blockmix_salsa8_ggg(X, Y, Z, r);

			/* 7: j <-- Integerify(X) mod N */
			j = integerify(Y, r) & (N - 1);

			/* 8: X <-- H(X \xor V_j) */
			blkxor_gg(Y, &V[j * s], s);
			/* V_j <-- Xprev \xor V_j */
			blockmix_salsa8_ggg(Y, X, Z, r);
		} while (--i);
	}

	/* 10: B' <-- X */
	for (i = 0; i < 2 * r; i++) {
		__global salsa20_blk_t *src = (__global salsa20_blk_t *)&X[i * 8];
		__global salsa20_blk_t *tmp = (__global salsa20_blk_t *)Y;
		__global salsa20_blk_t *dst = (__global salsa20_blk_t *)&B[i * 8];
		size_t k;
		for (k = 0; k < 16; k++)
			le32enc(&tmp->w[k], src->w[k]);
		salsa20_unshuffle_gg(tmp, dst);
	}
}


/**
 * p2floor(x):
 * Largest power of 2 not greater than argument.
 */
uint64_t p2floor(uint64_t x)
{
	uint64_t y;
	while ((y = x & (x - 1)))
		x = y;
	return x;
}

/**
 * smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S, passwd):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r+64 or (256r+64)*p bytes in length (the larger size is
 * required with OpenMP-enabled builds).  The value N must be a power of 2
 * greater than 1.
 */

void smix(__global uint64_t * B, uint r, uint64_t N, uint p, uint t,
    uint flags,
    __global uint64_t * V, uint64_t NROM, __global uint64_t * VROM,
    __global uint64_t * XY, __global uint8_t * S, uint8_t * passwd)
{
	uint s = 16 * r;
	uint64_t Nchunk, Nloop_all, Nloop_rw;
	uint32_t i;

	/* 1: n <-- N / p */
	Nchunk = N / p;

	/* 2: Nloop_all <-- fNloop(n, t, flags) */
	Nloop_all = Nchunk;
	if (flags & YESCRYPT_RW) {
		if (t <= 1) {
			if (t)
				Nloop_all *= 2; /* 2/3 */
			Nloop_all = (Nloop_all + 2) / 3; /* 1/3, round up */
		} else {
			Nloop_all *= t - 1;
		}
	} else if (t) {
		if (t == 1)
			Nloop_all += (Nloop_all + 1) / 2; /* 1.5, round up */
		Nloop_all *= t;
	}

	/* 6: Nloop_rw <-- 0 */
	Nloop_rw = 0;
	if (flags & __YESCRYPT_INIT_SHARED) {
		Nloop_rw = Nloop_all;
	} else {
		/* 3: if YESCRYPT_RW flag is set */
		if (flags & YESCRYPT_RW) {
			/* 4: Nloop_rw <-- Nloop_all / p */
			Nloop_rw = Nloop_all / p;
		}
	}

	/* 8: n <-- n - (n mod 2) */
	Nchunk &= ~(uint64_t)1; /* round down to even */
	/* 9: Nloop_all <-- Nloop_all + (Nloop_all mod 2) */
	Nloop_all++; Nloop_all &= ~(uint64_t)1; /* round up to even */
	/* 10: Nloop_rw <-- Nloop_rw + (Nloop_rw mod 2) */
	Nloop_rw++; Nloop_rw &= ~(uint64_t)1; /* round up to even */


	/* 11: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 12: u <-- in */
		uint64_t Vchunk = i * Nchunk;
		/* 13: if i = p - 1 */
		/* 14:   n <-- N - u */
		/* 15: end if */
		/* 16: v <-- u + n - 1 */
		uint64_t Np = (i < p - 1) ? Nchunk : (N - Vchunk);
		__global uint64_t * Bp = &B[i * s];
		__global uint64_t * Vp = &V[Vchunk * s];
		__global uint64_t * XYp = XY;
		__global pwxform_ctx_t * ctx_i = NULL;
		
		
		/* 17: if YESCRYPT_RW flag is set */
		if (flags & YESCRYPT_RW) {
			__global uint64_t *Si = (__global uint64_t *)(S + i * Salloc);
			/* 18: SMix1_1(B_i, Sbytes / 128, S_i, no flags) */
			smix1(Bp, 1, Sbytes / 128, 0 /* no flags */,
			    Si, 0, NULL, XYp, NULL);
			
			ctx_i = (__global pwxform_ctx_t *)(Si + Swords);
			/* 19: S2_i <-- S_{i,0...2^Swidth-1} */
			ctx_i->S2 = Si;
			/* 20: S1_i <-- S_{i,2^Swidth...2*2^Swidth-1} */
			ctx_i->S1 = Si + Swords / 3;
			/* 21: S0_i <-- S_{i,2*2^Swidth...3*2^Swidth-1} */
			ctx_i->S0 = Si + Swords / 3 * 2;
			/* 22: w_i <-- 0 */
			ctx_i->w = 0;
			/* 23: if i = 0 */
			if (i == 0) {
				/* 24: passwd <-- HMAC-SHA256(B_{0,2r-1}, passwd) */
				HMAC_SHA256_CTX ctx;
				char tmp[64];
				for(int ii=0;ii<64;ii++)
				  tmp[ii]=((__global char*) (Bp + (s - 8)))[ii];
				HMAC_SHA256_Init(&ctx, tmp, 64);
				HMAC_SHA256_Update(&ctx, passwd, 32);
				HMAC_SHA256_Final(passwd, &ctx);
			}
		}
		
		
		if (!(flags & __YESCRYPT_INIT_SHARED_2)) {
			/* 27: SMix1_r(B_i, n, V_{u..v}, flags) */
			smix1(Bp, r, Np, flags, Vp, NROM, VROM, XYp, ctx_i);
		}
		
		/* 28: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{u..v}, flags) */
		smix2(Bp, r, p2floor(Np), Nloop_rw, flags, Vp,
		    NROM, VROM, XYp, ctx_i);
	}

	/* 30: for i = 0 to p - 1 do */
	if (Nloop_all > Nloop_rw) {
		for (i = 0; i < p; i++) {
			__global uint64_t * Bp = &B[i * s];
			__global uint64_t * XYp = XY;
			__global pwxform_ctx_t * ctx_i = NULL;
			if (flags & YESCRYPT_RW)
				ctx_i = (__global pwxform_ctx_t *)(S + i * Salloc + Sbytes);
			/* 31: SMix2_r(B_i, N, Nloop_all - Nloop_rw, V, flags excluding YESCRYPT_RW) */
			smix2(Bp, r, N, Nloop_all - Nloop_rw,
			    flags & ~YESCRYPT_RW, V, NROM, VROM, XYp, ctx_i);
		}
	}
}

/**
 * yescrypt_kdf_body(shared, local, passwd, passwdlen, salt, saltlen,
 *     N, r, p, t, flags, buf, buflen, V, B, XY, S):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen), or a revision of scrypt as requested by flags and shared, and
 * write the result into buf.  The parameters r, p, and buflen must satisfy
 * r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N must be a power
 * of 2 greater than 1.
 *
 * t controls computation time while not affecting peak memory usage.  shared
 * and flags may request special modes as described in yescrypt.h.  local is
 * the thread-local data structure, allowing to preserve and reuse a memory
 * allocation across calls, thereby reducing its overhead.
 *
 * Return 0 on success; or -1 on error.
 */
static int
yescrypt_kdf_body(
    __global uint64_t * VROM, uint64_t NROM,
    uchar * passwd, uint passwdlen,
    uchar * salt, uint saltlen,
    uint64_t N, uint r, uint p, uint t, uint flags,
    uchar * buf, uint buflen, __global uint64_t *V,
    __global uint64_t *B, __global uint64_t *XY, __global uint8_t* S)
{
	uint B_size;
	uint64_t sha256[4];
	uchar dk[sizeof(sha256)], * dkp = buf;

	uchar init_buf[]="yescrypt-prehash";

	if (VROM) {
		NROM = NROM / (128 * r);
		if (((NROM & (NROM - 1)) != 0) || (NROM <= 1) ||
		    !(flags & YESCRYPT_RW)) {
			return -1;
		}
	}

	B_size = (size_t)128 * r * p;

	if (flags) {
		HMAC_SHA256_CTX ctx;
		HMAC_SHA256_Init(&ctx, init_buf,
		    (flags & __YESCRYPT_PREHASH) ? 16 : 8);
		HMAC_SHA256_Update(&ctx, passwd, passwdlen);
		HMAC_SHA256_Final((uchar *)sha256, &ctx);
		passwd = (uchar *)sha256;
		passwdlen = sizeof(sha256);
	}

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256_global2(passwd, passwdlen, salt, saltlen, 1, (__global uchar *)B, B_size);


	if (flags)
		blkcpy_pg(sha256, B, sizeof(sha256) / sizeof(sha256[0]));
	

	if (p == 1 || (flags & YESCRYPT_RW)) {
		smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S,
		    (uint8_t *)sha256);
	} else {
		uint i;
		/* 2: for i = 0 to p - 1 do */
		for (i = 0; i < p; i++) {
			smix(&B[(size_t)16 * r * i], r, N, 1, t, flags, V,
			    NROM, VROM, XY, NULL, NULL);
		}
	}
	

	dkp = buf;
	if (flags && buflen < sizeof(dk)) {
		PBKDF2_SHA256_global(passwd, passwdlen, (__global uchar *)B, B_size,
		    1, dk, sizeof(dk));
		dkp = dk;
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256_global(passwd, passwdlen, (__global uchar *)B, B_size, 1, buf, buflen);

	/*
	 * Except when computing classic scrypt, allow all computation so far
	 * to be performed on the client.  The final steps below match those of
	 * SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
	 * far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
	 * SCRAM's use of SHA-1) would be usable with yescrypt hashes.
	 */
	if (flags && !(flags & __YESCRYPT_PREHASH)) {
		/* Compute ClientKey */
		{
			uchar client_key[]="Client Key";
			HMAC_SHA256_CTX ctx;
			HMAC_SHA256_Init(&ctx, dkp, sizeof(dk));
			HMAC_SHA256_Update(&ctx, client_key, 10);
			HMAC_SHA256_Final((uchar *)sha256, &ctx);
		}
		/* Compute StoredKey */
		{
			int i;
			SHA256_CTX ctx;
			size_t clen = buflen;
			if (clen > sizeof(dk))
				clen = sizeof(dk);
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, (uchar *)sha256, sizeof(sha256));
			SHA256_Final(dk, &ctx);
			memcpy(buf, dk, clen);
		}
	}


	/* Success! */
	return 0;
}

__constant char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

__global uchar * encode64_uint32(__global uchar * dst, uint dstlen,
    uint src, uint srcbits)
{
	uint bit;

	for (bit = 0; bit < srcbits; bit += 6) {
		if (dstlen < 1)
			return NULL;
		*dst++ = itoa64[src & 0x3f];
		dstlen--;
		src >>= 6;
	}

	return dst;
}

void encode64(__global uchar * dst, uint dstlen,uchar * src, uint srclen)
{
	uint i;

	for (i = 0; i < srclen; ) {
		__global uchar * dnext;
		uint value = 0, bits = 0;
		do {
			value |= (uint)src[i++] << bits;
			bits += 8;
		} while (bits < 24 && i < srclen);
		dnext = encode64_uint32(dst, dstlen, value, bits);
		if (!dnext)
			return ;
		dstlen -= dnext - dst;
		dst = dnext;
	}

}

__kernel void yescrypt_crypt_kernel(
    __global const uchar * in,
    __global const uint * lengths,
    __global uchar *out,
    __global struct yescrypt_salt *salt, 
    __global uint64_t *V,
    __global uint64_t *B,
    __global uint64_t *XY,
    __global uint64_t *S,
    __global uint64_t *ROM
)
{
	int i;

	uchar buf[BINARY_SIZE];
	uchar real_salt[SALT_SIZE];
	uchar passwd[PLAINTEXT_LENGTH];
	uint flags=salt->flags;
	uint64_t N=salt->N;
	uint r=salt->r;
	uint p=salt->p;
	uint t=salt->t;
	uint g=salt->g;
	uint saltlen=salt->salt_length;

	uint gid=get_global_id(0);
	uint passwdlen=lengths[gid];
	uint64_t rom_size=salt->rom_size;

	out+=gid*HASH_SIZE;
	in += gid*PLAINTEXT_LENGTH;

	long V_size=128*r*(N<<(g*2));
	long B_size=128*r*p;
	long XY_size=256*r+64;
	long S_size = Salloc * p;

	for(i=0;i<passwdlen;i++)
		passwd[i]=in[i];

	for(i=0;i<saltlen;i++)
		real_salt[i]=salt->salt[i];

	for(i=0;i<HASH_SIZE;i++)
		out[i]=0;

	if(salt->ROM==0)
		ROM=NULL;

	B=(__global uint64_t *)(((__global char*)B)+gid*B_size);
	V = (__global uint64_t *)(((__global char*)V) + gid*V_size);
	XY = (__global uint64_t *)(((__global char*)XY) + gid*XY_size);
	S=(__global uint64_t *)(((__global char*)S)+gid*S_size);


	if ((flags & (YESCRYPT_RW | __YESCRYPT_INIT_SHARED)) == YESCRYPT_RW &&
	    p >= 1 && N / p >= 0x100 && N / p * r >= 0x20000) {
		int retval = yescrypt_kdf_body(
			ROM, rom_size, passwd, passwdlen, real_salt, saltlen,
		    N >> 6, r, p, 0, flags | __YESCRYPT_PREHASH,
		    buf, BINARY_SIZE, V, B, XY, S);
		if (retval)
		{
			for(i=4;i<HASH_SIZE;i++)
				out[i]=1;
			((__global int *)out)[0]=retval;
			return;
		}
		//passwd = dk;
		passwdlen = BINARY_SIZE;
		memcpy(passwd,buf,passwdlen);
	}

	do {
		int retval = yescrypt_kdf_body(
		    ROM, rom_size, passwd, passwdlen, real_salt, saltlen,
		    N, r, p, t, flags, buf, BINARY_SIZE, V, B, XY, S);
		if (retval)
		{
			for(i=4;i<HASH_SIZE;i++)
				out[i]=2;
			((__global int *)out)[0]=retval;
			return;
		}

		//passwd = dkp;
		passwdlen = BINARY_SIZE;
		memcpy(passwd,buf,passwdlen);

		N <<= 2;
		if (!N)
		{
			for(i=4;i<HASH_SIZE;i++)
				out[i]=3;
			((__global int *)out)[0]=-1;
			return;
		}
		t >>= 1;
	} while (g--);

	encode64(out, HASH_SIZE, buf, BINARY_SIZE);
}
 