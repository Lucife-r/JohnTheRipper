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
*/

#include <string.h>
#include "parallel.h"
#include "sha2.h"

#define HASH_LENGTH    64

static inline uint64_t calcLoopCount(uint32_t cost)
{
	// floor((cost & 1 ? 2 : 3) * 2 ** floor((cost - 1) / 2))
	// 1, 2, 3, 4, 6, 8, 12, 16, ...
	if (cost == 0)
	{
		return 1;
	}
	return ((uint64_t) ((cost & 1) ^ 3)) << ((cost - 1) >> 1);
}

static void hash(const void *message, size_t length, void *out, uint32_t outLength)
{
	uint64_t block[16];
	uint64_t tmp;
	size_t   left;
	uint32_t i,end,shift;

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	
	
	left = length;

	while (left >= 128)
	{
		SHA512_Transform(&ctx, message);
		message = ((const uint64_t*) message) + 16;
		left -= 128;
	}
	memcpy(block, message, left);
	((uint8_t*) block)[left] = 0x80;
	memset(((uint8_t*) block) + (left + 1), 0, 128 - (left + 1));
	if (left >= 128 - 16)
	{
		SHA512_Transform(&ctx, (unsigned char*)block);
		for (i = 0; i < 14; i++)
		{
			block[i] = 0;
		}
	}
	tmp = ((uint64_t) length) >> (64 - 3);
	block[14] = WRITE_BIG_ENDIAN_64(tmp);
	tmp = ((uint64_t) length) << 3;
	block[15] = WRITE_BIG_ENDIAN_64(tmp);
	SHA512_Transform(&ctx,(unsigned char*)block);
	if (outLength > 64)
	{
		outLength = 64;
	}
	for (i = 0, end = outLength / 8; i < end; i++)
	{
		((uint64_t*) out)[i] = WRITE_BIG_ENDIAN_64(ctx.h[i]);
	}
	for (i = outLength & ~7, shift = 56; i < outLength; i++, shift -= 8)
	{
		((uint8_t*) out)[i] = (uint8_t) (ctx.h[i / 8] >> shift);
	}
}

int PARALLEL(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost)
{
	uint64_t key [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t tmp [HASH_LENGTH / sizeof(uint64_t)];
	uint64_t work[HASH_LENGTH / sizeof(uint64_t)];
	uint64_t parallelLoops;
	uint64_t sequentialLoops;
	uint64_t i;
	uint64_t j;
	unsigned int k;
	SHA512_CTX ctx;


	if ((t_cost & 0xffff) > 106 || (t_cost >> 16) > 126 || outlen > HASH_LENGTH)
	{
		memset(out, 0, outlen);
		return 1;
	}

	// key = hash(hash(salt) || in)

	hash(salt, saltlen, key,HASH_LENGTH);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, HASH_LENGTH);
	SHA512_Update(&ctx, in, inlen);
	SHA512_Final((unsigned char *)key, &ctx);

	// Work
	parallelLoops = 3 * 5 * 128 * calcLoopCount(t_cost & 0xffff);
	sequentialLoops = calcLoopCount(t_cost >> 16);

	for (i = 0; i < sequentialLoops; i++)
	{
		// Clear work
		memset(work, 0, HASH_LENGTH);

		for (j = 0; j < parallelLoops; j++)
		{
			// work ^= hash(WRITE_BIG_ENDIAN_64(j) || key)
			uint64_t tmpJ = WRITE_BIG_ENDIAN_64(j);

			SHA512_Init(&ctx);
			SHA512_Update(&ctx, &tmpJ, sizeof(tmpJ));
			SHA512_Update(&ctx, key, HASH_LENGTH);
			SHA512_Final((unsigned char *)tmp, &ctx);
			for (k = 0; k < HASH_LENGTH / sizeof(uint64_t); k++)
			{
				work[k] ^= tmp[k];
			}
		}

		// Finish
		// key = truncate(hash(hash(work || key)), outlen) || zeros(HASH_LENGTH - outlen)

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, work, HASH_LENGTH);
		SHA512_Update(&ctx, key, HASH_LENGTH);
		SHA512_Final((unsigned char *)key, &ctx);
		hash(key, HASH_LENGTH, key,outlen);

		memset(((uint8_t*) key) + outlen, 0, HASH_LENGTH - outlen);
	}

	// Finish
	// out = key
	memcpy(out, key, outlen);

	return 0;
} 
