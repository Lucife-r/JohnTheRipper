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


#include "opencl_device_info.h"
#include "opencl_misc.h"


#define SWAP_ENDIAN_64_(x) \
	( \
		 ((x) << 56) | \
		(((x) << 40) & 0x00ff000000000000) | \
		(((x) << 24) & 0x0000ff0000000000) | \
		(((x) <<  8) & 0x000000ff00000000) | \
		(((x) >>  8) & 0x00000000ff000000) | \
		(((x) >> 24) & 0x0000000000ff0000) | \
		(((x) >> 40) & 0x000000000000ff00) | \
		 ((x) >> 56) \
	)

#define SWAP_ENDIAN_64(x)  SWAP_ENDIAN_64_(((unsigned long) (x)))


unsigned long constant SHA512_CONSTS[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};


#define INIT { \
	m_messageLengthLo = 0;		\
	m_state[0] = 0x6a09e667f3bcc908;	\
	m_state[1] = 0xbb67ae8584caa73b;	\
	m_state[2] = 0x3c6ef372fe94f82b;	\
	m_state[3] = 0xa54ff53a5f1d36f1;	\
	m_state[4] = 0x510e527fade682d1;	\
	m_state[5] = 0x9b05688c2b3e6c1f;	\
	m_state[6] = 0x1f83d9abfb41bd6b;	\
	m_state[7] = 0x5be0cd19137e2179;	\
}	\


inline void sha512Block(unsigned long block[16], unsigned long state[8])
{
#define ROTR(n,s) ((n >> s) | (n << (64 - s)))
#define SHA512_STEP(a,b,c,d,e,f,g,h,w,i) \
	h += (ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41)) + ((e & f) ^ (~e & g)) + SHA512_CONSTS[i] + w[i]; \
	d += h; \
	h += (ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));

	unsigned long w[80];
	unsigned long a = state[0];
	unsigned long b = state[1];
	unsigned long c = state[2];
	unsigned long d = state[3];
	unsigned long e = state[4];
	unsigned long f = state[5];
	unsigned long g = state[6];
	unsigned long h = state[7];

	for (int i = 0; i < 16; i++)
	{
		w[i] = SWAP_ENDIAN_64(block[i]);
	}
	for (int i = 16; i < 80; i++)
	{
        w[i] = 
			w[i-16] +
			w[i- 7] +
			(ROTR(w[i-15],  1) ^ ROTR(w[i-15],  8) ^ (w[i-15] >> 7)) +
			(ROTR(w[i- 2], 19) ^ ROTR(w[i- 2], 61) ^ (w[i- 2] >> 6));
	}

	for (int i = 0; i < 80; i += 8)
	{
		SHA512_STEP(a,b,c,d,e,f,g,h,w,i+0);
		SHA512_STEP(h,a,b,c,d,e,f,g,w,i+1);
		SHA512_STEP(g,h,a,b,c,d,e,f,w,i+2);
		SHA512_STEP(f,g,h,a,b,c,d,e,w,i+3);
		SHA512_STEP(e,f,g,h,a,b,c,d,w,i+4);
		SHA512_STEP(d,e,f,g,h,a,b,c,w,i+5);
		SHA512_STEP(c,d,e,f,g,h,a,b,w,i+6);
		SHA512_STEP(b,c,d,e,f,g,h,a,w,i+7);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

#undef ROTR
#undef SHA512_STEP
}

inline void hash(void *message, unsigned int length, void *out, unsigned int outLength)
{
	unsigned long block[16];
	unsigned int i,end,shift;
	unsigned long state[8] = {
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
	unsigned int left = length;

	while (left >= 128)
	{
		sha512Block((unsigned long*) message, state);
		message = ((unsigned long*) message) + 16;
		left -= 128;
	}
	
	for(i=0;i<left;i++)
		((unsigned char*)block)[i]=((unsigned char*)message)[i];
	((unsigned char*) block)[left] = 0x80;
	for(i=0;i<128 - (left + 1);i++)
		((unsigned char*) block)[left + 1+i]=0;

	if (left >= 128 - 16)
	{
		sha512Block(block, state);
		for (unsigned int i = 0; i < 14; i++)
		{
			block[i] = 0;
		}
	}
	unsigned long tmp;
	tmp = ((unsigned long) length) >> (64 - 3);
	block[14] = SWAP_ENDIAN_64(tmp);
	tmp = ((unsigned long) length) << 3;
	block[15] = SWAP_ENDIAN_64(tmp);
	
	sha512Block(block, state);
	if (outLength > 64)
	{
		outLength = 64;
	}
	for (i = 0, end = outLength / 8; i < end; i++)
	{
		((unsigned long*) out)[i] = SWAP_ENDIAN_64(state[i]);
	}
	for (i = outLength & ~7, shift = 56; i < outLength; i++, shift -= 8)
	{
		((unsigned char*) out)[i] = (unsigned long) (state[i / 8] >> shift);
	}
}

#define FINAL(OUT, OUTLENGTH) { \
	lengthHi = 0; \
	lengthLo = (unsigned long) m_messageLengthLo; \
\
	((unsigned char*) m_block)[lengthLo % 128] = 0x80; \
	for(i=0;i<128 - (lengthLo % 128 + 1);i++) \
		((unsigned char*) m_block)[lengthLo % 128 + 1+i]=0; \
\
	if (lengthLo % 128 >= 128 - 16) \
	{ \
		sha512Block(m_block, m_state); \
		for (unsigned int i = 0; i < 15; i++) \
		{ \
			m_block[i] = 0; \
		} \
	} \
	lengthHi  = (lengthHi << 3) + (lengthLo >> (64 - 3)); \
	lengthLo *= 8; \
	m_block[14] = SWAP_ENDIAN_64(lengthHi); \
	m_block[15] = SWAP_ENDIAN_64(lengthLo); \
	sha512Block(m_block, m_state);    \
	for (i = 0, end = (OUTLENGTH) / 8; i < end; i++) \
	{ \
		((unsigned long*) (OUT))[i] = SWAP_ENDIAN_64(m_state[i]); \
	} \
	for (i = (OUTLENGTH) & ~7, shift = 56; i < (OUTLENGTH); i++, shift -= 8) \
	{ \
		((unsigned char*) (OUT))[i] = (char) (m_state[i / 8] >> shift); \
	} \
} 


#define UPDATE(MSG, LENGTH) { \
	pos  = m_messageLengthLo & 127; \
	left = (LENGTH); \
	message=(unsigned char*) (MSG); \
	if (pos + left >= 128) \
	{ \
		for(k=0;k<128-pos;k++) 	\
			((unsigned char*) m_block)[pos+k]=message[k]; \
		sha512Block(m_block, m_state); \
		message = message + 128 - pos; \
		left=left+pos-128; \
		for(k=0;k<left;k++) \
			((unsigned char*) m_block)[k]=message[k]; \
	} \
	else	\
	{	\
		for(k=0;k<left;k++) \
			((unsigned char*)m_block)[pos+k]=message[k];\
	}	\
	m_messageLengthLo += (LENGTH); \
}


// BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH, HASH_LENGTH is passed with -D during build

struct parallel_salt {
	unsigned int cost;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

#define calcLoopCount(cost) (((cost)==0)?1:((unsigned long) (((cost) & 1) ^ 3)) << (((cost) - 1) >> 1)) 


__kernel void parallel_crypt_kernel(__global const uchar * in,
    __global const uint * index,
    __global unsigned char *out,
    __global struct parallel_salt *salt)
{
	
	unsigned int t_cost;
	unsigned int outlen;
	unsigned int saltlen;	

	unsigned long  key [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long  tmp [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long work [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long parallelLoops;
	unsigned long sequentialLoops;
	unsigned long i;
	unsigned long j;
	unsigned long tmpJ;
	unsigned int k;
	uint gid;
	unsigned int base, inlen;
	char salt_copy[SALT_SIZE];
	unsigned char in_copy[PLAINTEXT_LENGTH];

	unsigned int m_messageLengthLo;
	unsigned long m_state[8];
	unsigned long m_block[16];

	unsigned int pos;
	unsigned int left;
	unsigned char* message;
	unsigned long lengthHi;
	unsigned long lengthLo;
	unsigned int u;

	unsigned int end,shift;

	gid = get_global_id(0);
	out += gid * BINARY_SIZE;
	base = index[gid];
	inlen = index[gid + 1] - base;
	in += base;

	outlen=salt->hash_size;
	t_cost=salt->cost;
	saltlen=salt->salt_length;

	if ((t_cost & 0xffff) > 106 || (t_cost >> 16) > 126 || outlen > HASH_LENGTH || inlen >50)
	{
		for(i=0;i<outlen;i++)
			out[i]=0;
		return;
	}

	//copying salt from __global
	for(i=0;i<saltlen;i++)
		salt_copy[i]=salt->salt[i];

	//copying the key from __global
	for(i=0;i<inlen;i++)
		in_copy[i]=in[i];

	// key = hash(hash(salt) || in)

	hash(salt_copy, saltlen, key,HASH_LENGTH);
	INIT
	UPDATE(key, HASH_LENGTH);
	UPDATE(in_copy, inlen);
	FINAL(key,HASH_LENGTH);
	
	// Work
	parallelLoops = 3 * 5 * 128 * calcLoopCount(t_cost & 0xffff);
	sequentialLoops = calcLoopCount(t_cost >> 16);

	for (u = 0; u < sequentialLoops; u++)
	{
		// Clear work
		for (j=0; j<HASH_LENGTH / sizeof(unsigned long); j++)
		        work[j]=0;

		for (j = 0; j < parallelLoops; j++)
		{
			// work ^= hash(WRITE_BIG_ENDIAN_64(j) || key)
			tmpJ = SWAP_ENDIAN_64(j);

			INIT
			UPDATE(&tmpJ, sizeof(tmpJ));
			UPDATE(key, HASH_LENGTH);
			FINAL(tmp, HASH_LENGTH);
			for (k = 0; k < HASH_LENGTH / sizeof(unsigned long); k++)
			{
				work[k] ^= tmp[k];
			}
		}

		
		// Finish
		// key = truncate(hash(hash(work || key)), outlen) || zeros(HASH_LENGTH - outlen)

		INIT
		UPDATE(work, HASH_LENGTH);
		UPDATE(key, HASH_LENGTH);
		FINAL(key, HASH_LENGTH);
		hash(key, HASH_LENGTH, key,outlen);


		for(j=0;j<HASH_LENGTH - outlen;j++)
			((char *) key)[outlen+j]=0;
	}

	// Finish
	// out = key
	for(i=0;i<outlen;i++)
		out[i]=((unsigned char *) key)[i];
}
