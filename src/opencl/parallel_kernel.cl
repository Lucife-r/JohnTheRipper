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

// BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH, HASH_LENGTH, AMD_GCN is passed with -D during build
#include "opencl_device_info.h"

#if !gpu_nvidia(DEVICE_INFO) || nvidia_sm_5x(DEVICE_INFO)
#define USE_BITSELECT
#elif gpu_nvidia(DEVICE_INFO)
#define OLD_NVIDIA
#endif

#include "opencl_sha512.h"

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

#if AMD_GCN==1
inline void sha512Block(__private unsigned long block[16], unsigned long state[8])
{
	unsigned long w[16];
	unsigned long a = state[0];
	unsigned long b = state[1];
	unsigned long c = state[2];
	unsigned long d = state[3];
	unsigned long e = state[4];
	unsigned long f = state[5];
	unsigned long g = state[6];
	unsigned long h = state[7];
	unsigned long t1,t2;
	

#ifdef VECTOR_USAGE
	ulong16  w_vector;
	w_vector = vload16(0, block);
	w_vector = SWAP64_V(w_vector);
	vstore16(w_vector, 0, w);
#else
	#pragma unroll
	for (int i = 0; i < 16; i++)
		w[i] = SWAP_ENDIAN_64(block[i]);
#endif

	for (int i = 0; i < 16; i++) {
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	#pragma unroll 8
	for (int i = 16; i < 80; i++) {
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
 
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

#else
inline void sha512Block(__private unsigned long block[16], unsigned long state[8])
{
	unsigned long w[16];
	unsigned long a = state[0];
	unsigned long b = state[1];
	unsigned long c = state[2];
	unsigned long d = state[3];
	unsigned long e = state[4];
	unsigned long f = state[5];
	unsigned long g = state[6];
	unsigned long h = state[7];
	unsigned long t;

#ifdef VECTOR_USAGE
	ulong16  w_vector;
	w_vector = vload16(0, block);
	w_vector = SWAP64_V(w_vector);
	vstore16(w_vector, 0, w);
#else
	#pragma unroll
	for (int i = 0; i < 16; i++)
		w[i] = SWAP_ENDIAN_64(block[i]);
#endif

	for (int i = 0; i < 16; i++) 
	{
		t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

		h = g;
		g = f;
		f = e;
		e = d + t;
		t = t + Maj(a, b, c) + Sigma0(a);
		d = c;
		c = b;
		b = a;
		a = t;
	}

#ifdef AMD_STUPID_BUG_1
    #pragma unroll 4
#endif
    	for (int i = 16; i < 80; i++) 
	{
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

		h = g;
		g = f;
		f = e;
		e = d + t;
		t = t + Maj(a, b, c) + Sigma0(a);
		d = c;
		c = b;
		b = a;
		a = t;
    	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
#endif

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
