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

#define STEP {	\
	h = g;	\
	g = f;	\
	f = e;	\
	e = d + t;	\
	t = t + Maj(a, b, c) + Sigma0(a);	\
	d = c;	\
	c = b;	\
	b = a;	\
	a = t;	\
}

#if gpu_nvidia(DEVICE_INFO)
#define ror64(x, n)       ((x >> n) | (x << (64 - n)))
#else
#define ror64(x, n)       rotate(x, (ulong)(64 - n))
#endif

#define Sigma0_64(x) ((ror64(x,28))  ^ (ror64(x,34)) ^ (ror64(x,39)))
#define Sigma1_64(x) ((ror64(x,14))  ^ (ror64(x,18)) ^ (ror64(x,41)))
#define sigma0_64(x) ((ror64(x,1))  ^ (ror64(x,8)) ^ (x >> 7))
#define sigma1_64(x) ((ror64(x,19)) ^ (ror64(x,61)) ^ (x >> 6))

#define INIT_A	0x6a09e667f3bcc908UL
#define INIT_B	0xbb67ae8584caa73bUL
#define INIT_C	0x3c6ef372fe94f82bUL
#define INIT_D	0xa54ff53a5f1d36f1UL
#define INIT_E	0x510e527fade682d1UL
#define INIT_F	0x9b05688c2b3e6c1fUL
#define INIT_G	0x1f83d9abfb41bd6bUL
#define INIT_H	0x5be0cd19137e2179UL

#define ROUND512_A(a, b, c, d, e, f, g, h, ki, wi)	\
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_Z(a, b, c, d, e, f, g, h, ki)	\
	t = (ki) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_B(a, b, c, d, e, f, g, h, ki, wi, wj, wk, wl, wm)	  \
	wi = sigma1_64(wj) + sigma0_64(wk) + wl + wm; \
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));


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
	#pragma unroll 1
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
		STEP;
	}

#ifdef AMD_STUPID_BUG_1
    #pragma unroll 4
#endif
    	for (int i = 16; i < 80; i++) 
	{
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		STEP;
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

#if AMD_GCN==1
inline void sha512Block_Z(__private unsigned long block[16], unsigned long state[8])
{
	unsigned long w[16];
	unsigned long a = INIT_A;
	unsigned long b = INIT_B;
	unsigned long c = INIT_C;
	unsigned long d = INIT_D;
	unsigned long e = INIT_E;
	unsigned long f = INIT_F;
	unsigned long g = INIT_G;
	unsigned long h = INIT_H;
	unsigned long t1,t2;
	
	#pragma unroll 1
	for (int i = 0; i < 10; i++)
		w[i] = SWAP_ENDIAN_64(block[i]);

	w[10]=w[11]=w[12]=w[13]=w[14]=0;
	w[15] = block[15];

	#pragma unroll 1
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

/*
	for (int i = 0; i < 10; i++) {
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

	for (int i = 10; i < 15; i++) {
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

	t1 = k[15] + w[15] + h + Sigma1(e) + Ch(e, f, g);
	t2 = Maj(a, b, c) + Sigma0(a);

	h = g;
	g = f;
	f = e;
	e = d + t1;
	d = c;
	c = b;
	b = a;
	a = t1 + t2;*/

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
 
	state[0] = INIT_A + a;
	state[1] = INIT_B + b;
	state[2] = INIT_C + c;
	state[3] = INIT_D + d;
	state[4] = INIT_E + e;
	state[5] = INIT_F + f;
	state[6] = INIT_G + g;
	state[7] = INIT_H + h;
}

#else
inline void sha512Block_Z(__private unsigned long block[16], unsigned long state[8])
{
	unsigned long w[16];
	unsigned long a = INIT_A;
	unsigned long b = INIT_B;
	unsigned long c = INIT_C;
	unsigned long d = INIT_D;
	unsigned long e = INIT_E;
	unsigned long f = INIT_F;
	unsigned long g = INIT_G;
	unsigned long h = INIT_H;
	unsigned long t;

	#pragma unroll
	for (int i = 0; i < 10; i++)
		w[i] = SWAP_ENDIAN_64(block[i]);

	w[15] = block[15];


	for (int i = 0; i < 10; i++) 
	{
		t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		STEP;
	}

	for (int i = 10; i < 15; i++) 
	{
		t = k[i] + h + Sigma1(e) + Ch(e, f, g);
		STEP;
	}

	t = k[15] + w[15] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	
	w[0] = sigma0(w[1]) + w[0] + w[9];
	t = k[16] + w[0] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[1] = sigma1(w[15]) + sigma0(w[2]) + w[1];
	t = k[17] + w[1] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[2] = sigma1(w[0]) + sigma0(w[3]) + w[2];
	t = k[18] + w[2] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[3] = sigma1(w[1]) + sigma0(w[4]) + w[3];
	t = k[19] + w[3] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[4] = sigma1(w[2]) + sigma0(w[5]) + w[4];
	t = k[20] + w[4] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[5] = sigma1(w[3]) + sigma0(w[6]) + w[5];
	t = k[21] + w[5] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[6] = sigma1(w[4]) + sigma0(w[7]) + w[6] + w[15];
	t = k[22] + w[6] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[7] = sigma1(w[5]) + sigma0(w[8]) + w[7] + w[0];
	t = k[23] + w[7] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[8] = sigma1(w[6]) + sigma0(w[9]) + w[8] + w[1];
	t = k[24] + w[8] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[9] = sigma1(w[7])  + w[9] + w[2];
	t = k[25] + w[9] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[10] = sigma1(w[8]) + w[3];
	t = k[26] + w[10] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[11] = sigma1(w[9])  + w[4];
	t = k[27] + w[11] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[12] = sigma1(w[10])  + w[5];
	t = k[28] + w[12] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[13] = sigma1(w[11]) + w[6];
	t = k[29] + w[13] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[14] = sigma1(w[12]) + sigma0(w[15]) + w[7];
	t = k[30] + w[14] + h + Sigma1(e) + Ch(e, f, g);
	STEP;
	w[15] = sigma1(w[13]) + sigma0(w[0]) + w[15] + w[8];
	t = k[31] + w[15] + h + Sigma1(e) + Ch(e, f, g);
	STEP;

#ifdef AMD_STUPID_BUG_1
    #pragma unroll 4
#endif
    	for (int i = 32; i < 80; i++) 
	{
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		STEP;
    	}

	state[0] = INIT_A + a;
	state[1] = INIT_B + b;
	state[2] = INIT_C + c;
	state[3] = INIT_D + d;
	state[4] = INIT_E + e;
	state[5] = INIT_F + f;
	state[6] = INIT_G + g;
	state[7] = INIT_H + h;
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
	
	for(i=0;i<left;i++)
		((unsigned char*)block)[i]=((unsigned char*)message)[i];
	((unsigned char*) block)[left] = 0x80;
	for(i=0;i<128 - (left + 1);i++)
		((unsigned char*) block)[left + 1+i]=0;

	unsigned long tmp;
	tmp = ((unsigned long) length) >> (64 - 3);
	block[14] = SWAP_ENDIAN_64(tmp);
	tmp = ((unsigned long) length) << 3;
	block[15] = SWAP_ENDIAN_64(tmp);
	
	sha512Block(block, state);
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
	lengthLo *= 8; \
	m_block[14]=0; \
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

//to do: remove
#define FINAL_Z(OUT, OUTLENGTH) { \
	lengthLo = (unsigned long) m_messageLengthLo; \
\
	((unsigned char*) m_block)[lengthLo % 128] = 0x80; \
	for(i=0;i<128 - (lengthLo % 128 + 1);i++) \
		((unsigned char*) m_block)[lengthLo % 128 + 1+i]=0; \
\
	lengthLo *= 8; \
	m_block[15] = lengthLo; \
	sha512Block_Z(m_block, m_state);    \
	for (i = 0, end = (OUTLENGTH) / 8; i < end; i++) \
	{ \
		((unsigned long*) (OUT))[i] = SWAP_ENDIAN_64(m_state[i]); \
	} \
	for (i = (OUTLENGTH) & ~7, shift = 56; i < (OUTLENGTH); i++, shift -= 8) \
	{ \
		((unsigned char*) (OUT))[i] = (char) (m_state[i / 8] >> shift); \
	} \
} 


#define UPDATE1(MSG, LENGTH) { \
	pos  = m_messageLengthLo; \
	left = (LENGTH); \
	message=(unsigned char*) (MSG); \
	for(k=0;k<left;k++) \
		((unsigned char*)m_block)[pos+k]=message[k];\
	m_messageLengthLo += (LENGTH); \
}

#define UPDATE2(MSG, LENGTH) { \
	pos  = m_messageLengthLo; \
	left = (LENGTH); \
	message=(unsigned char*) (MSG); \
	for(k=0;k<64;k++) 	\
		((unsigned char*) m_block)[pos+k]=message[k]; \
	sha512Block(m_block, m_state); \
	message = message + 64; \
	m_messageLengthLo += (LENGTH); \
}

#define SIMPLE(tmpJ,key) { \
	for(k=0;k<8;k++) \
		((unsigned char*)m_block)[k]=((unsigned char*) (tmpJ))[k];\
\
	for(k=0;k<(HASH_LENGTH);k++) \
		((unsigned char*)m_block)[8+k]=((unsigned char*) (key))[k];\
\
	((unsigned char*) m_block)[72] = 0x80; \
	for(i=0;i<55;i++) \
		((unsigned char*) m_block)[73+i]=0; \
\
	m_block[15] = 576; \
	sha512Block_Z(m_block, m_state);    \
}
//to do: why change 55 to 10, makes slower speed from 32k to 24 k?

struct parallel_salt {
	unsigned int s_loops;
	unsigned int p_loops;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

#define calcLoopCount(cost) (((cost)==0)?1:((unsigned long) (((cost) & 1) ^ 3)) << (((cost) - 1) >> 1)) 


__kernel void parallel_kernel_init(
    __global const uchar * in,
    __global const uint * index,
    __global unsigned char *out,
    __global struct parallel_salt *salt)
{
	
	unsigned int outlen;
	unsigned int saltlen;	

	unsigned long  key [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long i;
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
	unsigned long lengthLo;

	unsigned int end,shift;

	gid = get_global_id(0);
	out += gid * BINARY_SIZE;
	base = index[gid];
	inlen = index[gid + 1] - base;
	in += base;

	outlen=salt->hash_size;
	saltlen=salt->salt_length;

	if ((salt->p_loops) > 106 || (salt->s_loops) > 126 || outlen > HASH_LENGTH || inlen >50)
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
	UPDATE1(key, HASH_LENGTH);
	UPDATE1(in_copy, inlen);
	FINAL(key,HASH_LENGTH);
	

	// Finish
	// out = key
	for(i=0;i<HASH_LENGTH;i++)
		out[i]=((unsigned char *) key)[i];
}

__kernel void parallel_kernel_loop(__global const uchar * in,
    __global const uint * index,
    __global unsigned char *out,
    __global struct parallel_salt *salt,
    __global unsigned char *job)
{
	
	unsigned int outlen;
	unsigned int saltlen;	

	unsigned long  key [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long work [HASH_LENGTH / sizeof(unsigned long)];
	//unsigned long w[16];
	unsigned long parallelLoops;
	unsigned long i;
	unsigned long j;
	unsigned long tmpJ;
	unsigned int k;
	uint gid;

	unsigned int m_messageLengthLo;
	unsigned long m_state[8];
	unsigned long m_block[16];

	unsigned char* message;

	gid = get_global_id(0);
	out += gid * BINARY_SIZE;
	job += gid * BINARY_SIZE;

	outlen=salt->hash_size;
	saltlen=salt->salt_length;

	//copying saved previously work
	for(i=0;i<HASH_LENGTH;i++)
		((unsigned char *)key)[i]=((__global unsigned char *) out)[i];
	
	// Work
	parallelLoops = 3 * 5 * 128 * calcLoopCount((salt->p_loops));

	// Clear work
	for (j=0; j<HASH_LENGTH / sizeof(unsigned long); j++)
		work[j]=0;

	for (j = 0; j < parallelLoops; j++)
	{
		// work ^= hash(WRITE_BIG_ENDIAN_64(j) || key)
		tmpJ = SWAP_ENDIAN_64(j);

		SIMPLE(&tmpJ, key);
		for (k = 0; k < HASH_LENGTH / sizeof(unsigned long); k++)
		{
			work[k] ^= SWAP_ENDIAN_64(m_state[k]);//to do: test on another GPUs
		}
	}
		
	// Finish
	// out = key
	#pragma unroll 1
	for(i=0;i<HASH_LENGTH;i++)
		out[i]=((unsigned char *) work)[i];
	#pragma unroll 1
	for(i=0;i<HASH_LENGTH;i++)
		job[i]=((unsigned char *) key)[i];
}

__kernel void parallel_kernel_finish_loop(
    __global const uchar * in,
    __global const uint * index,
    __global unsigned char *out,
    __global struct parallel_salt *salt,
    __global unsigned char *job)
{
	
	unsigned int outlen;
	unsigned int saltlen;	

	unsigned long  key [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long work [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long parallelLoops;
	unsigned long i;
	unsigned int k;
	uint gid;

	unsigned int m_messageLengthLo;
	unsigned long m_state[8];
	unsigned long m_block[16];

	unsigned int pos;
	unsigned int left;
	unsigned char* message;
	unsigned long lengthLo;

	unsigned int end,shift;

	gid = get_global_id(0);
	out += gid * BINARY_SIZE;
	job += gid * BINARY_SIZE;

	outlen=salt->hash_size;
	saltlen=salt->salt_length;

	//copying saved previously work
	for(i=0;i<HASH_LENGTH;i++)
		((unsigned char*)work)[i]=((__global unsigned char *) out)[i];
	for(i=0;i<HASH_LENGTH;i++)
		((unsigned char*)key )[i]=((__global unsigned char *) job)[i];

	INIT
	UPDATE1(work, HASH_LENGTH);
	UPDATE2(key, HASH_LENGTH);
	FINAL(key, HASH_LENGTH);
	hash(key, HASH_LENGTH, key,outlen);


	for(i=0;i<HASH_LENGTH - outlen;i++)//to do
		((char *) key)[outlen+i]=0;

	//saving current work
	for(i=0;i<HASH_LENGTH;i++)
		out[i]=((unsigned char *) key)[i];

}

__kernel void parallel_kernel_finish(__global const uchar * in,
    __global const uint * index,
    __global unsigned char *out,
    __global struct parallel_salt *salt,
    __global unsigned char *job)
{
	
	unsigned int outlen;
	unsigned int saltlen;	

	unsigned long  key [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long work [HASH_LENGTH / sizeof(unsigned long)];
	unsigned long i;
	unsigned int k;
	uint gid;

	unsigned int m_messageLengthLo;
	unsigned long m_state[8];
	unsigned long m_block[16];

	unsigned int pos;
	unsigned int left;
	unsigned char* message;
	unsigned long lengthLo;

	unsigned int end,shift;

	gid = get_global_id(0);
	out += gid * BINARY_SIZE;
	job += gid * BINARY_SIZE;

	outlen=salt->hash_size;
	saltlen=salt->salt_length;

	//copying previously saved work
	for(i=0;i<HASH_LENGTH;i++)
		((unsigned char*)work)[i]=((__global unsigned char *) out)[i];
	for(i=0;i<HASH_LENGTH;i++)
		((unsigned char*)key )[i]=((__global unsigned char *) job)[i];

	INIT
	UPDATE1(work, HASH_LENGTH);
	UPDATE2(key, HASH_LENGTH);
	FINAL(key, HASH_LENGTH);
	hash(key, HASH_LENGTH, key,outlen);

	// Finish
	for(i=0;i<outlen;i++)
		out[i]=((unsigned char *) key)[i];
}

