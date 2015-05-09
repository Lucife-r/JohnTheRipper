// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015.  

// This code give the C implementation of POMELO using the AVX2 implementation. 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)    

#include "pomelo.h"

#ifdef __AVX2__

#include <stdlib.h>
#include <string.h>
#include <immintrin.h>

#define XOR256(x,y)       _mm256_xor_si256((x),(y))	/*XOR256(x,y) = x ^ y, where x and y are two 256-bit word */
#define ADD256(x,y)       _mm256_add_epi64((x), (y))
#define OR256(x,y)        _mm256_or_si256((x),(y))	/*OR(x,y)  = x | y, where x and y are two 256-bit word */
#define SHIFTL256(x,n)    _mm256_slli_epi64((x), (n))
#define ROTL256(x,n)      OR256( _mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x),(64-n)) )	/*Rotate 4 64-bit unsigned integers in x to the left by n-bit positions */
#define ROTL256_64(x)     _mm256_permute4x64_epi64((x), _MM_SHUFFLE(2,1,0,3))	/*Rotate x by 64-bit  positions to the left */
#define ROTL256_128(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(1,0,3,2))	/*Rotate x by 128-bit positions to the left */
#define ROTL256_192(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(0,3,2,1))	/*Rotate x by 192-bit positions to the left */

// Function F0 update the state using a nonlinear feedback shift register in the expansion (step 3)   
#define F0(i)  {            \
    i0 = ((i) - 0)  & mask; \
    i1 = ((i) - 4)  & mask; \
    i2 = ((i) - 6)  & mask; \
    i3 = ((i) - 14)  & mask; \
    i4 = ((i) - 26) & mask; \
    S[i0] = XOR256(ADD256(XOR256(S[i1], S[i2]), S[i3]), S[i4]);  \
    S[i0+1] = XOR256(ADD256(XOR256(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]);  \
    S[i0] = ROTL256_64(S[i0]);  \
    S[i0+1] = ROTL256_64(S[i0+1]);  \
    S[i0] = ROTL256(S[i0],17);  \
    S[i0+1] = ROTL256(S[i0+1],17);  \
}

// Function F update the state using a nonlinear feedback shift register
#define F(i)  {             \
    i0 = ((i) - 0)  & mask; \
    i1 = ((i) - 4)  & mask; \
    i2 = ((i) - 6)  & mask; \
    i3 = ((i) - 14)  & mask; \
    i4 = ((i) - 26) & mask; \
    S[i0] = ADD256(S[i0], XOR256(ADD256(XOR256(S[i1], S[i2]), S[i3]), S[i4]));      \
    S[i0+1] = ADD256(S[i0+1], XOR256(ADD256(XOR256(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]));      \
    S[i0] = ROTL256_64(S[i0]);  \
    S[i0+1] = ROTL256_64(S[i0+1]);  \
    S[i0] = ROTL256(S[i0],17); \
    S[i0+1] = ROTL256(S[i0+1],17); \
}

// Function G update the state using function F together with Key-INdependent random memory accesses  
#define G(i)  {                                                       \
    index_global = ((random_number >> 16)<<1) & mask;                                    \
    for (j = 0; j < 64; j+=2)                                                        \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 2) & mask;                                 \
        index_local    = ((((i + j)>>1) - 0x1000 + (random_number & 0x1fff))<<1 )& mask;        \
        S[i0]            = ADD256(S[i0],  SHIFTL256(S[index_local],  1));           \
	S[i0+1]          = ADD256(S[i0+1],SHIFTL256(S[index_local+1],1));           \
        S[index_local]   = ADD256(S[index_local],    SHIFTL256(S[i0],  2));      \
	S[index_local+1] = ADD256(S[index_local+1],  SHIFTL256(S[i0+1],2));      \
        S[i0]          	 = ADD256(S[i0],  SHIFTL256(S[index_global],  1));          \
	S[i0+1]          = ADD256(S[i0+1],SHIFTL256(S[index_global+1],1));          \
        S[index_global  ]= ADD256(S[index_global],   SHIFTL256(S[i0],3));        \
	S[index_global+1]= ADD256(S[index_global+1], SHIFTL256(S[i0+1],3));      \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

// Function H update the state using function F together with Key-dependent random memory accesses  
#define H(i)  {                                                      \
    index_global  = ((random_number  >> 16)<<1) & mask;                                  \
    index_global2 = ((random_number2 >> 16)<<1) & mask;                                  \
    for (j = 0; j < 64; j+=2)                                                        \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global  + 2) & mask;                            \
	index_global2  = (index_global2 + 2) & mask;                            \
        index_local    = (((((i + j)>>1) - 0x1000 + (random_number  & 0x1fff))<<1 )& mask);     \
	index_local2   = (((((i + j)>>1) - 0x1000 + (random_number2 & 0x1fff))<<1 )& mask) +1;  \
        S[i0]          = ADD256(S[i0],  SHIFTL256(S[index_local ],1));                 \
	S[i0+1]        = ADD256(S[i0+1],SHIFTL256(S[index_local2],1));              \
        S[index_local]   = ADD256(S[index_local],  SHIFTL256(S[i0],   2));           \
	S[index_local2]  = ADD256(S[index_local2],  SHIFTL256(S[i0+1],2));           \
        S[i0]            = ADD256(S[i0],  SHIFTL256(S[index_global   ] ,1));           \
	S[i0+1]          = ADD256(S[i0+1],SHIFTL256(S[index_global2+1],1));           \
        S[index_global   ] = ADD256(S[index_global   ], SHIFTL256(S[i0],  3));           \
	S[index_global2+1] = ADD256(S[index_global2+1], SHIFTL256(S[i0+1],3));           \
        random_number    = ((uint64_t*)S)[(i3     << 2)];                       	    \
	random_number2   = ((uint64_t*)S)[((i3+1) << 2)];                       	    \
    }                                                                               \
}


#define INTERLEAVING_LEVEL 2

#define sMAP(X) ((X)*INTERLEAVING_LEVEL)
#define MAP(X,I) (((X)/4*INTERLEAVING_LEVEL+(I))*4+(X)%4)
#define MAPCH(X,I) (MAP((X)/8,I)*8 +(X)%8)

static void *aligned_malloc(size_t required_bytes, size_t alignment)
{
	void *p1;		// original block
	void **p2;		// aligned block
	int offset = alignment - 1 + sizeof(void *);
	if ((p1 = (void *)malloc(required_bytes + offset)) == NULL) {
		return NULL;
	}
	p2 = (void **)(((size_t) (p1) + offset) & ~(alignment - 1));
	p2[-1] = p1;
	return p2;
}

static void aligned_free(void *p)
{
	free(((void **)p)[-1]);
}



int POMELO_AVX2(void *out, size_t outlen, const void *in, size_t *inlen,
    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t i, j;
	uint64_t i0, i1, i2, i3, i4;
	__m256i *S;
	uint64_t random_number, random_number2, index_global, index_global2, index_local, index_local2;
	uint64_t state_size, mask;

	//check the size of password, salt, and output. Password at most 256 bytes; salt at most 64 bytes; output at most 256 bytes.  
	if ( saltlen > 64 || outlen > 256 || 
	    saltlen < 0 || outlen < 0)
		return 1;
	
	for(i=0;i<INTERLEAVING_LEVEL;i++)
	{
	
	if(inlen[i] > 256 || inlen[i]<0)
		return 1;
	}

	//Step 1: Initialize the state S          
	state_size = 1ULL << (13 + m_cost);	// state size is 2**(13+m_cost) bytes 
	S = (__m256i *) aligned_malloc(state_size*INTERLEAVING_LEVEL, 4096);	// aligned malloc is needed; otherwise it is only aligned to 16 bytes when using GCC.        
	mask = (1ULL << (9 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/32

	//Step 2: Load the password, salt, input/output sizes into the state S
	for (j = 0;j<INTERLEAVING_LEVEL;j++)
	{
		for (i = 0; i < inlen[j]; i++)
			((unsigned char *)S)[MAPCH(i,j)] = ((unsigned char *)in)[i+j*(PLAINTEXT_LENGTH+1)];	// load password into S

		for (i = 0; i < saltlen; i++)
			((unsigned char *)S)[MAPCH(inlen[j] + i,j)] = ((unsigned char *)salt)[i];	// load salt into S

		for (i = inlen[j] + saltlen; i < 384; i++)
			((unsigned char *)S)[MAPCH(i,j)] = 0;
		((unsigned char *)S)[MAPCH(384,j)] = inlen[j] & 0xff;	// load password length (in bytes) into S;
		((unsigned char *)S)[MAPCH(385,j)] = (inlen[j] >> 8) & 0xff;	// load password length (in bytes) into S;
		((unsigned char *)S)[MAPCH(386,j)] = saltlen;	// load salt length (in bytes) into S;
		((unsigned char *)S)[MAPCH(387,j)] = outlen & 0xff;	// load output length (in bytes into S)
		((unsigned char *)S)[MAPCH(388,j)] = (outlen >> 8) & 0xff;	// load output length (in bytes into S)
		((unsigned char *)S)[MAPCH(389,j)] = 0;
		((unsigned char *)S)[MAPCH(390,j)] = 0;
		((unsigned char *)S)[MAPCH(391,j)] = 0;

		((unsigned char *)S)[MAPCH(392,j)] = 1;
		((unsigned char *)S)[MAPCH(393,j)] = 1;
		for (i = 394; i < 416; i++)
			((unsigned char *)S)[MAPCH(i,j)] =
		    	((unsigned char *)S)[MAPCH(i - 1,j)] + ((unsigned char *)S)[MAPCH(i - 2,j)];

	}


	//Step 3: Expand the data into the whole state
	for (i = 13*2; i < (1ULL << (9 + m_cost)); i = i + 2 )
		F0(i);


	//Step 4: Update the state using function G
	random_number = 123456789ULL;
	for (i = 0; i < (1ULL << (8 + m_cost + t_cost)); i = i + 64)
		G(i);


	//Step 5: Update the state using function H
	random_number2=random_number;
	for (i = 1ULL << (8 + m_cost + t_cost);
	    i < (1ULL << (9 + m_cost + t_cost)); i = i + 64)
		H(i);


	//Step 6: Update the state using function F
	for (i = 0; i < (1ULL << (9 + m_cost)); i = i + 2)
		F(i);


	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	for(j=0;j<INTERLEAVING_LEVEL;j++)
	for(i=0;i<outlen;i++)
		((char *)out)[i+j*BINARY_SIZE]=((unsigned char *)S) [MAPCH(state_size - outlen+i,j)];
	
	aligned_free(S);	// free the memory

	return 0;
}

#endif
