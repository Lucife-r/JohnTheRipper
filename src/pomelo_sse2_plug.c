// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015. 
// This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on April,2015. 

// This code gives the C implementation of POMELO using the SSE2 instructions.  

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)    


#include "pomelo.h"

#ifdef SIMD_COEF_64

#include <stdlib.h>
#include <string.h>
#include <immintrin.h>


#define ADD128(x,y)       _mm_add_epi64((x), (y))
#define XOR128(x,y)       _mm_xor_si128((x),(y))	/*XOR(x,y) = x ^ y, where x and y are two 128-bit word */
#define OR128(x,y)        _mm_or_si128((x),(y))	/*OR(x,y)  = x | y, where x and y are two 128-bit word */
#define ROTL128(x,n)      XOR128(_mm_slli_epi64((x), (n)),  _mm_srli_epi64((x),(64-n)))	/*Rotate 2 64-bit unsigned integers in x to the left by n-bit positions */
#define SHIFTL128(x,n)    _mm_slli_epi64((x), (n))
#define SHIFTL64(x)       _mm_slli_si128(x, 8)
#define SHIFTR64(x)       _mm_srli_si128(x, 8)

// Function F0 update the state using a nonlinear feedback shift register  
#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0]   = XOR128(ADD128(XOR128(S[i1],   S[i2]),   S[i3]),   S[i4]);    \
    S[i0+1] = XOR128(ADD128(XOR128(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]);  \
    S[i0+2]   = XOR128(ADD128(XOR128(S[i1+2],   S[i2+2]),   S[i3+2]),   S[i4+2]);    \
    S[i0+3] = XOR128(ADD128(XOR128(S[i1+3], S[i2+3]), S[i3+3]), S[i4+3]);  \
    temp = S[i0];                  \
    temp2 = S[i0+2];                  \
    S[i0]   = XOR128(SHIFTL64(S[i0]),   SHIFTR64(S[i0+1]));  \
    S[i0+2]   = XOR128(SHIFTL64(S[i0+2]),   SHIFTR64(S[i0+3]));  \
    S[i0+1] = XOR128(SHIFTL64(S[i0+1]), SHIFTR64(temp));   \
    S[i0+3] = XOR128(SHIFTL64(S[i0+3]), SHIFTR64(temp2));   \
    S[i0]   = ROTL128(S[i0],  17);  \
    S[i0+1] = ROTL128(S[i0+1],  17);  \
    S[i0+2] = ROTL128(S[i0+2],17);  \
    S[i0+3] = ROTL128(S[i0+3],17);  \
}

// Function F update the state using a nonlinear feedback shift register 
#define F(i)  {              \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0]   = ADD128(S[i0],XOR128(ADD128(XOR128(S[i1],   S[i2]),   S[i3]),   S[i4]));    \
    S[i0+1] = ADD128(S[i0+1],XOR128(ADD128(XOR128(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]));  \
    S[i0+2] = ADD128(S[i0+2],XOR128(ADD128(XOR128(S[i1+2], S[i2+2]), S[i3+2]), S[i4+2]));    \
    S[i0+3] = ADD128(S[i0+3],XOR128(ADD128(XOR128(S[i1+3], S[i2+3]), S[i3+3]), S[i4+3]));  \
    temp = S[i0];                  \
    temp2 = S[i0+2];                  \
    S[i0]   = XOR128(SHIFTL64(S[i0]),   SHIFTR64(S[i0+1]));  \
    S[i0+2] = XOR128(SHIFTL64(S[i0+2]), SHIFTR64(S[i0+3]));  \
    S[i0+1] = XOR128(SHIFTL64(S[i0+1]), SHIFTR64(temp));   \
    S[i0+3] = XOR128(SHIFTL64(S[i0+3]), SHIFTR64(temp2));   \
    S[i0]   = ROTL128(S[i0],  17);  \
    S[i0+1] = ROTL128(S[i0+1],17);  \
    S[i0+2] = ROTL128(S[i0+2],17);  \
    S[i0+3] = ROTL128(S[i0+3],17);  \
}

#define G(i,random_number)  {                                                          \
    index_global = ((random_number >> 16) & mask) << 2;                                \
    for (j = 0; j < 128; j = j+4)                                                        \
    {                                                                                  \
        F(i+j);                                                                        \
        index_global     = (index_global + 4) & mask1;                                 \
        index_local      = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;\
        index_local      = index_local << 2;                                           \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_local],1));                \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_local+1],1));              \
	S[i0+2]          = ADD128(S[i0+2],SHIFTL128(S[index_local+2],1));              \
	S[i0+3]          = ADD128(S[i0+3],SHIFTL128(S[index_local+3],1));              \
        S[index_local]   = ADD128(S[index_local],   SHIFTL128(S[i0],2));               \
        S[index_local+1] = ADD128(S[index_local+1], SHIFTL128(S[i0+1],2));             \
	S[index_local+2] = ADD128(S[index_local+2], SHIFTL128(S[i0+2],2));             \
	S[index_local+3] = ADD128(S[index_local+3], SHIFTL128(S[i0+3],2));             \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_global],1));               \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_global+1],1));             \
	S[i0+2]          = ADD128(S[i0+2],SHIFTL128(S[index_global+2],1));             \
	S[i0+3]          = ADD128(S[i0+3],SHIFTL128(S[index_global+3],1));             \
        S[index_global]  = ADD128(S[index_global],  SHIFTL128(S[i0],3));               \
        S[index_global+1]= ADD128(S[index_global+1],SHIFTL128(S[i0+1],3));             \
	S[index_global+2]= ADD128(S[index_global+2],SHIFTL128(S[i0+2],3));             \
	S[index_global+3]= ADD128(S[index_global+3],SHIFTL128(S[i0+3],3));             \
        random_number   += (random_number << 2);                                       \
        random_number    = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                                  \
}

#define H(i, random_number,random_number2)  {                                                         \
    index_global = ((random_number >> 16) & mask) << 2;                                \
    index_global2 = ((random_number2 >> 16) & mask) << 2;                                \
    for (j = 0; j < 128; j = j+4)                                                       \
    {                                                                                  \
        F(i+j);                                                                        \
        index_global     = (index_global + 4) & mask1;                                 \
	index_global2     = (index_global2 + 4) & mask1;                                 \
        index_local      = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;\
	index_local2      = (((i + j) >> 2) - 0x1000 + (random_number2 & 0x1fff)) & mask;\
	index_global_t=index_global;						  \
	index_global2_t=index_global2+2;						\
        index_local      = index_local << 2;                                           \
	index_local2      = (index_local2 << 2) +2;                                         \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_local],1));                \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_local+1],1));              \
	S[i0+2]          = ADD128(S[i0+2],SHIFTL128(S[index_local2],1));              \
	S[i0+3]          = ADD128(S[i0+3],SHIFTL128(S[index_local2+1],1));              \
        S[index_local]   = ADD128(S[index_local],   SHIFTL128(S[i0],2));               \
        S[index_local+1] = ADD128(S[index_local+1], SHIFTL128(S[i0+1],2));             \
	S[index_local2]   = ADD128(S[index_local2],   SHIFTL128(S[i0+2],2));               \
        S[index_local2+1] = ADD128(S[index_local2+1], SHIFTL128(S[i0+3],2));             \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_global_t],1));               \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_global_t+1],1));             \
	S[i0+2]          = ADD128(S[i0+2],SHIFTL128(S[index_global2_t],1));               \
        S[i0+3]          = ADD128(S[i0+3],SHIFTL128(S[index_global2_t+1],1));             \
        S[index_global_t]  = ADD128(S[index_global_t],  SHIFTL128(S[i0],3));               \
        S[index_global_t+1]= ADD128(S[index_global_t+1],SHIFTL128(S[i0+1],3));             \
	S[index_global2_t]  = ADD128(S[index_global2_t],  SHIFTL128(S[i0+2],3));               \
        S[index_global2_t+1]= ADD128(S[index_global2_t+1],SHIFTL128(S[i0+3],3));             \
        random_number  = ((uint64_t*)S)[i3<<1];                                                        \
	random_number2  =((uint64_t*)S)[(i3+2)<<1];                                                        \
    }                                                                                     \
}

#define INTERLEAVING_LEVEL 2

#define sMAP(X) ((X)*INTERLEAVING_LEVEL)
#define MAP(X,I) (((X)/4*INTERLEAVING_LEVEL+(I))*4+(X)%4)
#define MAPCH(X,I) (MAP((X)/8,I)*8 +(X)%8)

int POMELO_SSE2(void *out, size_t outlen, const void *in, size_t *inlen,
    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t i, j;
	__m128i temp,temp2;
	uint64_t i0, i1, i2, i3, i4;
	__m128i *S;
	uint64_t random_number, random_number2, index_global, index_global2, index_local, index_local2, index_global_t,index_global2_t;
	uint64_t state_size, mask, mask1;

	//check the size of password, salt and output. Password is at most 256 bytes; the salt is at most 64 bytes. 
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
	S = (__m128i *) malloc(state_size*INTERLEAVING_LEVEL);
	mask = (1ULL << (8 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1ULL << (10 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/4;

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
	for (i = 13 * 4; i < (1ULL << (10 + m_cost)); i = i + 4)
		F0(i);
	
	//Step 4: Update the state using function G  
	random_number = 123456789ULL;
	for (i = 0; i < (1ULL << (9 + m_cost + t_cost)); i = i + 128)
		G(i, random_number);

	random_number2=random_number;
	//Step 5: Update the state using function H     
	for (i = 1ULL << (9 + m_cost + t_cost);
	    i < (1ULL << (10 + m_cost + t_cost)); i = i + 128)
		H(i, random_number,random_number2);

	//Step 6: Update the state using function F 
	for (i = 0; i < (1ULL << (10 + m_cost)); i = i + 4)
		F(i);

	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	for(j=0;j<INTERLEAVING_LEVEL;j++)
	for(i=0;i<outlen;i++)
		((char *)out)[i+j*BINARY_SIZE]=((unsigned char *)S) [MAPCH(state_size - outlen+i,j)];

	free(S);		// free the memory

	return 0;
}

#endif
