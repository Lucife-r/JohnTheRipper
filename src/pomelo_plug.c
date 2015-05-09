// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015.  
// This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on April,2015. 

// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)
    

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "pomelo.h"

#define F0(i)  {               \
    i0 = ((i) - 0*4*2)  & mask1; \
    i1 = ((i) - 2*4*2)  & mask1; \
    i2 = ((i) - 3*4*2)  & mask1; \
    i3 = ((i) - 7*4*2)  & mask1; \
    i4 = ((i) - 13*4*2) & mask1; \
    S[i0+1] = ((S[i1] ^ S[i2]) + S[i3]) ^ S[i4];         \
    S[i0+5] = ((S[i1+4] ^ S[i2+4]) + S[i3+4]) ^ S[i4+4];         \
    S[i0+2] = ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+6] = ((S[i1+5] ^ S[i2+5]) + S[i3+5]) ^ S[i4+5];         \
    S[i0+3] = ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+7] = ((S[i1+6] ^ S[i2+6]) + S[i3+6]) ^ S[i4+6];         \
    S[i0] = ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+4] = ((S[i1+7] ^ S[i2+7]) + S[i3+7]) ^ S[i4+7];         \
    S[i0] = (S[i0] << 17) | (S[i0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
    S[i0+4] = (S[i0+4] << 17) | (S[i0+4] >> 47);  \
    S[i0+5] = (S[i0+5] << 17) | (S[i0+5] >> 47);  \
    S[i0+6] = (S[i0+6] << 17) | (S[i0+6] >> 47);  \
    S[i0+7] = (S[i0+7] << 17) | (S[i0+7] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4*2)  & mask1; \
    i1 = ((i) - 2*4*2)  & mask1; \
    i2 = ((i) - 3*4*2)  & mask1; \
    i3 = ((i) - 7*4*2)  & mask1; \
    i4 = ((i) - 13*4*2) & mask1; \
    S[i0] += ((S[i1] ^ S[i2]) + S[i3]) ^ S[i4];         \
    S[i0+1] += ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+2] += ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+3] += ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+4] += ((S[i1+4] ^ S[i2+4]) + S[i3+4]) ^ S[i4+4];         \
    S[i0+5] += ((S[i1+5] ^ S[i2+5]) + S[i3+5]) ^ S[i4+5];         \
    S[i0+6] += ((S[i1+6] ^ S[i2+6]) + S[i3+6]) ^ S[i4+6];         \
    S[i0+7] += ((S[i1+7] ^ S[i2+7]) + S[i3+7]) ^ S[i4+7];         \
    temp  = S[i0+3];         \
    temp1 = S[i0+7];         \
    S[i0+3] = S[i0+2];      \
    S[i0+7] = S[i0+6];      \
    S[i0+2] = S[i0+1];      \
    S[i0+6] = S[i0+5];      \
    S[i0+1] = S[i0+0];      \
    S[i0+5] = S[i0+4];      \
    S[i0] = temp;         \
    S[i0+4] = temp1;         \
    S[i0] = (S[i0] << 17) | (S[i0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
    S[i0+4] = (S[i0+4] << 17) | (S[i0+4] >> 47);  \
    S[i0+5] = (S[i0+5] << 17) | (S[i0+5] >> 47);  \
    S[i0+6] = (S[i0+6] << 17) | (S[i0+6] >> 47);  \
    S[i0+7] = (S[i0+7] << 17) | (S[i0+7] >> 47);  \
}


#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 3;                             \
    for (j = 0; j < 256; j = j+8)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 8) & mask1;                                      \
        index_local    = (((i + j) >> 3) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 3;                                                \
        S[i0]          += (S[index_local]  << 1);                                   \
	S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
	S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[i0+4]       += (S[index_local+4] << 1);                                   \
	S[i0+5]       += (S[index_local+5] << 1);                                   \
        S[i0+6]       += (S[index_local+6] << 1);                                   \
	S[i0+7]       += (S[index_local+7] << 1);                                   \
        S[index_local]   += (S[i0]   << 2); \
	S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
	S[index_local+3] += (S[i0+3] << 2); \
        S[index_local+4] += (S[i0+4] << 2); \
	S[index_local+5] += (S[i0+5] << 2); \
        S[index_local+6] += (S[i0+6] << 2); \
	S[index_local+7] += (S[i0+7] << 2); \
        S[i0]         += (S[index_global]   << 1);                                   \
	S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
	S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[i0+4]       += (S[index_global+4] << 1);                                   \
	S[i0+5]       += (S[index_global+5] << 1);                                   \
        S[i0+6]       += (S[index_global+6] << 1);                                   \
	S[i0+7]       += (S[index_global+7] << 1);                                   \
        S[index_global]   += (S[i0]   << 3); \
	S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
	S[index_global+3] += (S[i0+3] << 3); \
        S[index_global+4] += (S[i0+4] << 3); \
	S[index_global+5] += (S[i0+5] << 3); \
        S[index_global+6] += (S[i0+6] << 3); \
	S[index_global+7] += (S[i0+7] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

#define H(i, random_number,random_number1)  {                                                      \
    index_global = ((random_number >> 16) & mask) << 3;                             \
    index_global1 = ((random_number1 >> 16) & mask) << 3;                             \
    for (j = 0; j < 256; j = j+8)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 8) & mask1;                                      \
	index_global1   = (index_global1 + 8) & mask1;                                      \
        index_local    = (((i + j) >> 3) - 0x1000 + (random_number & 0x1fff)) & mask;     \
	index_local1    = (((i + j) >> 3) - 0x1000 + (random_number1 & 0x1fff)) & mask;     \
        index_local    = index_local << 3;                                                \
	index_local1    = (index_local1 << 3) +4;                                                \
        S[i0+0]       += (S[index_local]   << 1);                                   \
	S[i0+1]       += (S[index_local+1] << 1);                                   \
	S[i0+2]       += (S[index_local+2] << 1);                                   \
	S[i0+3]       += (S[index_local+3] << 1);                                   \
	S[i0+4]       += (S[index_local1]  << 1);                                   \
	S[i0+5]       += (S[index_local1+1] << 1);                                   \
	S[i0+6]       += (S[index_local1+2] << 1);                                   \
	S[i0+7]       += (S[index_local1+3] << 1);                                   \
        S[index_local] += (S[i0] << 2); \
	S[index_local+1] += (S[i0+1] << 2); \
	S[index_local+2] += (S[i0+2] << 2); \
	S[index_local+3] += (S[i0+3] << 2); \
	S[index_local1]  += (S[i0+4] << 2); \
	S[index_local1+1] += (S[i0+5] << 2); \
	S[index_local1+2] += (S[i0+6] << 2); \
	S[index_local1+3] += (S[i0+7] << 2); \
        S[i0]         += (S[index_global+0] << 1);                                   \
	S[i0+1]       += (S[index_global+1] << 1);                                   \
	S[i0+2]       += (S[index_global+2] << 1);                                   \
	S[i0+3]       += (S[index_global+3] << 1);                                   \
	S[i0+4]       += (S[index_global1+4] << 1);                                   \
	S[i0+5]       += (S[index_global1+5] << 1);                                   \
	S[i0+6]       += (S[index_global1+6] << 1);                                   \
	S[i0+7]       += (S[index_global1+7] << 1);                                   \
        S[index_global]   += (S[i0] << 3); \
	S[index_global+1] += (S[i0+1] << 3); \
	S[index_global+2] += (S[i0+2] << 3); \
	S[index_global+3] += (S[i0+3] << 3); \
	S[index_global1+4]   += (S[i0+4] << 3); \
	S[index_global1+5] += (S[i0+5] << 3); \
	S[index_global1+6] += (S[i0+6] << 3); \
	S[index_global1+7] += (S[i0+7] << 3); \
        random_number   = S[i3+0];              \
	random_number1  = S[i3+4];              \
    }                                        \
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

int POMELO(void *out, size_t outlen, const void *in, size_t *inlen,
    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	uint64_t i, j, temp, temp1;
	uint64_t i0, i1, i2, i3, i4;
	uint64_t *S;
	uint64_t random_number, random_number1, index_global, index_global1, index_local, index_local1;
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
	S = (uint64_t *) aligned_malloc(state_size*INTERLEAVING_LEVEL,4096);
	mask = (1ULL << (8 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1ULL << (11 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/4;

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
	for (i = 13 * 4*2; i < (1ULL << (11 + m_cost)); i = i + 8)
		F0(i);


	//Step 4: Update the state using function G  
	random_number = 123456789ULL;
	for (i = 0; i < (1ULL << (10 + m_cost + t_cost)); i = i + 256)
		G(i, random_number);


	random_number1=random_number;
	//Step 5: Update the state using function H     
	for (i = 1ULL << (10 + m_cost + t_cost);
	    i < (1ULL << (11 + m_cost + t_cost)); i = i + 256)
		H(i, random_number,random_number1);
	

	//Step 6: Update the state using function F 
	for (i = 0; i < (1ULL << (11 + m_cost)); i = i + 8)
		F(i);


	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	for(j=0;j<INTERLEAVING_LEVEL;j++)
	for(i=0;i<outlen;i++)
		((char *)out)[i+j*BINARY_SIZE]=((unsigned char *)S) [MAPCH(state_size - outlen+i,j)];

	aligned_free(S);		// free the memory

	return 0;
}
