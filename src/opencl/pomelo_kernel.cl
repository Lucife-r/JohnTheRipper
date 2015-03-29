// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015. 
// This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on March 29,2015. 


// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)

#define BINARY_SIZE             257
#define SALT_SIZE		32
#define MEM_SIZE                131072

#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+1] = ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+2] = ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+3] = ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+0] = ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+0] += ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+1] += ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+2] += ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+3] += ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    temp = S[i0+3];         \
    S[i0+3] = S[i0+2];      \
    S[i0+2] = S[i0+1];      \
    S[i0+1] = S[i0+0];      \
    S[i0+0] = temp;         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

#define H(i, random_number)  {                                                      \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number  = S[i3];              \
    }                                        \
}



#include "opencl_device_info.h"
#include "opencl_misc.h"

__kernel void pomelo_crypt_kernel(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global const char *salt,
    __global unsigned short int *rest_salt, __global unsigned long *S)
{

	uint gid;

	unsigned long i, j, temp, y;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long random_number, index_global, index_local;
	unsigned long state_size, mask, mask1;


	size_t outlen, saltlen;
	unsigned int m_cost, t_cost;

	uint base, inlen;

	gid = get_global_id(0);

	out += gid * BINARY_SIZE;


	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = rest_salt[0];
	saltlen = rest_salt[1];
	t_cost = rest_salt[2];
	m_cost = rest_salt[3];


	in += base;

	S = (__global unsigned long *)((MEM_SIZE * gid +
		((__global unsigned char *)S)));


	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;

	state_size = 1ULL << (13 + m_cost);	//m_cost=3 is max
	if (state_size > MEM_SIZE)
		return;


	mask = (1ULL << (8 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1ULL << (10 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/8;



	//Step 2: Load the password, salt, input/output sizes into the state S
	for (i = 0; i < inlen; i++)
		((__global unsigned char *)S)[i] = in[i];	// load password into S
	for (i = 0; i < saltlen; i++)
		((__global unsigned char *)S)[inlen + i] = salt[i];	// load salt into S
	for (i = inlen + saltlen; i < 384; i++)
		((__global unsigned char *)S)[i] = 0;
	((__global unsigned char *)S)[384] = inlen & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[385] = (inlen >> 8) & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[386] = saltlen;	// load salt length (in bytes) into S;
	((__global unsigned char *)S)[387] = outlen & 0xff;	// load output length (in bytes into S)
	((__global unsigned char *)S)[388] = (outlen >> 8) & 0xff;	// load output length (in bytes into S) 
	((__global unsigned char *)S)[389] = 0;
	((__global unsigned char *)S)[390] = 0;
	((__global unsigned char *)S)[391] = 0;

	((__global unsigned char *)S)[392] = 1;
	((__global unsigned char *)S)[393] = 1;


	for (i = 394; i < 416; i++)
		((__global unsigned char *)S)[i] =
		    ((__global unsigned char *)S)[i - 1] +
		    ((__global unsigned char *)S)[i - 2];


	//Step 3: Expand the data into the whole state  
	y = (1ULL << (10 + m_cost));
	for (i = 13 * 4; i < y; i = i + 4)
		F0(i);

	//Step 4: Update the state using function G  
	random_number = 123456789ULL;
	for (i = 0; i < (1ULL << (9 + m_cost + t_cost)); i = i + 128)
		G(i, random_number);

	//Step 5: Update the state using function H     
	for (i = 1ULL << (9 + m_cost + t_cost);
	    i < (1ULL << (10 + m_cost + t_cost)); i = i + 128)
		H(i, random_number);

	//Step 6: Update the state using function F 
	for (i = 0; i < (1ULL << (10 + m_cost)); i = i + 4)
		F(i);

	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	for (i = 0; i < outlen; i++) {
		out[i + 1] =
		    ((__global unsigned char *)S)[state_size - outlen + i];
	}
	out[0] = (char)outlen;
}
