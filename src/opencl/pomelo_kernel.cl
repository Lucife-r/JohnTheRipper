// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015. 
// This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on March 29,2015. 


// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)


#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[MAP(i0+1)] = ((S[MAP(i1+0)] ^ S[MAP(i2+0)]) + S[MAP(i3+0)]) ^ S[MAP(i4+0)];         \
    S[MAP(i0+2)] = ((S[MAP(i1+1)] ^ S[MAP(i2+1)]) + S[MAP(i3+1)]) ^ S[MAP(i4+1)];         \
    S[MAP(i0+3)] = ((S[MAP(i1+2)] ^ S[MAP(i2+2)]) + S[MAP(i3+2)]) ^ S[MAP(i4+2)];         \
    S[MAP(i0+0)] = ((S[MAP(i1+3)] ^ S[MAP(i2+3)]) + S[MAP(i3+3)]) ^ S[MAP(i4+3)];         \
    Saddress=S[MAP(i0+instruction)];							  \
    S[MAP(i0+instruction)] = (Saddress << 17) | (Saddress >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    address=i0+instruction; \
    S[MAP(address)] += ((S[MAP(i1+instruction)] ^ S[MAP(i2+instruction)]) + S[MAP(i3+instruction)]) ^ S[MAP(i4+instruction)];         \
    temp = S[MAP(i0+3)];         \
    S[MAP(i0+3)] = S[MAP(i0+2)];      \
    S[MAP(i0+2)] = S[MAP(i0+1)];      \
    S[MAP(i0+1)] = S[MAP(i0+0)];      \
    S[MAP(i0+0)] = temp;         \
    Saddress = S[MAP(address)]; \
    Saddress=S[MAP(address)] = (Saddress << 17) | (Saddress >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2; \
	if(address==index_local+instruction) { \
	   	Saddress       += (Saddress << 1);                                   \
           	Saddress += (Saddress << 2); \
           	S[MAP(address)]=Saddress; \
	} \
	else {\
	   loc_addr=MAP(index_local+instruction); \
           Saddress       += (S[loc_addr] << 1);                                   \
           S[loc_addr] += (Saddress << 2); \
	} \
	if(address==index_global+instruction) \
	{ \
		Saddress       += (Saddress << 1);                                   \
        	Saddress += (Saddress << 3); \
		S[MAP(address)]=Saddress; \
	} \
	else { \
		glob_addr=MAP(index_global+instruction); \
        	Saddress       += (S[glob_addr] << 1);                                   \
        	S[glob_addr] += (Saddress << 3); \
	} \
	S[MAP(address)] =Saddress; \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238UL;   \
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
	Saddress=S[MAP(address)];							\
	if(address==index_local+instruction) \
	{ \
		Saddress       += (Saddress << 1);                                   \
                Saddress += (Saddress << 2); \
		S[MAP(address)]=Saddress; \
	} \
	else \
	{ \
		loc_addr=MAP(index_local+instruction); \
        	Saddress       += (S[loc_addr] << 1);                                   \
        	S[loc_addr] += (Saddress << 2); \
	} \
	if(address==index_global+instruction) \
  	{ \
		Saddress       += (Saddress << 1);                                   \
        	Saddress += (Saddress << 3);  \
		S[MAP(address)]=Saddress; \
	}\
	else \
	{ \
		glob_addr=MAP(index_global+instruction); \
        	Saddress       += (S[glob_addr] << 1);                                   \
        	S[glob_addr] += (Saddress << 3); \
	} \
	S[MAP(address)]=Saddress;                 \
        random_number  = S[MAP(i3)];              \
    }                                        \
}

//#define MAP(X) ((X)*GID+gid)
//#define MAPCH(X) (((X)/8*GID+gid)*8+(X)%8)

#define MAP(X) (((X)/4*4)*GID+gid4+(X)%4)
#define MAPCH(X) MAP((X)/8)*8+(X)%8

#include "opencl_device_info.h"
#include "opencl_misc.h"

// BINARY_SIZE, SALT_SIZE, MEM_SIZE, T_COST and M_COST is passed with -D during build

__kernel void pomelo_crypt_kernel(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global const char *salt, 
    __global unsigned short int *rest_salt,
    __global unsigned long *S)
{
	uint gid;
	uint GID;
	unsigned long instruction;

	unsigned long i, j, temp, y;
	unsigned long address;
	unsigned long Saddress;
	unsigned long gid4;
	unsigned long i0, i1, i2, i3, i4;
	unsigned long loc_addr;
	unsigned long glob_addr;

	unsigned long random_number, index_global, index_local;
	unsigned long state_size, mask, mask1;


	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID=get_global_size(0);
	
	//for computing one hash in 4 GPU units	
	instruction=gid%4;
	gid=gid/4;
	GID=GID/4;
	gid4=gid*4;

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = rest_salt[0];
	saltlen = rest_salt[1];


	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;


	state_size = 1UL << (13 + M_COST);	

	mask = (1UL << (8 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;


	if(instruction==0)
	{
	//Step 2: Load the password, salt, input/output sizes into the state S
	for (i = 0; i < inlen; i++)
		((__global unsigned char *)S)[MAPCH(i)] = in[i];	// load password into S
	for (i = 0; i < saltlen; i++)
		((__global unsigned char *)S)[MAPCH(inlen + i)] = salt[i];	// load salt into S
	for (i = inlen + saltlen; i < 384; i++)
		((__global unsigned char *)S)[MAPCH(i)] = 0;
	((__global unsigned char *)S)[MAPCH(384)] = inlen & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(385)] = (inlen >> 8) & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(386)] = saltlen;	// load salt length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(387)] = outlen & 0xff;	// load output length (in bytes into S)
	((__global unsigned char *)S)[MAPCH(388)] = (outlen >> 8) & 0xff;	// load output length (in bytes into S) 
	((__global unsigned char *)S)[MAPCH(389)] = 0;
	((__global unsigned char *)S)[MAPCH(390)] = 0;
	((__global unsigned char *)S)[MAPCH(391)] = 0;

	((__global unsigned char *)S)[MAPCH(392)] = 1;
	((__global unsigned char *)S)[MAPCH(393)] = 1;


	for (i = 394; i < 416; i++)
		((__global unsigned char *)S)[MAPCH(i)] =
		    ((__global unsigned char *)S)[MAPCH(i - 1)] + ((__global unsigned char *)S)[MAPCH(i - 2)];

	}

	//Step 3: Expand the data into the whole state  
	y = (1UL << (10 + M_COST));
	for (i = 13 * 4; i < y; i = i + 4)
		F0(i);


	//Step 4: Update the state using function G  
	random_number = 123456789UL;
	for (i = 0; i < (1UL << (9 + M_COST + T_COST)); i = i + 128)
		G(i, random_number);

	//Step 5: Update the state using function H     
	for (i = 1UL << (9 + M_COST + T_COST);
	    i < (1UL << (10 + M_COST + T_COST)); i = i + 128)
		H(i, random_number);

	//Step 6: Update the state using function F 
	for (i = 0; i < (1UL << (10 + M_COST)); i = i + 4)
		F(i);

	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	for (i = 0; i < outlen; i++) {
		out[i + 1] = ((__global unsigned char *)S)[MAPCH(state_size - outlen + i)];
	}
	if(instruction==0)
	{
	  out[0] = (char)outlen;
        }
}
