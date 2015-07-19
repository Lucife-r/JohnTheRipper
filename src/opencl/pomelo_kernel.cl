// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015. 
// This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on April,2015. 


// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)


#define F0(i)  {		\
    i0 = ((i) - 0*4)  & mask1;	\
    i1 = ((i) - 2*4)  & mask1;	\
    i2 = ((i) - 3*4)  & mask1;	\
    i3 = ((i) - 7*4)  & mask1;	\
    i4 = ((i) - 13*4) & mask1;	\
    v=vload4(0,S+sMAP(i0));	\
    v1=vload4(0,S+sMAP(i1));	\
    v2=vload4(0,S+sMAP(i2));	\
    v3=vload4(0,S+sMAP(i3));	\
    v4=vload4(0,S+sMAP(i4));	\
    v= ((v1^v2)+v3)^v4;		\
    v=(ulong4)(v.w,v.xyz);	\
    v= v<<17 | v >>47;		\
    vstore4(v,0,S+sMAP(i0));	\
}

#define F(i)  {			\
    i0 = ((i) - 0*4)  & mask1;	\
    i1 = ((i) - 2*4)  & mask1;	\
    i2 = ((i) - 3*4)  & mask1;	\
    i3 = ((i) - 7*4)  & mask1;	\
    i4 = ((i) - 13*4) & mask1;	\
				\
    v=vload4(0,S+sMAP(i0));	\
    v1=vload4(0,S+sMAP(i1));	\
    v2=vload4(0,S+sMAP(i2));	\
    v3=vload4(0,S+sMAP(i3));	\
    v4=vload4(0,S+sMAP(i4));	\
    v= v+(((v1^v2)+v3)^v4);	\
				\
    v=(ulong4)(v.w,v.x,v.y,v.z);\
				\
    v= v<<17 | v >>47;		\
    vstore4(v,0,S+sMAP(i0));	\
}

#define G(i,random_number)  {										\
    index_global = ((random_number >> 16) & mask) << 2;							\
    for (j = 0; j < 128; j = j+4)									\
    {													\
        F(i+j);												\
        index_global   = (index_global + 4) & mask1;							\
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;			\
        index_local    = index_local << 2;								\
													\
	if(i0==index_local)										\
	{												\
    	v= v+(v<<1);											\
	v=v+(v<<2);											\
	vstore4(v,0,S+sMAP(i0));									\
	}												\
	else												\
	{												\
	v1=vload4(0,S+sMAP(index_local));								\
    	v= v+(v1<<1);											\
	v1=v1+(v<<2);											\
	vstore4(v1,0,S+sMAP(index_local));								\
	}												\
													\
	if(i0==index_global)										\
	{												\
    	v= v+(v<<1);											\
	v=v+(v<<3);											\
	vstore4(v,0,S+sMAP(i0));									\
	}												\
	else												\
	{												\
	v1=vload4(0,S+sMAP(index_global));								\
    	v= v+(v1<<1);											\
	v1=v1+(v<<3);											\
	vstore4(v1,0,S+sMAP(index_global));								\
	}												\
	vstore4(v,0,S+sMAP(i0));									\
        random_number += (random_number << 2);								\
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238UL;	\
    }													\
}

#define H(i, random_number)  {								\
    index_global = ((random_number >> 16) & mask) << 2;					\
    for (j = 0; j < 128; j = j+4)							\
    {											\
        F(i+j);										\
        index_global   = (index_global + 4) & mask1;					\
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;	\
        index_local    = index_local << 2;						\
											\
	if(i0==index_local)								\
	{										\
    	v= v+(v<<1);									\
	v=v+(v<<2);									\
	vstore4(v,0,S+sMAP(i0));							\
	}										\
	else										\
	{										\
	v1=vload4(0,S+sMAP(index_local));						\
    	v= v+(v1<<1);									\
	v1=v1+(v<<2);									\
	vstore4(v1,0,S+sMAP(index_local));						\
	}										\
											\
	if(i0==index_global)								\
	{										\
    	v= v+(v<<1);									\
	v=v+(v<<3);									\
	vstore4(v,0,S+sMAP(i0));							\
	}										\
	else										\
	{										\
	v1=vload4(0,S+sMAP(index_global));						\
    	v= v+(v1<<1);									\
	v1=v1+(v<<3);									\
	vstore4(v1,0,S+sMAP(index_global));						\
	}										\
	vstore4(v,0,S+sMAP(i0));							\
        random_number  = S[sMAP(i3)];							\
    }											\
}

#define MAP(X) (((X)/4*4)*GID+gid4+(X)%4)
#define sMAP(X) ((X)*GID+gid4)
#define MAPCH(X) MAP((X)/8)*8+(X)%8

#include "opencl_device_info.h"
#include "opencl_misc.h"

// BINARY_SIZE, SALT_SIZE is passed with -D during build

struct pomelo_salt {
	unsigned int t_cost, m_cost;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

struct pomelo_loop{
	unsigned long from;
	unsigned long to;
};

/* whole kernel (unused) */
__kernel void pomelo_crypt_kernel(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct pomelo_salt *salt,
    __global unsigned long *S,
    __global struct pomelo_loop *loop
)
{
	unsigned long gid4;

	uint gid;
	uint GID;

	unsigned long i, j, y;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long random_number, index_global, index_local;
	unsigned long state_size, mask, mask1;
	ulong4 v, v1, v2, v3, v4;

	unsigned short int M_COST, T_COST;
	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID = get_global_size(0);
	gid4 = gid * 4;

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	saltlen = salt->salt_length;

	T_COST = salt->t_cost;
	M_COST = salt->m_cost;


	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;

	state_size = 1UL << (13 + M_COST);

	mask = (1UL << (8 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;


	//Step 2: Load the password, salt, input/output sizes into the state S
	for (i = 0; i < inlen; i++)
		((__global unsigned char *)S)[MAPCH(i)] = in[i];	// load password into S
	for (i = 0; i < saltlen; i++)
		((__global unsigned char *)S)[MAPCH(inlen + i)] = salt->salt[i];	// load salt into S
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
		    ((__global unsigned char *)S)[MAPCH(i - 1)] +
		    ((__global unsigned char *)S)[MAPCH(i - 2)];


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
		out[i] =
		    ((__global unsigned char *)S)[MAPCH(state_size - outlen +
			i)];
	}
}

__kernel void pomelo_init_and_F0(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct pomelo_salt *salt,
    __global unsigned long *S,
    __global struct pomelo_loop *loop
)
{
	unsigned long gid4;

	uint gid;
	uint GID;

	unsigned long i, y, from=loop->from;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long mask1;
	ulong4 v, v1, v2, v3, v4;

	unsigned short int M_COST;
	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID = get_global_size(0);
	gid4 = gid * 4;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	saltlen = salt->salt_length;

	M_COST = salt->m_cost;

	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;
 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;


	if(from==13 * 4)
	{
		//Step 2: Load the password, salt, input/output sizes into the state S
		for (i = 0; i < inlen; i++)
			((__global unsigned char *)S)[MAPCH(i)] = in[i];	// load password into S
		for (i = 0; i < saltlen; i++)
			((__global unsigned char *)S)[MAPCH(inlen + i)] = salt->salt[i];	// load salt into S
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
			    ((__global unsigned char *)S)[MAPCH(i - 1)] +
			    ((__global unsigned char *)S)[MAPCH(i - 2)];
	}


	//Step 3: Expand the data into the whole state  
	y = loop->to;
	for (i = from; i < y; i = i + 4)
		F0(i);
}

__kernel void pomelo_G(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct pomelo_salt *salt,
    __global unsigned long *S,
    __global struct pomelo_loop *loop
)
{
	unsigned long gid4;

	uint gid;
	uint GID;

	unsigned long i, j, y;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long random_number, index_global, index_local;
	unsigned long mask, mask1;
	ulong4 v, v1, v2, v3, v4;

	unsigned short int M_COST;
	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID = get_global_size(0);
	gid4 = gid * 4;

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	saltlen = salt->salt_length;

	M_COST = salt->m_cost;

	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;


	mask = (1UL << (8 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;


	//Step 4: Update the state using function G 
	i=loop->from;
	if(i==0) 
		random_number = 123456789UL;
	else
		random_number=((__global unsigned long*)out)[0];
	y=loop->to;
	for (; i < y; i = i + 128)
		G(i, random_number);

	//save random number
	((__global unsigned long*)out)[0]=random_number;
}

__kernel void pomelo_H(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct pomelo_salt *salt,
    __global unsigned long *S,
    __global struct pomelo_loop *loop
)
{
	unsigned long gid4;

	uint gid;
	uint GID;

	unsigned long i, j, y;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long random_number, index_global, index_local;
	unsigned long mask, mask1;
	ulong4 v, v1, v2, v3, v4;

	unsigned short int M_COST;
	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID = get_global_size(0);
	gid4 = gid * 4;

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	saltlen = salt->salt_length;

	M_COST = salt->m_cost;

	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;

	mask = (1UL << (8 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;

	//load random number
	random_number=((__global unsigned long*)out)[0];

	//Step 5: Update the state using function H
	y=loop->to;     
	for (i = loop->from;
	    i < y; i = i + 128)
		H(i, random_number);

	//save random number
	((__global unsigned long*)out)[0]=random_number;
}

__kernel void pomelo_F_and_out(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct pomelo_salt *salt,
    __global unsigned long *S,
    __global struct pomelo_loop *loop
)
{
	unsigned long gid4;

	uint gid;
	uint GID;

	unsigned long i, y;

	unsigned long i0, i1, i2, i3, i4;

	unsigned long state_size, mask1;
	ulong4 v, v1, v2, v3, v4;

	unsigned short int M_COST;
	size_t outlen, saltlen;

	uint base, inlen;

	gid = get_global_id(0);
	GID = get_global_size(0);
	gid4 = gid * 4;

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	saltlen = salt->salt_length;

	M_COST = salt->m_cost;

	in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;

	state_size = 1UL << (13 + M_COST);

	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;


	//Step 6: Update the state using function F 
	y=loop->to;
	for (i = loop->from; i < y; i = i + 4)
		F(i);

	//Step 7: Generate the output   
	//memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	if(y==(1UL << (10 + M_COST)))
		for (i = 0; i < outlen; i++) {
			out[i] =
			    ((__global unsigned char *)S)[MAPCH(state_size - outlen +
				i)];
		}
}

