/*****Argon2d optimized implementation*
*  Code written by Daniel Dinu and Dmitry Khovratovich
* khovratovich@gmail.com
* modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
**/

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_string.h"
#include "opencl_blake2.h"
#include "opencl_argon2d.h"
#include "opencl_blake2-round-no-msg.h"

//#define MAP(X) ((X)*get_global_size(0))
#define MAP(X) ((X))

// BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH is paVd with -D during build

struct argon2d_salt {
	unsigned int t_cost, m_cost;
	uchar lanes;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

static void scheme_info_t_init(scheme_info_t *scheme, __global ulong2* s, uint m, uint p, uchar l)
{
	scheme->state = s;
	scheme->mem_size = m;
	scheme->passes = p;
	scheme->lanes = l;
}

static void position_info_t_init(position_info_t *position, uint p, uchar s, uchar l, uint i)
{
	position->pass = p;
	position->slice = s;
	position->lane = l;
	position->index = i;
}

static int blake2b_long(uchar *out, const void *in, const uint outlen, const ulong inlen)
{
	uint toproduce;
	blake2b_state blake_state;
	if (outlen <= BLAKE2B_OUTBYTES)
	{
		blake2b_init(&blake_state, outlen);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final(&blake_state, out, outlen);
	}
	else
	{
		uchar out_buffer[BLAKE2B_OUTBYTES];
		uchar in_buffer[BLAKE2B_OUTBYTES];
		blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
		memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
		out += BLAKE2B_OUTBYTES / 2;
		toproduce = outlen - BLAKE2B_OUTBYTES / 2;
		while (toproduce > BLAKE2B_OUTBYTES)
		{
			memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
			blake2b(out_buffer, in_buffer, 0, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
			memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			toproduce -= BLAKE2B_OUTBYTES / 2;
		}
		memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
		blake2b(out_buffer, in_buffer, 0, toproduce, BLAKE2B_OUTBYTES, 0);
		memcpy(out, out_buffer, toproduce);

	}
	return 0;
}


static void ComputeBlock_pgg(ulong2 *state, __global ulong2 *ref_block_ptr, __global ulong2 *next_block_ptr)
{
	ulong2 ref_block[64];
	ulong2 statecp[64];
	uchar i;

	ulong8 t0,t1;
	uchar16 r16 = (uchar16) (2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	uchar16 r24 = (uchar16) (3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

	for (i = 0; i < 64; i++)
	{
		ref_block[i] = ref_block_ptr[MAP(i)];
	}

	for (i = 0; i < 64; i++)
	{
		ref_block[i] ^= state[i] ; //XORing the reference block to the state and storing the copy of the result
	}


	// BLAKE2 - begin

	for(i=0;i<8;i++)
	{
		state[i*4]=ref_block[i];
		state[i*4+1]=ref_block[i+8];
		state[i*4+2]=ref_block[i+16];
		state[i*4+3]=ref_block[i+24];
		state[i*4+32]=ref_block[i+32];
		state[i*4+1+32]=ref_block[i+40];
		state[i*4+2+32]=ref_block[i+48];
		state[i*4+3+32]=ref_block[i+56];
	}

	// BLAKE2 - begin

	ulong8 v1=(ulong8) (((ulong8 *)state)[0]);
	ulong8 v2=(ulong8) (((ulong8 *)state)[1]);
	ulong8 v3=(ulong8) (((ulong8 *)state)[2]);
	ulong8 v4=(ulong8) (((ulong8 *)state)[3]);
	ulong8 v5=(ulong8) (((ulong8 *)state)[4]);
	ulong8 v6=(ulong8) (((ulong8 *)state)[5]);
	ulong8 v7=(ulong8) (((ulong8 *)state)[6]);
	ulong8 v8=(ulong8) (((ulong8 *)state)[7]);

	ulong8 v9=(ulong8) (((ulong8 *)state)[8]);
	ulong8 v10=(ulong8) (((ulong8 *)state)[9]);
	ulong8 v11=(ulong8) (((ulong8 *)state)[10]);
	ulong8 v12=(ulong8) (((ulong8 *)state)[11]);
	ulong8 v13=(ulong8) (((ulong8 *)state)[12]);
	ulong8 v14=(ulong8) (((ulong8 *)state)[13]);
	ulong8 v15=(ulong8) (((ulong8 *)state)[14]);
	ulong8 v16=(ulong8) (((ulong8 *)state)[15]);

	BLAKE2_ROUND_NO_MSG_V8(v1,v2,v3,v4,v5,v6,v7,v8);
	BLAKE2_ROUND_NO_MSG_V8(v9,v10,v11,v12,v13,v14,v15,v16);

	ulong8 v1c = v1;
	ulong8 v2c = v2;
	ulong8 v3c = v3;
	ulong8 v4c = v4;
	ulong8 v5c = v5;
	ulong8 v6c = v6;
	ulong8 v7c = v7;
	ulong8 v8c = v8;

	ulong8 v9c = v9;
	ulong8 v10c = v10;
	ulong8 v11c = v11;
	ulong8 v12c = v12;
	ulong8 v13c = v13;
	ulong8 v14c = v14;
	ulong8 v15c = v15;
	ulong8 v16c = v16;

	v1= (ulong8) (v1c.s01, v2c.s01, v3c.s01, v4c.s01);
	v2= (ulong8) (v5c.s01, v6c.s01, v7c.s01, v8c.s01);
	v3= (ulong8) (v1c.s23, v2c.s23, v3c.s23, v4c.s23);
	v4= (ulong8) (v5c.s23, v6c.s23, v7c.s23, v8c.s23);
	v5= (ulong8) (v1c.s45, v2c.s45, v3c.s45, v4c.s45);
	v6= (ulong8) (v5c.s45, v6c.s45, v7c.s45, v8c.s45);
	v7= (ulong8) (v1c.s67, v2c.s67, v3c.s67, v4c.s67);
	v8= (ulong8) (v5c.s67, v6c.s67, v7c.s67, v8c.s67);

	v9= (ulong8) (v9c.s01, v10c.s01, v11c.s01, v12c.s01);
	v10= (ulong8) (v13c.s01, v14c.s01, v15c.s01, v16c.s01);
	v11= (ulong8) (v9c.s23, v10c.s23, v11c.s23, v12c.s23);
	v12= (ulong8) (v13c.s23, v14c.s23, v15c.s23, v16c.s23);
	v13= (ulong8) (v9c.s45, v10c.s45, v11c.s45, v12c.s45);
	v14= (ulong8) (v13c.s45, v14c.s45, v15c.s45, v16c.s45);
	v15= (ulong8) (v9c.s67, v10c.s67, v11c.s67, v12c.s67);
	v16= (ulong8) (v13c.s67, v14c.s67, v15c.s67, v16c.s67); 


	BLAKE2_ROUND_NO_MSG_V8(v1, v3, v5, v7, v9, v11, v13, v15);
	BLAKE2_ROUND_NO_MSG_V8(v2, v4, v6, v8, v10, v12, v14, v16);


	(((ulong8 *)state)[0]) = v1 ^ ((ulong8*)ref_block)[0];
	(((ulong8 *)state)[1]) = v2 ^ ((ulong8*)ref_block)[1];
	(((ulong8 *)state)[2]) = v3 ^ ((ulong8*)ref_block)[2];
	(((ulong8 *)state)[3]) = v4 ^ ((ulong8*)ref_block)[3];
	(((ulong8 *)state)[4]) = v5 ^ ((ulong8*)ref_block)[4];
	(((ulong8 *)state)[5]) = v6 ^ ((ulong8*)ref_block)[5];
	(((ulong8 *)state)[6]) = v7 ^ ((ulong8*)ref_block)[6];
	(((ulong8 *)state)[7]) = v8 ^ ((ulong8*)ref_block)[7];

	(((ulong8 *)state)[8]) = v9 ^ ((ulong8*)ref_block)[8];
	(((ulong8 *)state)[9]) = v10 ^ ((ulong8*)ref_block)[9];
	(((ulong8 *)state)[10]) = v11 ^ ((ulong8*)ref_block)[10];
	(((ulong8 *)state)[11]) = v12 ^ ((ulong8*)ref_block)[11];
	(((ulong8 *)state)[12]) = v13 ^ ((ulong8*)ref_block)[12];
	(((ulong8 *)state)[13]) = v14 ^ ((ulong8*)ref_block)[13];
	(((ulong8 *)state)[14]) = v15 ^ ((ulong8*)ref_block)[14];
	(((ulong8 *)state)[15]) = v16 ^ ((ulong8*)ref_block)[15];


	for (i = 0; i< 64; i++)
	{
		next_block_ptr[MAP(i)]=state[i];
	}
}

static void Initialize(scheme_info_t* info,uchar* input_hash)
{
	uchar l;
	uint i;
	__global ulong2 *memory=info->state;
	uchar block_input[BLAKE_INPUT_HASH_SIZE + 8];
	ulong2 out_tmp[BLOCK_SIZE/16];
	uint segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, BLAKE_INPUT_HASH_SIZE);
	memset(block_input + BLAKE_INPUT_HASH_SIZE, 0, 8);
	for (l = 0; l < info->lanes; ++l)
	{
		block_input[BLAKE_INPUT_HASH_SIZE + 4] = l;
		block_input[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long((uchar*)out_tmp, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		for(i=0;i<BLOCK_SIZE/16;i++)
			memory[MAP(l * segment_length*BLOCK_SIZE/16+i)]=out_tmp[i];
		block_input[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uchar*)out_tmp, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		for(i=0;i<BLOCK_SIZE/16;i++)
			memory[MAP((l * segment_length + 1)*BLOCK_SIZE/16+i)]=out_tmp[i];
	}
	memset(block_input, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

static void Finalize_g(__global ulong2 *state, uchar* out, uint outlen, uchar lanes, uint m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	uchar l;
	uint j;
	ulong2 blockhash[BLOCK_SIZE/sizeof(ulong2)];
	for(j=0;j<BLOCK_SIZE/sizeof(ulong2);j++)
	{
		blockhash[j]=0;
	}
	for (l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint segment_length = m_cost / (SYNC_POINTS*lanes);
		__global ulong2* block_ptr = state + MAP((((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE/16); //points to the last block of the first lane

		for (j = 0; j < BLOCK_SIZE / sizeof(ulong2); ++j)
		{
			blockhash[j] = blockhash[j]^block_ptr[MAP(j)];

		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);
}

static void FillSegment(scheme_info_t *info, position_info_t pos)
{
	uint i;

	ulong2 prev_block[64];

	uint next_block_offset;
	uchar lanes = info->lanes;
	__global ulong2* memory = info->state;
	uint phi;

	uint segment_length = (info->mem_size) / (lanes*SYNC_POINTS);
	//uint stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint start=0;

	uint prev_block_recalc=0; //number of the first block in the reference area in the previous slice

	if(0 == pos.pass && 0 == pos.slice) // First pass; first slice
	{
		uint bi;
		uint reference_block_offset;

		start += 3;
		if (segment_length <= 2)
			return;

		bi = (pos.lane * segment_length + 1) * BLOCK_SIZE / 16;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 64; i++)
		{
			prev_block[i] = memory[MAP(bi+i)];
		}

		next_block_offset = (pos.lane * segment_length + 2) * BLOCK_SIZE;

		reference_block_offset = (pos.lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock_pgg(prev_block, memory+ MAP(reference_block_offset/16), memory+MAP(next_block_offset/16));//Computing third block in the segment

		phi = ((ulong *)prev_block)[0];
	}
	else
	{
		uint prev_slice = (pos.slice>0)?(pos.slice-1):(SYNC_POINTS-1);
		uint bi;

		prev_block_recalc = (pos.slice > 0) ? ((pos.slice - 1)*lanes*segment_length) : (SYNC_POINTS - 2)*lanes*segment_length;
		bi = ((prev_slice * lanes + pos.lane + 1) * segment_length - 1) * BLOCK_SIZE / 16;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 64; i++)
		{
			prev_block[i] = memory[MAP(bi+i)];
		}

		phi = ((ulong *)prev_block)[0];
	}

	next_block_offset = ((pos.slice*lanes + pos.lane)*segment_length + start)*BLOCK_SIZE;
	for(i = start; i < segment_length; i++)
	{
		// Compute block2 index
		uint barrier1 = pos.slice * segment_length*lanes; //Number of blocks generated in previous slices

		uint barrier2;  //Number of blocks that we can reference in total (including the previous block in the lane that we can not reference in the first block of the segment)
		uint barrier3, r, reference_block_offset;

		if(pos.pass==0)
			barrier2 = barrier1;
		else
		{
			barrier2 = barrier1 + (SYNC_POINTS - pos.slice - 1) *  segment_length*lanes;
		}

		barrier3 = (i==0)? (barrier2 -lanes):(barrier2+ i-1);

		r = barrier3;

		reference_block_offset = (phi % r);

		/*Excluding the previous block from referencing*/
		if(i==0)
		{
			if (reference_block_offset >= prev_block_recalc)
			{
				uint shift = (reference_block_offset - prev_block_recalc) / (segment_length - 1);
				reference_block_offset += (shift > lanes) ? lanes : shift;
			}
		}

		//Mapping the reference block address into the memory
		if(reference_block_offset < barrier1)
			reference_block_offset *= BLOCK_SIZE;
		else
		{
			if(reference_block_offset >= barrier1 && reference_block_offset < barrier2)
				reference_block_offset = (reference_block_offset + segment_length*lanes) * BLOCK_SIZE;
			else
				reference_block_offset = (reference_block_offset - (barrier2 - barrier1) + pos.lane *  segment_length) * BLOCK_SIZE;
		}

		// compute block
		ComputeBlock_pgg(prev_block, memory + MAP(reference_block_offset/16), memory+MAP(next_block_offset/16));
		phi = ((ulong *)prev_block)[0];
		next_block_offset += BLOCK_SIZE;
	}
}

static void FillMemory(scheme_info_t* info)//Main loop: filling memory <t_cost> times
{
	uint p,s,t;
	position_info_t position;
	position_info_t_init(&position,0,0,0,0);
	for (p = 0; p < info->passes; p++)
	{
		position.pass = p;
		for (s = 0; s < SYNC_POINTS; s++)
		{
			position.slice = s;
			for (t = 0; t < info->lanes; t++)
			{
				position.lane = t;
				FillSegment(info, position);
			}
		}
	}
}

static int argon2d(__global uchar *out, uint outlen, const uchar *msg, uint msglen, const uchar *nonce, uint noncelen, const uchar *secret,
	uchar secretlen, const uchar *ad, uint adlen, uint t_cost, uint m_cost, uchar lanes, __global ulong2 *memory)
{
	uchar blockhash[BLAKE_INPUT_HASH_SIZE];//H_0 in the document
	uchar out_tmp[BINARY_SIZE*10];
	uchar version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	scheme_info_t info;

	if (outlen>MAX_OUTLEN)
		outlen = MAX_OUTLEN;
	if (outlen < MIN_OUTLEN)
		return -1;  //Tag too short

	if (msglen> MAX_MSG)
		msglen = MAX_MSG;

	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;

	if (adlen> MAX_AD)
		adlen = MAX_AD;

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*(uint)lanes)
		m_cost = 2 * SYNC_POINTS*(uint)lanes;
	if (m_cost>MAX_MEMORY)
		return -6;

	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =3
	if (t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;


	//Initial hashing
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE);
	blake2b_init(&BlakeHash, BLAKE_INPUT_HASH_SIZE);

	blake2b_update(&BlakeHash, (const uchar*)&lanes, sizeof(lanes));
	blake2b_update(&BlakeHash, (const uchar*)&outlen, sizeof(outlen));
	blake2b_update(&BlakeHash, (const uchar*)&m_cost, sizeof(m_cost));
	blake2b_update(&BlakeHash, (const uchar*)&t_cost, sizeof(t_cost));
	blake2b_update(&BlakeHash, (const uchar*)&version, sizeof(version));
	blake2b_update(&BlakeHash, (const uchar*)&msglen, sizeof(msglen));
	blake2b_update(&BlakeHash, (const uchar*)msg, msglen);
	blake2b_update(&BlakeHash, (const uchar*)&noncelen, sizeof(noncelen));
	blake2b_update(&BlakeHash, (const uchar*)nonce, noncelen);
	blake2b_update(&BlakeHash, (const uchar*)&secretlen, sizeof(secretlen));
	blake2b_update(&BlakeHash, (const uchar*)secret, secretlen);
	blake2b_update(&BlakeHash, (const uchar*)&adlen, sizeof(adlen));
	blake2b_update(&BlakeHash, (const uchar*)ad, adlen);


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE); //Calculating H0

	scheme_info_t_init(&info, memory, m_cost, t_cost, lanes);
	//2433K
	Initialize(&info,blockhash); //Computing first two blocks in each segment


	FillMemory(&info);  //Filling memory with <t_cost> passes
	//11K
	Finalize_g(memory, out_tmp, outlen , lanes, m_cost);
	memcpy_g(out, out_tmp, outlen);

	return 0;
}


__kernel void argon2d_crypt_kernel(
    __global const uchar * in,
    __global const uint * lengths,
    __global uchar *out,
    __global struct argon2d_salt *salt,
    __global ulong2 *memory
)
{
	uint i;
	uint gid;

	uint m_cost, t_cost;
	uchar lanes;
	uint outlen, noncelen;

	uint inlen;

	uchar passwd[PLAINTEXT_LENGTH];
	uchar nonce[SALT_SIZE];

	gid = get_global_id(0);

	out += gid * BINARY_SIZE;

	inlen = lengths[gid];

	outlen = salt->hash_size;
	noncelen = salt->salt_length;

	t_cost = salt->t_cost;
	m_cost = salt->m_cost;
	lanes=salt->lanes;

	in += gid*PLAINTEXT_LENGTH;
	//memory+=gid;
	memory+=gid*(((ulong)m_cost)<<10)/sizeof(ulong2);

	//copying password
	for(i=0;i<inlen;i++)
		passwd[i]=in[i];

	//copying salt
	for(i=0;i<noncelen;i++)
		nonce[i]=salt->salt[i];

	argon2d(out, outlen, passwd, inlen, nonce, noncelen, 0, 0, 0, 0, t_cost, m_cost, lanes, memory);
}
