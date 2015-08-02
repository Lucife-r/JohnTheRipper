/*****Argon2i optimized implementation*
*  Code written by Daniel Dinu and Dmitry Khovratovich
* khovratovich@gmail.com
* modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
**/

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_string.h"
#include "opencl_blake2.h"
#include "opencl_argon2i.h"
#include "opencl_blake2-round-no-msg.h"

// BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH is passed with -D during build

struct argon2i_salt {
	unsigned int t_cost, m_cost;
	uchar lanes;
	unsigned int hash_size;
	unsigned int salt_length;
	char salt[SALT_SIZE];
};

static void scheme_info_t_init(scheme_info_t *scheme, __global uchar* s, uint m, uint p, uchar l)
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
			blake2b(out_buffer, in_buffer, NULL, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
			memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			toproduce -= BLAKE2B_OUTBYTES / 2;
		}
		memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
		blake2b(out_buffer, in_buffer, NULL, toproduce, BLAKE2B_OUTBYTES, 0);
		memcpy(out, out_buffer, toproduce);

	}
	return 0;
}

static int blake2b_long_g(__global uchar *out, const void *in, const uint outlen, const ulong inlen)
{
	uint toproduce;
	blake2b_state blake_state;
	if (outlen <= BLAKE2B_OUTBYTES)
	{
		blake2b_init(&blake_state, outlen);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final_g(&blake_state, out, outlen);
	}
	else
	{
		uchar out_buffer[BLAKE2B_OUTBYTES];
		uchar in_buffer[BLAKE2B_OUTBYTES];
		blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
		blake2b_update(&blake_state, (const uchar*)&outlen, sizeof(uint));
		blake2b_update(&blake_state, (const uchar *)in, inlen);
		blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
		memcpy_g(out, out_buffer, BLAKE2B_OUTBYTES / 2);
		out += BLAKE2B_OUTBYTES / 2;
		toproduce = outlen - BLAKE2B_OUTBYTES / 2;
		while (toproduce > BLAKE2B_OUTBYTES)
		{
			memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
			blake2b(out_buffer, in_buffer, NULL, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
			memcpy_g(out, out_buffer, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			toproduce -= BLAKE2B_OUTBYTES / 2;
		}
		memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
		blake2b(out_buffer, in_buffer, NULL, toproduce, BLAKE2B_OUTBYTES, 0);
		memcpy_g(out, out_buffer, toproduce);

	}
	return 0;
}

static void ComputeBlock(ulong *v, uchar* ref_block_ptr, uchar* next_block_ptr)
{
	ulong ref_block[128];
	uchar i;

	for (i = 0; i < 128; i++)
	{
		ref_block[i] = ((ulong *)ref_block_ptr)[i];
	}


	for (i = 0; i < 128; i++)
	{
		ref_block[i] = v[i] = v[i]^ref_block[i]; //XORing the reference block to the state and storing the copy of the result
	}

	// BLAKE2 - begin
	for (i = 0; i < 8; ++i)//Applying Blake2 on columns of 64-bit words: (0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
	{

		BLAKE2_ROUND_NOMSG(v[16 * i], v[16 * i + 1], v[16 * i + 2], v[16 * i + 3], v[16 * i + 4],
			v[16 * i + 5], v[16 * i + 6], v[16 * i + 7], v[16 * i + 8], v[16 * i + 9], v[16 * i + 10],
			v[16 * i + 11], v[16 * i + 12], v[16 * i + 13], v[16 * i + 14], v[16 * i + 15]);
	}
	for (i = 0; i < 8; i++) //(0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
	{
		BLAKE2_ROUND_NOMSG(v[2*i], v[2*i + 1], v[2*i + 16], v[2*i + 17], v[2*i + 32], v[2*i + 33], v[2*i + 48],
			v[2*i + 49], v[2*i + 64], v[2*i + 65], v[2*i + 80], v[2*i + 81], v[2*i + 96], v[2*i + 97],
			v[2*i + 112], v[2*i + 113]);
	}// BLAKE2 - end


	for (i = 0; i< 128; i++)
	{
		v[i] = v[i] ^ ref_block[i]; //Feedback
		((ulong *) next_block_ptr)[i]= v[i];
	}
}

static void ComputeBlock_pgg(ulong *v, __global uchar* ref_block_ptr, __global uchar* next_block_ptr)
{
	ulong ref_block[128];
	uchar i;

	for (i = 0; i < 128; i++)
	{
		ref_block[i] = ((__global ulong *)ref_block_ptr)[i];
	}


	for (i = 0; i < 128; i++)
	{
		ref_block[i] = v[i] = v[i]^ref_block[i]; //XORing the reference block to the state and storing the copy of the result
	}

	// BLAKE2 - begin
	for (i = 0; i < 8; ++i)//Applying Blake2 on columns of 64-bit words: (0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
	{

		BLAKE2_ROUND_NOMSG(v[16 * i], v[16 * i + 1], v[16 * i + 2], v[16 * i + 3], v[16 * i + 4],
			v[16 * i + 5], v[16 * i + 6], v[16 * i + 7], v[16 * i + 8], v[16 * i + 9], v[16 * i + 10],
			v[16 * i + 11], v[16 * i + 12], v[16 * i + 13], v[16 * i + 14], v[16 * i + 15]);
	}
	for (i = 0; i < 8; i++) //(0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
	{
		BLAKE2_ROUND_NOMSG(v[2*i], v[2*i + 1], v[2*i + 16], v[2*i + 17], v[2*i + 32], v[2*i + 33], v[2*i + 48],
			v[2*i + 49], v[2*i + 64], v[2*i + 65], v[2*i + 80], v[2*i + 81], v[2*i + 96], v[2*i + 97],
			v[2*i + 112], v[2*i + 113]);
	}// BLAKE2 - end


	for (i = 0; i< 128; i++)
	{
		v[i] = v[i] ^ ref_block[i]; //Feedback
		((__global ulong *) next_block_ptr)[i]= v[i];
	}
}

static void Initialize(scheme_info_t* info,uchar* input_hash)
{
	uchar l;
	uchar block_input[BLAKE_INPUT_HASH_SIZE + 8];
	uint segment_length = (info->mem_size / (SYNC_POINTS*(info->lanes)));
	memcpy(block_input, input_hash, BLAKE_INPUT_HASH_SIZE);
	memset(block_input + BLAKE_INPUT_HASH_SIZE, 0, 8);
	for (l = 0; l < info->lanes; ++l)
	{
		block_input[BLAKE_INPUT_HASH_SIZE + 4] = l;
		block_input[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long_g(info->state + l * segment_length*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		block_input[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long_g(info->state + (l * segment_length + 1)*BLOCK_SIZE, block_input, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(block_input, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

static void Finalize(uchar *state, uchar* out, uint outlen, uchar lanes, uint m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	uchar l;
	uint j;
	ulong blockhash[BLOCK_SIZE/sizeof(ulong)];
	memset(blockhash, 0, BLOCK_SIZE);
	for (l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint segment_length = m_cost / (SYNC_POINTS*lanes);
		uchar* block_ptr = state + (((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE; //points to the last block of the first lane

		for (j = 0; j < BLOCK_SIZE / sizeof(ulong); ++j)
		{
			blockhash[j] = blockhash[j]^( *(ulong*)block_ptr);
			block_ptr += sizeof(ulong);
		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);
}

static void Finalize_g(__global uchar *state, uchar* out, uint outlen, uchar lanes, uint m_cost)//XORing the last block of each lane, hashing it, making the tag.
{
	uchar l;
	uint j;
	ulong blockhash[BLOCK_SIZE/sizeof(ulong)];
	memset(blockhash, 0, BLOCK_SIZE);
	for (l = 0; l < lanes; ++l)//XORing all last blocks of the lanes
	{
		uint segment_length = m_cost / (SYNC_POINTS*lanes);
		__global uchar* block_ptr = state + (((SYNC_POINTS - 1)*lanes+l+1)*segment_length-1)*BLOCK_SIZE; //points to the last block of the first lane

		for (j = 0; j < BLOCK_SIZE / sizeof(ulong); ++j)
		{
			blockhash[j] = blockhash[j]^( *(__global ulong*)block_ptr);
			block_ptr += sizeof(ulong);
		}
	}
	blake2b_long(out, blockhash, outlen, BLOCK_SIZE);
}

static void GenerateAddresses(const scheme_info_t* info, position_info_t* position, uint* addresses)//generate 256 addresses
{
	uint i;
	uchar zero_block[BLOCK_SIZE];
	uint input_block[BLOCK_SIZE/4];
	uint segment_length;
	uint barrier1; //Number of blocks generated in previous slices
	uint barrier2; //Number of blocks that we can reference in total (including the last blocks of each lane
	uint start = 0;
	memset(zero_block, 0,BLOCK_SIZE);
	memset(input_block, 0, 256 * sizeof(uint));
	input_block[0] = position->pass;
	input_block[1] = position->lane;
	input_block[2] = position->slice;
	input_block[3] = position->index;
	input_block[4] = 0xFFFFFFFF;
	ComputeBlock((ulong*)input_block, zero_block, (uchar*)addresses);
	ComputeBlock((ulong*)zero_block, (uchar*)addresses, (uchar*)addresses);


	/*Making block offsets*/
	segment_length = info->mem_size / ((info->lanes)*SYNC_POINTS);
	barrier1 = (position->slice) * segment_length*(info->lanes);

	if (position->pass == 0)//Including later slices for second and later passes
	{
		barrier2 = barrier1;
		if (position->slice == 0 && position->index==0)
			start = 2;
	}
	else
		barrier2 = barrier1 + (SYNC_POINTS - position->slice - 1) *  segment_length*(info->lanes);

	if (position->index == 0 && start==0)/*Special rule for first block of the segment, if not very first blocks*/
	{
		uint r = barrier2 - (info->lanes);
		uint reference_block_index = addresses[0] % r;
		uint prev_block_recalc = (position->slice > 0) ? ((position->slice - 1)*(info->lanes)*segment_length) : (SYNC_POINTS - 2)*(info->lanes)*segment_length;

		/*Shifting <reference_block_index> to have gaps in the last blocks of each lane*/
		if (reference_block_index >= prev_block_recalc)
		{
			uint shift = (reference_block_index - prev_block_recalc) / (segment_length - 1);
			reference_block_index += (shift > info->lanes) ? info->lanes : shift;
		}
		if (reference_block_index < barrier1)
			addresses[0] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[0] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[0] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
		start = 1;
	}

	for (i = start; i < ADDRESSES_PER_BLOCK; ++i)
	{
		uint r = barrier2 + (position->index)*ADDRESSES_PER_BLOCK+i - 1;
		uint reference_block_index = addresses[i] % r;
		//Mapping the reference block address into the memory
		if (reference_block_index < barrier1)
			addresses[i] = reference_block_index*BLOCK_SIZE;
		else
		{
			if (reference_block_index >= barrier1 && reference_block_index < barrier2)
				addresses[i] = (reference_block_index + segment_length*(info->lanes)) * BLOCK_SIZE;
			else
				addresses[i] = (reference_block_index - (barrier2 - barrier1) + (position->lane) *  segment_length) * BLOCK_SIZE;
		}
	}
}

static void FillSegment(const scheme_info_t* info, const position_info_t position)
{
	uint i;
	ulong prev_block[128];
	uint addresses[ADDRESSES_PER_BLOCK];
	uint next_block_offset;
	__global uchar *memory = info->state;
	uint pass = position.pass;
	uint slice = position.slice;
	uchar lane = position.lane;
	uchar lanes = info->lanes;
	uint m_cost = info->mem_size;
	position_info_t position_local = position;

	uint segment_length = m_cost / (lanes*SYNC_POINTS);
	//uint stop = segment_length;//Number of blocks to produce in the segment, is different for the first slice, first pass
	uint start=0;

	uint prev_block_offset; //offset of previous block

	if(0 == pass && 0 == slice) // First pass; first slice
	{
		uint bi;
		uint reference_block_offset;

		start += 3;
		if (segment_length <= 2)
			return;

		bi = prev_block_offset = (lane * segment_length + 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 128; i++)
		{
			prev_block[i] = *(__global ulong *) (&memory[bi]);
			bi += 8;
		}

		next_block_offset = (lane * segment_length + 2) * BLOCK_SIZE;

		reference_block_offset = (lane * segment_length) * BLOCK_SIZE;

		// compute block
		ComputeBlock_pgg(prev_block, memory+ reference_block_offset, memory+next_block_offset);//Computing third block in the segment
		position_local.index = 0;
		GenerateAddresses(info, &position_local, addresses);
	}
	else
	{
		uint prev_slice = (slice>0)?(slice-1):(SYNC_POINTS-1);
		uint bi = prev_block_offset = ((prev_slice * lanes + lane + 1) * segment_length - 1) * BLOCK_SIZE;//<bi> -- temporary variable for loading previous block
		for (i = 0; i < 128; i++)
		{
			prev_block[i] = *(__global ulong *) (&memory[bi]);
			bi += 8;
		}
	}

	next_block_offset = ((slice*lanes + lane)*segment_length + start)*BLOCK_SIZE;
	for(i = start; i < segment_length; i++)
	{
		// compute block
		if ((i&ADDRESSES_MASK) == 0)
		{
			position_local.index = i / ADDRESSES_PER_BLOCK;
			GenerateAddresses(info, &position_local, addresses);
		}
		ComputeBlock_pgg(prev_block, memory+addresses[i&ADDRESSES_MASK], memory + next_block_offset);
		next_block_offset += BLOCK_SIZE;
	}
}



static void FillMemory(const scheme_info_t* info)//Main loop: filling memory <t_cost> times
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


static int Argon2i(__global uchar *out, uint outlen, const uchar *msg, uint msglen, const uchar *nonce, uint noncelen, const uchar *secret,
	uchar secretlen, const uchar *ad, uint adlen, uint t_cost, uint m_cost, uchar lanes, __global void *memory)
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
	if (msglen < MIN_MSG)
		return -2; //Password too short

	if (noncelen < MIN_NONCE)
		return -3; //Salt too short
	if (noncelen> MAX_NONCE)
		noncelen = MAX_NONCE;

	if (secretlen> MAX_SECRET)
		secretlen = MAX_SECRET;
	if (secretlen < MIN_SECRET)
		return -4; //Secret too short

	if (adlen> MAX_AD)
		adlen = MAX_AD;
	if (adlen < MIN_AD)
		return -5; //Associated data too short

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (m_cost < 2 * SYNC_POINTS*(uint)lanes)
		m_cost = 2 * SYNC_POINTS*(uint)lanes;
	if (m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;

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


__kernel void argon2i_crypt_kernel(__global const uchar * in,
    __global const uint * index,
    __global char *out,
    __global struct argon2i_salt *salt,
    __global uchar *memory
)
{
	uint i;
	uint gid;
	uint GID;

	uint m_cost, t_cost;
	uchar lanes;
	uint outlen, noncelen;

	uint base, inlen;

	uchar passwd[PLAINTEXT_LENGTH];
	uchar nonce[SALT_SIZE];

	gid = get_global_id(0);

	out += gid * BINARY_SIZE;

	base = index[gid];
	inlen = index[gid + 1] - base;

	outlen = salt->hash_size;
	noncelen = salt->salt_length;

	t_cost = salt->t_cost;
	m_cost = salt->m_cost;
	lanes=salt->lanes;

	in += base;
	memory=(__global uchar*)memory+gid*(((ulong)m_cost)<<10);

	//copying password
	for(i=0;i<inlen;i++)
		passwd[i]=in[i];

	//copying salt
	for(i=0;i<noncelen;i++)
		nonce[i]=salt->salt[i];

	Argon2i(out, outlen, passwd, inlen, nonce, noncelen, NULL, 0, NULL, 0, t_cost, m_cost, lanes, memory);
}
