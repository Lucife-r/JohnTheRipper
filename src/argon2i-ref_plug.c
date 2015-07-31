/*Argon2i Reference Implementation
  Code written by Dmitry Khovratovich in 2015.
  khovratovich@gmail.com
  modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>*/


#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <time.h> 

#include <string.h>

#include "blake2-round-no-msg.h"
#include "blake2-impl.h"
#include "blake2.h"
#include "argon2i-ref.h"


#define BLOCK(lane,slice,index) ((index)+(lane)*segment_length+(slice)*segment_length*(info->lanes))

static void block_init(block *b)
{ 
	memset(b->v, 0, BYTES_IN_BLOCK); 
}

static block block_xor(block *b, const block* r)
{
	block a;
	unsigned int j;
	for (j = 0; j < BYTES_IN_BLOCK; ++j)
		a.v[j] = b->v[j] ^ r->v[j];
	return a; 
}

static void scheme_info_t_init(scheme_info_t* scheme, block* s, uint32_t m, uint32_t p, uint32_t l)
{ 
	scheme->state = s;
	scheme->mem_size = m;
	scheme->passes = p;
	scheme->lanes = l; 
}

static void position_info_t_init(position_info_t* position, uint32_t p, uint8_t s, uint8_t l, uint32_t i)
{ 
	position->pass = p;
	position->slice = s;
	position->lane = l;
	position->index = i; 
}

static int blake2b_long(uint8_t *out, const void *in, const uint32_t outlen, const uint64_t inlen)
{
	blake2b_state blake_state;
	if (outlen <= BLAKE2B_OUTBYTES)
	{
		blake2b_init(&blake_state, outlen);
		blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
		blake2b_update(&blake_state, (const uint8_t *)in, inlen);
		blake2b_final(&blake_state, out, outlen);
	}
	else
	{
		uint32_t toproduce;
		uint8_t out_buffer[BLAKE2B_OUTBYTES];
		uint8_t in_buffer[BLAKE2B_OUTBYTES];
		blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
		blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
		blake2b_update(&blake_state, (const uint8_t *)in, inlen);
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


static void MakeBlock(block* prev_block, block* ref_block, block* next_block)
{
	block blockR = block_xor(prev_block, ref_block);
	block blocktmp = blockR;
	unsigned int i;
	uint64_t * v=(uint64_t *)blockR.v;
	
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


	*next_block = block_xor(&blockR, &blocktmp);
}


static void GenerateAddresses(const scheme_info_t* info, position_info_t* position, uint32_t* addresses)//generate 256 addresses 
{
	uint32_t i;
	uint8_t lanes, slice, lane;
	uint32_t segment_length;
	uint32_t reference_area_size; //Number of blocks outside of the slice to reference
	uint32_t ref_index, ref_lane, ref_slice;
	block zero_block, input_block, address_block;
	uint32_t pseudo_rand, total_area;
	uint32_t *ptr=(uint32_t*) input_block.v;

	block_init(&zero_block);
	block_init(&input_block);
	block_init(&address_block);
	ptr[0] = position->pass;
	ptr[1] = position->lane;
	ptr[2] = position->slice;
	ptr[3] = position->index;
	ptr[4] = 0xFFFFFFFF;
	MakeBlock(&zero_block, &input_block, &address_block);
	MakeBlock(&zero_block, &address_block, &address_block);
	lanes = info->lanes;
	slice = position->slice;
	lane = position->lane;

	/*Making block offsets*/
	segment_length = info->mem_size / ((info->lanes)*SYNC_POINTS);
	/*Computing number of blocks to reference, except current slice*/
	if (position->pass == 0)
	{
		reference_area_size = lanes*slice*segment_length;
	}
	else
		reference_area_size = lanes*(SYNC_POINTS - 1)*segment_length;

	//Filling blocks, preparing macro for referencing blocks in memory

	for (i = 0; i < ADDRESSES_PER_BLOCK; ++i)
	{
		if (position->slice == 0 && position->pass == 0 && position->index==0&& i <2)
			continue;
		pseudo_rand = ((uint32_t*)address_block.v)[i];
		total_area = reference_area_size  +(position->index)*ADDRESSES_PER_BLOCK+ i - 1;
		if (position->index == 0 && i == 0) //Special rule for the first block of the segment, except for the very beginning (i==0 is skipped in the first slice, first pass)
		{
			uint32_t recalculation_start = 0;
			total_area -= lanes - 1; //Excluding last blocks of the other lanes
			pseudo_rand %= total_area;
			if (slice == 0)
				recalculation_start = BLOCK(0, SYNC_POINTS - 2, 0);
			else
				recalculation_start = BLOCK(0, slice - 1, 0);
			if (pseudo_rand > recalculation_start)//we are in the previous slice and have to recalculate
			{
				uint32_t recalc_shift = (pseudo_rand - recalculation_start) / (segment_length - 1);
				pseudo_rand += (recalc_shift > lanes) ? (lanes) : recalc_shift; //Adding "missed" blocks to correctly locate reference block in the memory
			}
		}
		else
			pseudo_rand %= total_area;
		//Mapping pseudo_rand to the memory
		if (pseudo_rand >= reference_area_size)
		{
			ref_index = pseudo_rand - reference_area_size;
			ref_slice = slice;
			ref_lane = lane;
		}
		else //Reference block is in other slices, in all lanes
		{
			ref_slice = pseudo_rand / (lanes*segment_length);
			ref_lane = (pseudo_rand / segment_length) % lanes;
			ref_index = pseudo_rand%segment_length;
			if (ref_slice >= slice) //This means we refer to next lanes in a previous pass
				ref_slice++;
		}
		addresses[i] = BLOCK(ref_lane, ref_slice, ref_index);
	}
}


static void FillSegment(const scheme_info_t* info, position_info_t* position)//Filling "slice" in "lane" and "round"
{
	uint32_t i;
	uint32_t segment_length = info->mem_size /(info->lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice
	uint8_t slice = position->slice;
	uint8_t lane = position->lane;
	uint32_t pass = position->pass;
	uint32_t addresses[ADDRESSES_PER_BLOCK];
	block prev_block;  //previous block
	
	block_init(&prev_block);
	for (i = 0; i < segment_length; ++i)
	{
		uint32_t prev_index;
		block ref_block;
		block* next_block;
		block_init(&ref_block);
		/*0.Computing addresses if necessary*/
		if (i%ADDRESSES_PER_BLOCK == 0)
		{
			position->index = i / ADDRESSES_PER_BLOCK;
			GenerateAddresses(info, position, addresses);
		}
		/*1. First blocks*/
		if ((position->pass == 0) && (position->slice == 0) && (i < 2)) //skip first two blocks
			continue;

		/*2. Previous block*/
		if ((pass == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			else
				prev_index = BLOCK(lane, slice - 1, segment_length - 1);
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = info->state[prev_index];
		
		/*2.Creating a new block*/
		ref_block = info->state[addresses[i%ADDRESSES_PER_BLOCK]];  //pseudo-random block from memory
		
		next_block = &(info->state[BLOCK(position->lane, position->slice, i)]);
		MakeBlock(&prev_block, &ref_block, next_block);  //Create new block
		
	}

}

static block* Initialize(uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes, block *state)
{
	uint32_t segment_length;
	uint8_t l;
	//Initial hashing
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE+8];//H_0 in the document
	uint8_t version = VERSION_NUMBER;
	blake2b_state BlakeHash;
	blake2b_init(&BlakeHash, BLAKE_INPUT_HASH_SIZE);

	blake2b_update(&BlakeHash, (const uint8_t*)&lanes, sizeof(lanes));
	blake2b_update(&BlakeHash, (const uint8_t*)&outlen, sizeof(outlen));
	blake2b_update(&BlakeHash, (const uint8_t*)&m_cost, sizeof(m_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&t_cost, sizeof(t_cost));
	blake2b_update(&BlakeHash, (const uint8_t*)&version, sizeof(version));
	blake2b_update(&BlakeHash, (const uint8_t*)&msglen, sizeof(msglen));
	blake2b_update(&BlakeHash, (const uint8_t*)msg, msglen);
	blake2b_update(&BlakeHash, (const uint8_t*)&noncelen, sizeof(noncelen));
	blake2b_update(&BlakeHash, (const uint8_t*)nonce, noncelen);
	blake2b_update(&BlakeHash, (const uint8_t*)&secretlen, sizeof(secretlen));
	blake2b_update(&BlakeHash, (const uint8_t*)secret, secretlen);
	blake2b_update(&BlakeHash, (const uint8_t*)&adlen, sizeof(adlen));
	blake2b_update(&BlakeHash, (const uint8_t*)ad, adlen);


	blake2b_final(&BlakeHash, blockhash, BLAKE_INPUT_HASH_SIZE);
	memset(blockhash + BLAKE_INPUT_HASH_SIZE, 0, 8);

	//Creating first blocks, we always have at least two blocks in a slice
	
	segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);
	for (l = 0; l < lanes; ++l)
	{
		blockhash[BLAKE_INPUT_HASH_SIZE + 4] = l;
		blockhash[BLAKE_INPUT_HASH_SIZE] = 0;
		blake2b_long((uint8_t*)&(state[l*segment_length]),blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		blockhash[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uint8_t*)&(state[l*segment_length + 1]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE + 8);
	return state;
}

static void Finalize(scheme_info_t* info, uint8_t *out, uint32_t outlen)//XORing the last block of each lane, hashing it, making the tag.
{
	block blockhash;
	uint32_t segment_length = info->mem_size/ (info->lanes* (uint32_t)SYNC_POINTS);
	uint8_t l;

	block_init(&blockhash);
	for (l = 0; l < info->lanes; ++l)
	{
		blockhash = block_xor(&blockhash, &(info->state[BLOCK(l, SYNC_POINTS - 1, segment_length - 1)]));
	}
	blake2b_long(out, blockhash.v, outlen, BLOCK_SIZE);	
}

static void FillMemory(scheme_info_t* info) //Main loop: filling memory <t_cost> times
{
	uint32_t r,s,l;
	for (r = 0; r < info->passes; ++r)
	{
		for (s = 0; s < SYNC_POINTS; ++s)
		{
			for (l = 0; l < info->lanes; ++l)
			{
				position_info_t position;
				position_info_t_init(&position, r, s, l, 0);
				FillSegment(info,&position);
			}
		}
	}
}

int Argon2iRef(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes, void *memory)
{
	block* state = (block *) memory;
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
	if (m_cost < 2 * SYNC_POINTS*lanes)
		m_cost=2 * SYNC_POINTS*lanes;
	if (m_cost>MAX_MEMORY)
		m_cost = MAX_MEMORY;

	m_cost = (m_cost / (lanes*SYNC_POINTS))*(lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =1
	if (t_cost<MIN_TIME)
		t_cost = MIN_TIME;

	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;
	if (lanes<MIN_LANES)
		lanes = MIN_LANES;


	/*1. Initialization: Hashing inputs, allocating memory, filling first blocks*/
	Initialize( outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes, state);

	scheme_info_t_init(&info, state, m_cost, t_cost, lanes);
	/*2. Filling memory */
	FillMemory(&info);
	

	/*3. Finalization*/
	Finalize(&info, out, outlen);
	return 0;
}

int ARGON2i_REF(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
	 unsigned int t_cost, unsigned int m_cost, uint8_t lanes, void *memory)
 {
	return Argon2iRef((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, lanes, memory);
 }
