/*Argon2 Reference Implementation
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
#include "argon2d-ref.h"

#define BLOCK(lane,slice,index) ((index)+(lane)*segment_length+(slice)*segment_length*lanes)

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





static void FillSegment(block* state, uint32_t m_cost, uint8_t lanes, uint32_t round, uint8_t lane, uint8_t slice)//Filling "slice" in "lane" and "round"
{
	uint32_t i = 0;
	uint32_t segment_length = m_cost /(lanes* (uint32_t)SYNC_POINTS);   //Computing length of the slice
	uint32_t reference_area_size;//Number of blocks outside of the slice to reference
	uint32_t pseudo_rand, ref_index, ref_lane, ref_slice;
	block prev_block;  //previous block

	/*Computing number of blocks to reference, except current slice*/
	if (round == 0)
	{
		reference_area_size = lanes*slice*segment_length;
	}
	else
		reference_area_size = lanes*(SYNC_POINTS-1)*segment_length;
	
	//Filling blocks, preparing macro for referencing blocks in memory
	for (i = 0; i < segment_length; ++i)
	{
		uint32_t prev_index;
		uint32_t recalculation_start=0;
		uint32_t total_area;
		uint32_t *ptr;
		block ref_block;
		block* next_block;

		/*0.Computing addresses if necessary*/
		if ((round == 0) && (slice == 0) && (i < 2)) //skip first two blocks
			continue;

		/*Reading previous block*/
		if ((round == 0) && (slice == 0) && (i == 2))
			prev_index = BLOCK(lane, 0, 1);
		if (i == 0)//not round 0, slice 0
		{
			if (slice == 0)
			{
				recalculation_start = BLOCK(0, SYNC_POINTS - 2, 0);
				prev_index = BLOCK(lane, SYNC_POINTS - 1, segment_length - 1);
			}
			else
			{
				recalculation_start = BLOCK(0, slice - 1, 0);
				prev_index = BLOCK(lane, slice - 1, segment_length - 1);
			}
		}
		else prev_index = BLOCK(lane, slice, i - 1);
		prev_block = state[prev_index];

		/*1. Computing the reference block*/
		/*1.1 Taking pseudo-random value from the previous block */
		ptr=(uint32_t*)prev_block.v;
		pseudo_rand = ptr[0];
		/*1.2 Computing reference block location*/
		total_area = (i == 0) ? (reference_area_size - lanes) : (reference_area_size + i - 1); //Excluding previous blocks and other last segment blocks if necessary
		pseudo_rand %= total_area;
		if (i == 0)
		{
			if (pseudo_rand > recalculation_start)//we are in the previous slice and have to recalculate
			{
				uint32_t recalc_shift = (pseudo_rand - recalculation_start)/(segment_length-1);
				pseudo_rand += (recalc_shift > lanes) ? (lanes) : recalc_shift; //Adding "missed" blocks to correctly locate reference block in the memory
			}
		}
		/*if ((i == 0) && ((pseudo_rand >= prev_index) && (slice>0) ||
			(pseudo_rand + m_cost / SYNC_POINTS >= prev_index) && (slice==0)))//If previous block is in another segment
				pseudo_rand++;*/
		if (pseudo_rand>=reference_area_size)
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
		/*2.Creating a new block*/
		ref_block = state[BLOCK(ref_lane,ref_slice,ref_index)];  //random block from memory
		
		next_block = &(state[BLOCK(lane, slice, i)]);
		//printf("Ref: %.2d Next:%.2d\n", (ref_block - state) / BYTES_IN_BLOCK, (next_block - state) / BYTES_IN_BLOCK);
		MakeBlock(&prev_block, &ref_block, next_block);  //Create new block
		
	}

}

static void Initialize(uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes, void *memory)
{
	block* state=(block*) memory;
	uint8_t l;
	uint32_t segment_length;

	//Initial hashing
	uint8_t blockhash[BLAKE_INPUT_HASH_SIZE + 8];//H_0 in the document
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
		blake2b_long((uint8_t*)&(state[l*segment_length]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
		blockhash[BLAKE_INPUT_HASH_SIZE] = 1;
		blake2b_long((uint8_t*)&(state[l*segment_length + 1]), blockhash, BLOCK_SIZE, BLAKE_INPUT_HASH_SIZE + 8);
	}
	memset(blockhash, 0, BLAKE_INPUT_HASH_SIZE + 8);
}

static void Finalize(block* state, uint8_t *out, uint32_t outlen, uint32_t m_cost, uint8_t lanes)//XORing the last block of each lane, hashing it, making the tag.
{
	uint8_t l;
	block blockhash;
	uint32_t segment_length = m_cost / (lanes* (uint32_t)SYNC_POINTS);

	block_init(&blockhash);
	for (l = 0; l < lanes; ++l)
	{
		blockhash = block_xor(&blockhash,&(state[BLOCK(l, SYNC_POINTS - 1, segment_length - 1)]));
	}

	blake2b_long(out, blockhash.v, outlen, BLOCK_SIZE);
}

static void FillMemory(block* state, uint32_t t_cost, uint32_t m_cost, uint8_t lanes) //Main loop: filling memory <t_cost> times
{
	uint8_t r, s, l;
	for (r = 0; r < t_cost; ++r)
	{
		for (s = 0; s < SYNC_POINTS; ++s)
		{
			for (l = 0; l < lanes; ++l)
			{
				FillSegment(state, m_cost, lanes, r, l, s);
			}
		}
	}
}

int Argon2dRef(uint8_t *out, uint32_t outlen, const uint8_t *msg, uint32_t msglen, const uint8_t *nonce, uint32_t noncelen, const uint8_t *secret,
	uint8_t secretlen, const uint8_t *ad, uint32_t adlen, uint32_t t_cost, uint32_t m_cost, uint8_t lanes, void *memory)
{
	block* state=(block*) memory;

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

	if (lanes<MIN_LANES)
		lanes = MIN_LANES;
	if (lanes>m_cost / BLOCK_SIZE_KILOBYTE)
		lanes = m_cost / BLOCK_SIZE_KILOBYTE;

	/*1. Initialization: Hashing inputs, allocating memory, filling first blocks*/
	Initialize( outlen, msg, msglen, nonce, noncelen, secret, secretlen, ad, adlen, t_cost, m_cost, lanes, memory);//

	/*2. Filling memory */
	FillMemory(state, t_cost, m_cost, lanes);
	

	/*3. Finalization*/
	Finalize(state,out,outlen,m_cost,lanes);
	return 0;
}
int ARGON2d_REF(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, uint8_t lanes, void *memory)
{
	return Argon2dRef((uint8_t*)out, (uint32_t)outlen, (const uint8_t*)in, (uint32_t)inlen, (const uint8_t*)salt, (uint32_t)saltlen, NULL, 0, NULL, 0, (uint32_t)t_cost, (uint32_t)m_cost, lanes, memory);
}
