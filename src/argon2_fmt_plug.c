/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_argon2i;
extern struct fmt_main fmt_argon2d;
extern struct fmt_main fmt_argon2id;
extern struct fmt_main fmt_argon2ds;
#elif FMT_REGISTERS_H
john_register_one(&fmt_argon2i);
john_register_one(&fmt_argon2d);
john_register_one(&fmt_argon2id);
john_register_one(&fmt_argon2ds);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"

#include "stdbool.h"
#include "argon2.h"
#include "argon2-core.h"

#include "memdbg.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL_i			"argon2i"
#define FORMAT_LABEL_d			"argon2d"
#define FORMAT_LABEL_id			"argon2id"
#define FORMAT_LABEL_ds			"argon2ds"
#define FORMAT_NAME			""

#if defined(__XOP__)
#define ALGORITHM_NAME			"Blake2 XOP"
#elif defined(__AVX__)
#define ALGORITHM_NAME			"Blake2 AVX"
#elif defined(__SSSE3__)
#define ALGORITHM_NAME			"Blake2 SSSE3"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"Blake2 SSE2"
#else
#define ALGORITHM_NAME			"Blake2"
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0
#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		BINARY_SIZE*2
#define BINARY_SIZE			256
#define BINARY_ALIGN			1
#define SALT_SIZE			64
#define SALT_ALIGN			1
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#define OMP_SCALE			1
#define ARGON_ALIGN			64

#ifdef _OPENMP
#define THREAD_NUMBER omp_get_thread_num()
#else
#define THREAD_NUMBER 1
#endif

#define PREFIX_i			"$argon2i$"
#define PREFIX_d			"$argon2d$"
#define PREFIX_id			"$argon2id$"
#define PREFIX_ds			"$argon2ds$"

static struct fmt_tests tests_i[] = {
	{"$argon2i$3$1536$1$damage_done$DC62B7B469BDF17DB335062CDCEF7F565700B414D5EBEE2431D86001BC21385E","cathode_ray_sunshine"},
	{"$argon2i$3$1536$1$damage_done$DC62B7B469BDF17DB335062CDCEF7F565700B414D5EBEE2431D86001BC21385E","cathode_ray_sunshine"},
	{NULL}
};

static struct fmt_tests tests_d[] = {
	{"$argon2d$3$1536$1$damage_done$248B76AE28BC53BAC90DDCEE5FC5EDF5202ADCA4EEED247422B9884A08F27F07","cathode_ray_sunshine"},
	{"$argon2d$3$1536$1$damage_done$248B76AE28BC53BAC90DDCEE5FC5EDF5202ADCA4EEED247422B9884A08F27F07","cathode_ray_sunshine"},
	{NULL}
};

static struct fmt_tests tests_id[] = {
	{"$argon2id$3$1536$1$damage_done$BCB4FA53A26DED26B15C4E38204548BC7B3069AFB3922A8B564A2AE1061E14BF","cathode_ray_sunshine"},
	{"$argon2id$3$1536$1$damage_done$BCB4FA53A26DED26B15C4E38204548BC7B3069AFB3922A8B564A2AE1061E14BF","cathode_ray_sunshine"},
	{NULL}
};

static struct fmt_tests tests_ds[] = {
	{"$argon2ds$3$1536$1$damage_done$B8E1B34ECA81A366CA5EC166BB1EC0079106846C3591F1635441016726D27B07","cathode_ray_sunshine"},
	{"$argon2ds$3$1536$1$damage_done$B8E1B34ECA81A366CA5EC166BB1EC0079106846C3591F1635441016726D27B07","cathode_ray_sunshine"},
	{NULL}
};

struct argon2_salt {
	uint32_t t_cost;
	uint32_t m_cost;
	uint32_t lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

struct argon2_salt saved_salt;
static region_t * memory;
static region_t * Sbox;
static region_t pseudo_rands;

static char *saved_key;
static int threads;
static uint64_t saved_mem_size;
static uint64_t saved_pseudo_rands_size;
static uint64_t pseudo_rands_size;

int prev_m_cost;

static unsigned char *crypted;

static void *get_salt(char *ciphertext);

static void init(struct fmt_main *self)
{
	int i;
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	threads=omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#else
	threads=1;
#endif
	saved_key =
	    malloc(self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	memset(saved_key, 0,
	    self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	crypted = malloc(self->params.max_keys_per_crypt * (BINARY_SIZE));
	memset(crypted, 0, self->params.max_keys_per_crypt * (BINARY_SIZE));

	memory=malloc(threads*sizeof(region_t));
	for(i=0;i<threads;i++)
		init_region(&memory[i]);
	
	init_region(&pseudo_rands);

	saved_mem_size=pseudo_rands_size=saved_pseudo_rands_size=0;
}

static void init_ds(struct fmt_main *self)
{
	int i;
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	threads=omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#else
	threads=1;
#endif
	saved_key =
	    malloc(self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	memset(saved_key, 0,
	    self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	crypted = malloc(self->params.max_keys_per_crypt * (BINARY_SIZE));
	memset(crypted, 0, self->params.max_keys_per_crypt * (BINARY_SIZE));

	memory=malloc(threads*sizeof(region_t));
	for(i=0;i<threads;i++)
		init_region(&memory[i]);
	
	init_region(&pseudo_rands);

	Sbox=malloc(threads*sizeof(region_t));
	for(i=0;i<threads;i++)
	{
		init_region(&Sbox[i]);
		alloc_region(&Sbox[i],sizeof(uint64_t)*ARGON2_SBOX_SIZE);
	}
	//printf("%d\n",sizeof(uint64_t)*ARGON2_SBOX_SIZE);
	saved_mem_size=pseudo_rands_size=saved_pseudo_rands_size=0;
}

static void done(void)
{
	int i;
	free(saved_key);
	free(crypted);
	for(i=0;i<threads;i++)
		free_region(&memory[i]);
	free(memory);
	free_region(&pseudo_rands);
}

static void done_ds(void)
{
	int i;
	free(saved_key);
	free(crypted);
	for(i=0;i<threads;i++)
		free_region(&memory[i]);
	for(i=0;i<threads;i++)
		free_region(&Sbox[i]);
	free(memory);
	free(Sbox);
	free_region(&pseudo_rands);
}

static void print_memory(double memory)
{
	char s[]="\0kMGT";
	int i=0;
	while(memory>=1024)
	{
		memory/=1024;
		i++;
	}
	printf("memory per hash : %.2lf %cB\n",memory,s[i]);
}

static void reset(struct db_main *db, struct fmt_tests *tests)
{
	static int printed=0;
	if(!printed)
	{
		int i;
		uint32_t m_cost, prev_m_cost;
		m_cost=prev_m_cost=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct argon2_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				m_cost = MAX(m_cost, salt->m_cost);
				if(i==0)
				{
					printf("\n");
					prev_m_cost=m_cost;
					print_memory(m_cost<<10);
				}
			}

			if(prev_m_cost!=m_cost)
			{
				printf("max ");
				print_memory(m_cost<<10);
			}
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct argon2_salt * salt=salts->salt;
				m_cost = MAX(m_cost, salt->m_cost);
				salts = salts->next;
			}

			printf("\n");
			print_memory(m_cost<<10);
		}
	}
}


static void reset_i(struct db_main *db)
{
	reset(db, tests_i);
}

static void reset_d(struct db_main *db)
{
	reset(db, tests_d);
}

static void reset_id(struct db_main *db)
{
	reset(db, tests_id);
}

static void reset_ds(struct db_main *db)
{
	reset(db, tests_ds);
}

static int valid(char *ciphertext, struct fmt_main *self, char *prefix)
{
	struct argon2_salt *salt;
	char *next_dollar;
	char *i;

	if (strncmp(ciphertext, prefix, strlen(prefix)))
		return 0;
	i = ciphertext + strlen(prefix);
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//lanes
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	if(atoi(i)>255)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	//
		i++;
	if (*i)
		return 0;

	salt=get_salt(ciphertext);

	if (ARGON2_MIN_OUTLEN > salt->hash_size) {
		return 0; //ARGON2_OUTPUT_TOO_SHORT;
	}
    	if (ARGON2_MAX_OUTLEN < salt->hash_size) {
		return 0; //ARGON2_OUTPUT_TOO_LONG;
	}

	if (ARGON2_MAX_SALT_LENGTH < salt->salt_length) {
  		return 0; //ARGON2_SALT_TOO_LONG;
        }

	/* Validate memory cost */
	if (ARGON2_MIN_MEMORY > salt->m_cost) {
		return 0; //ARGON2_MEMORY_TOO_LITTLE;
	}
	if (ARGON2_MAX_MEMORY < salt->m_cost) {
		return 0; //ARGON2_MEMORY_TOO_MUCH;
	}

	/* Validate time cost */
	if (ARGON2_MIN_TIME > salt->t_cost) {
		return 0; //ARGON2_TIME_TOO_SMALL;
	}
	if (ARGON2_MAX_TIME < salt->t_cost) {
		return 0; //ARGON2_TIME_TOO_LARGE;
	}

	/* Validate lanes */
	if (ARGON2_MIN_LANES > salt->lanes) {
		return 0; //ARGON2_LANES_TOO_FEW;
	}
	if (ARGON2_MAX_LANES < salt->lanes) {
		return 0; //ARGON2_LANES_TOO_MANY;
 	}

	return 1;
}

static int valid_i(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext,self,PREFIX_i);
}

static int valid_d(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext,self,PREFIX_d);
}

static int valid_id(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext,self,PREFIX_id);
}

static int valid_ds(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext,self,PREFIX_ds);
}

static void set_key(char *key, int index)
{
	int len;
	len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key + index * (PLAINTEXT_LENGTH + 1), key, len);
	saved_key[index * (PLAINTEXT_LENGTH + 1) + len] = 0;
}

static char *get_key(int index)
{
	return saved_key + index * (PLAINTEXT_LENGTH + 1);
}

static void char_to_bin(char *in, int char_length, char *bin)
{
	int i;
	for (i = 0; i < char_length; i += 2) {
		char a = in[i];
		char b = in[i + 1];
		if (a >= 65)
			a -= 55;
		else
			a -= 48;
		if (b >= 65)
			b -= 55;
		else
			b -= 48;
		bin[i / 2] = a << 4;
		bin[i / 2] += b;
	}
}

static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[BINARY_SIZE];
	memset(out, 0, BINARY_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	char_to_bin(ii, strlen(ii), out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct argon2_salt salt;
	char *i = strchr(ciphertext+1,'$')+1;
	char *first_dollar,*second_dollar, *third_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');

	salt.salt_length = last_dollar - third_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.lanes = atoi(second_dollar+1);

	memcpy(salt.salt, third_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt_)
{
	uint32_t i;
	size_t mem_size;
	uint32_t memory_blocks, segment_length;
	struct argon2_salt * salt = (struct argon2_salt *) salt_;

	memcpy(&saved_salt,salt_,sizeof(struct argon2_salt));
	
	//allocate memory
	memory_blocks = salt->m_cost;
    	if (memory_blocks < 2 * ARGON2_SYNC_POINTS * salt->lanes) {
		memory_blocks = 2 * ARGON2_SYNC_POINTS * salt->lanes;
	}
	segment_length = memory_blocks / (salt->lanes * ARGON2_SYNC_POINTS);
	// Ensure that all segments have equal length
	memory_blocks = segment_length * (salt->lanes * ARGON2_SYNC_POINTS);

	mem_size= sizeof(block)*memory_blocks;

	if(mem_size>saved_mem_size)
	{
		if(saved_mem_size>0)
			for(i=0;i<threads;i++)
				free_region(&memory[i]);
		for(i=0;i<threads;i++)
			alloc_region(&memory[i],mem_size);

		saved_mem_size=mem_size;
	}
	pseudo_rands_size=sizeof(uint64_t)*segment_length;
	pseudo_rands_size+=MEM_ALIGN_CACHE;
	//must be divisible by ARGON_ALIGN
	pseudo_rands_size+=ARGON_ALIGN-1;
	pseudo_rands_size-=pseudo_rands_size%ARGON_ALIGN;
	if(pseudo_rands_size>saved_pseudo_rands_size)
	{
		if(saved_pseudo_rands_size>0)
			free_region(&pseudo_rands);
		
		alloc_region(&pseudo_rands,(pseudo_rands_size)*threads);

		saved_pseudo_rands_size=pseudo_rands_size;
	}
	//printf("%d\n",mem_size);
	//printf("%d\n",sizeof(uint64_t)*segment_length);
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted + i * BINARY_SIZE, saved_salt.hash_size))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypted + index * BINARY_SIZE,  saved_salt.hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void argon2i(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, uint8_t lanes, region_t *memory, void *Sbox, void* pseudo_rands)
{
	uint8_t* default_ad_ptr = NULL;
	uint32_t default_ad_length = 0;
	uint8_t* default_secret_ptr = NULL;
	uint32_t default_secret_length = 0;
	uint8_t default_parallelism = 1;
	AllocateMemoryCallback default_a_cbk = NULL;
	FreeMemoryCallback default_f_cbk= NULL;
	bool c_p=false;
	bool c_s=false;
	bool c_m=false;
	bool pr=false;

	Argon2_Context context = {(uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism,default_parallelism,default_a_cbk,default_f_cbk,
	c_p,c_s,c_m,pr, memory->aligned, Sbox, pseudo_rands};
	Argon2Core(&context, Argon2_i);
}

static void argon2d(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, uint8_t lanes, region_t *memory, void *Sbox, void* pseudo_rands)
{
	uint8_t* default_ad_ptr = NULL;
	uint32_t default_ad_length = 0;
	uint8_t* default_secret_ptr = NULL;
	uint32_t default_secret_length = 0;
	uint8_t default_parallelism = 1;
	AllocateMemoryCallback default_a_cbk = NULL;
	FreeMemoryCallback default_f_cbk= NULL;
	bool c_p=false;
	bool c_s=false;
	bool c_m=false;
	bool pr=false;

	Argon2_Context context = {(uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism,default_parallelism,default_a_cbk,default_f_cbk,
	c_p,c_s,c_m,pr, memory->aligned, Sbox, pseudo_rands};
	Argon2Core(&context, Argon2_d);
}

static void argon2id(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, uint8_t lanes, region_t *memory, void *Sbox, void* pseudo_rands)
{
	uint8_t* default_ad_ptr = NULL;
	uint32_t default_ad_length = 0;
	uint8_t* default_secret_ptr = NULL;
	uint32_t default_secret_length = 0;
	uint8_t default_parallelism = 1;
	AllocateMemoryCallback default_a_cbk = NULL;
	FreeMemoryCallback default_f_cbk= NULL;
	bool c_p=false;
	bool c_s=false;
	bool c_m=false;
	bool pr=false;

	Argon2_Context context = {(uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism,default_parallelism,default_a_cbk,default_f_cbk,
	c_p,c_s,c_m,pr, memory->aligned, Sbox, pseudo_rands};
	Argon2Core(&context, Argon2_id);
}

static void argon2ds(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, uint8_t lanes, region_t *memory, void *Sbox, void* pseudo_rands)
{
	uint8_t* default_ad_ptr = NULL;
	uint32_t default_ad_length = 0;
	uint8_t* default_secret_ptr = NULL;
	uint32_t default_secret_length = 0;
	uint8_t default_parallelism = 1;
	AllocateMemoryCallback default_a_cbk = NULL;
	FreeMemoryCallback default_f_cbk= NULL;
	bool c_p=false;
	bool c_s=false;
	bool c_m=false;
	bool pr=false;

	Argon2_Context context = {(uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism,default_parallelism,default_a_cbk,default_f_cbk,
	c_p,c_s,c_m,pr, memory->aligned, Sbox, pseudo_rands};
	Argon2Core(&context, Argon2_ds);
}

static int crypt_all_i(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2i
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost,
		    saved_salt.lanes, &memory[THREAD_NUMBER%threads],
		    NULL,pseudo_rands.aligned+pseudo_rands_size*(THREAD_NUMBER%threads));
	}
	return count;
}

static int crypt_all_d(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2d
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost,
		    saved_salt.lanes, &memory[THREAD_NUMBER%threads],
		    NULL,pseudo_rands.aligned+pseudo_rands_size*(THREAD_NUMBER%threads));
	}
	return count;
}

static int crypt_all_id(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2id
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost,
		    saved_salt.lanes, &memory[THREAD_NUMBER%threads],
		    NULL,pseudo_rands.aligned+pseudo_rands_size*(THREAD_NUMBER%threads));
	}
	return count;
}

static int crypt_all_ds(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2ds
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost,
		    saved_salt.lanes, &memory[THREAD_NUMBER%threads],
		    Sbox[THREAD_NUMBER%threads].aligned,
                    pseudo_rands.aligned+pseudo_rands_size*(THREAD_NUMBER%threads));
	}
	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct argon2_salt *salt = (struct argon2_salt*)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for(i=0;i<salt->salt_length;i++) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}


#if FMT_MAIN_VERSION > 11

static unsigned int tunable_cost_t(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_l(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->lanes;
}

#endif

struct fmt_main fmt_argon2i = {
	{
		FORMAT_LABEL_i,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l"
		},
#endif
		tests_i
	}, {
		init,
		done,
		reset_i,
		fmt_default_prepare,
		valid_i,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all_i,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_argon2d = {
	{
		FORMAT_LABEL_d,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l"
		},
#endif
		tests_d
	}, {
		init,
		done,
		reset_d,
		fmt_default_prepare,
		valid_d,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all_d,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_argon2id = {
	{
		FORMAT_LABEL_id,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l"
		},
#endif
		tests_id
	}, {
		init,
		done,
		reset_id,
		fmt_default_prepare,
		valid_id,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all_id,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_argon2ds = {
	{
		FORMAT_LABEL_ds,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l"
		},
#endif
		tests_ds
	}, {
		init_ds,
		done_ds,
		reset_ds,
		fmt_default_prepare,
		valid_ds,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all_ds,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};


#endif
