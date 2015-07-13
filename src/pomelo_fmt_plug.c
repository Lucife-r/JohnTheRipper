/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pomelo;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pomelo);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "pomelo.h"
#include "memdbg.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"POMELO"
#define FORMAT_NAME			""

#ifdef __AVX2__
#define ALGORITHM_NAME			"AVX2"
#elif defined(AVX)
#define ALGORITHM_NAME			"AVX"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"SSE2"
#else
#define ALGORITHM_NAME			" "
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define CIPHERTEXT_LENGTH		512

#define BINARY_SIZE			256

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#ifdef __AVX2__
#define OMP_SCALE 16
#elif  defined(SIMD_COEF_64)
#define OMP_SCALE 16
#else
#define OMP_SCALE 16
#endif

#ifdef _OPENMP
#define THREAD_NUMBER omp_get_thread_num()
#else
#define THREAD_NUMBER 1
#endif

static struct fmt_tests tests[] = {
	{"$POMELO$2$2$S$982D98794C7D4E728552970972665E6BF0B829353C846E5063B78FDC98F8A61473218A18D5DBAEB0F987400F2CC44865EB02", "password"},
	{"$POMELO$2$2$salt$CBA3E72A1F3CAD74AE0E33F353787E82E1D808C65908B2EA57BA5BDD435D3BC645937A1772D1AA18D91D7164616B010810C359B04F4FFA58E60C04C6B8A095DE4500C18CD815A8960E54B0777A3279485EC559BE34D5DBFBF2A66BA61F386FC8896A18D8", "pass"},
	{"$POMELO$3$3$s$8129F2646C7583D996A87937475F4C10747F4A6D23BB65B3B28AD1F61C5EFCA58969CE8472B49135BB870F0264AFB3E7AE2D9FD798C2852C60543ECFB06528CCC8390F749803ABF2D8F67DB4F4B07297174DF7628DC1EA58DB862DF4ECE41F1E829550E8DC2BDD6B4F44431B21A9C5657162E8BD2869A79F7B23BAD01D4417957CE5439691DA82F81B018CAB9F57B38AE19F2F307C849D2FE3A7CE38081175405DD71E08CA804D5DBEC6FAA623ADCFC67445DD0336A3F9BA91CF1EB7B0239138DD23FCB1989D2BF2EADADE2DC4639E5B811514A2885D7535C707D3003BDCCE59A9B5B9B085385B044EAE8527A31C5972B1A5F3F17F522899B8F0B2BF9036D697", "home"},
	{"$POMELO$5$5$zxc$CA9CC9943988222B2BBD837509382BE8833C5B462D2FDC603D38CDE1A7E74202C30CA726B3843E296C3FD06C8463C74E38868F839B629C7C148BBFB417D523673696B8A88D2C704927132ED43EB1F621BCA6C48535A2C28623D7EF0CD23EDB5305E9A564", "qwe"},
	{NULL}
};

struct pomelo_salt {
	uint32_t t_cost,m_cost;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

struct pomelo_salt saved_salt;
static region_t * memory;

static char *saved_key;
static int threads;
int prev_m_cost;

static unsigned char *crypted;

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
}

static void done(void)
{
	int i;
	free(saved_key);
	free(crypted);
	for(i=0;i<threads;i++)
		free_region(&memory[i]);
	free(memory);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *next_dollar;
	char *i;

	if (strncmp(ciphertext, "$pomelo$", 8) &&
	    strncmp(ciphertext, "$POMELO$", 8))
		return 0;
	i = ciphertext + 8;
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
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
	return 1;
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
	static struct pomelo_salt salt;
	char *i = ciphertext + 8;
	char *first_dollar,*second_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');

	salt.salt_length = last_dollar - second_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);

	memcpy(salt.salt, second_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	/*int i;
	size_t mem_size;*/
	memcpy(&saved_salt,salt,sizeof(struct pomelo_salt));
	/*if(prev_m_cost>=(int)saved_salt.m_cost)
		return;
	mem_size= 1ULL << (13 + saved_salt.m_cost);
	free_allocated();
	prev_m_cost=saved_salt.m_cost;
	allocated=malloc(threads*(sizeof(struct pomelo_allocation)));
	for(i=0;i<threads;i++)
	{
		allocated[i].alloc=malloc(mem_size+ALIGN);
		allocated[i].buffer=allocated[i].alloc;
		while((size_t)allocated[i].buffer%ALIGN)
			allocated[i].buffer++;
	}*/
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

static void pomelo(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, region_t *memory)
{
	size_t mem_size= 1ULL << (13 + m_cost);
	alloc_region(memory,mem_size);
#ifdef __AVX2__
	POMELO_AVX2
#elif defined(SIMD_COEF_64)
	POMELO_SSE2
#else
	POMELO
#endif
		(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, memory->aligned);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		pomelo
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost, &memory[THREAD_NUMBER%threads]);
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
	struct pomelo_salt *salt = (struct pomelo_salt*)_salt;
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
	struct pomelo_salt *salt=(struct pomelo_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct pomelo_salt *salt=(struct pomelo_salt *)_salt;
	return salt->m_cost;
}

#endif

struct fmt_main fmt_pomelo = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct pomelo_salt),
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
			"m"
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m
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
		crypt_all,
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
