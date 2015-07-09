/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_yescrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_yescrypt);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "memdbg.h"
#include "yescrypt.h"

#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"yescrypt"
#define FORMAT_NAME			""

#ifdef __AVX2__
#define ALGORITHM_NAME			"AVX2"
#elif defined(SIMD_COEF_64)
#define ALGORITHM_NAME			"SSE2"
#else
#define ALGORITHM_NAME			" "
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define SETTING 			4 + 1 + 5 + 5 + BYTES2CHARS(32) + 1
#define HASH_SIZE			HASH_LEN + 1

#define PLAINTEXT_LENGTH		125

#define BINARY_SIZE			32

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define YESCRYPT_FLAGS YESCRYPT_RW
#define YESCRYPT_P 11
#define YESCRYPT_PROM 8

#define BYTES2CHARS(bytes) \
	((((bytes) * 8) + 5) / 6)

#define HASH_LEN BYTES2CHARS(BINARY_SIZE) /* base-64 chars */

#ifdef __AVX2__
#define OMP_SCALE 1
#elif  defined(SIMD_COEF_64)
#define OMP_SCALE 1
#else
#define OMP_SCALE 1
#endif

struct yescrypt_salt {
	char salt[SALT_SIZE];
	uint32_t salt_length;
	uint64_t N;
	uint32_t r, p, t, g;
	yescrypt_flags_t flags;
};

static struct fmt_tests tests[] = {
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34.$ZoMvPuaKOKqV3K2xNz3pPp.cWOIYJICPLdp6EFsv5Z0","pleaseletmein"},
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34.$etMpFbzahhNbJ0UPlAESnepEdKjs5VqpbpMEZyl.7H/","spiderman"},
	{"$1$1$7X$96....9....WZaPV7LSUEKMo34.$PIeIJHhlVeIEcM3.sIuIH85KdkqPPNCfZ3WJdTKpY81","spiderman"},
	{NULL}
};

extern int decode64_one(uint32_t * dst, uint8_t src);
extern const uint8_t * decode64_uint32(uint32_t * dst, uint32_t dstbits,
    const uint8_t * src);

static struct yescrypt_salt saved_salt;

static char *saved_key;

static int threads;

static unsigned char *crypted;

static yescrypt_local_t * memory_local;

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
	crypted = malloc(self->params.max_keys_per_crypt * (HASH_SIZE));
	memset(crypted, 0, self->params.max_keys_per_crypt * (HASH_SIZE));

	memory_local=malloc(threads*sizeof(yescrypt_local_t));
	for(i=0;i<threads;i++)
		yescrypt_init_local(&memory_local[i]);
}

static void done(void)
{
	int i;
	free(saved_key);
	free(crypted);
	for(i=0;i<threads;i++)
		yescrypt_free_local(&memory_local[i]);
	free(memory_local);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	uint32_t r, p;
	size_t prefixlen, saltlen, need;
	const char *src, *salt;
	char *dollar=ciphertext;
	for(i=0;i<2;i++){
		dollar=strchr(dollar,'$');
		if(dollar==NULL)
			return 0;
		dollar++;
	}
	src=strchr(dollar,'$');
	for(i=0;i<3;i++){
		dollar=strchr(dollar,'$');
		if(dollar==NULL)
			return 0;
		dollar++;
	}
	if (src[0] != '$' || src[1] != '7')
		return 0;

	src+=2;
	if (*src != '$' && *src != 'X')
		return 0;

	if(*src == 'X')
		src++;
	if (*src != '$') {
		uint32_t decoded_flags;
		if (decode64_one(&decoded_flags, *src))
			return 0;
		if (*++src != '$')
			return 0;
	}
	src++;
	{
		uint32_t N_log2;
		if (decode64_one(&N_log2, *src))
			return 0;
		src++;
	}
	src = (char*)decode64_uint32(&r, 30, (uint8_t*)src);
	if (!src)
		return 0;

	src = (char*)decode64_uint32(&p, 30, (uint8_t*)src);
	if (!src)
		return 0;

	prefixlen = src - ciphertext;
	salt = src;
	src = strrchr((char *)salt, '$');

	if (src)
		saltlen = src - salt;
	else
		saltlen = strlen(salt);

	need = prefixlen + saltlen + 1 + HASH_LEN + 1;
	if (need < saltlen)
		return 0;

	if(saltlen>sizeof(saved_salt.salt))
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


static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[HASH_SIZE];
	memset(out, 0, HASH_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	strcpy(out,ii);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct yescrypt_salt salt;
	const char * src, * salt_src;
	size_t saltlen;
	uint64_t N;
	uint32_t r, p;
	yescrypt_flags_t flags = 0;
	
	memset(&salt,0,sizeof(struct yescrypt_salt));

	src=ciphertext+1;
	salt.t=atoi(src);
	src=strchr(src,'$')+1;
	salt.g=atoi(src);
	src=strchr(src,'$')+2;
	if(*src=='X')
	{
		src++;
		flags = YESCRYPT_RW;
	}

	if (*src != '$') {
		uint32_t decoded_flags;
		if (decode64_one(&decoded_flags, *src))
			return NULL;
		flags = decoded_flags;
		if (*++src != '$')
			return NULL;
	}
	src++;

	{
		uint32_t N_log2;
		if (decode64_one(&N_log2, *src))
			return NULL;
		src++;
		N = (uint64_t)1 << N_log2;
	}

	src = (char*)decode64_uint32(&r, 30, (uint8_t*)src);


	src = (char*)decode64_uint32(&p, 30, (uint8_t*)src);

	salt_src = src;
	src = strrchr((char *)salt_src, '$');
	if (src)
		saltlen = src - salt_src;
	else
		saltlen = strlen((char *)salt_src);

	memset(salt.salt,0,sizeof(salt.salt));
	strncpy(salt.salt,salt_src,saltlen);
	salt.salt_length=saltlen;
	salt.N=N;
	salt.r=r;
	salt.p=p;
	salt.flags=flags;
	
	return (void *)&salt;
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt,salt,sizeof(struct yescrypt_salt));
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted + i * HASH_SIZE, HASH_SIZE))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypted + index * HASH_SIZE, HASH_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		uint8_t hash[BINARY_SIZE];
		yescrypt_kdf(NULL, &memory_local[i], (uint8_t*)(saved_key + i * (PLAINTEXT_LENGTH + 1)),
		    	strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), (uint8_t*)saved_salt.salt, saved_salt.salt_length,
	    		saved_salt.N, saved_salt.r, saved_salt.p, saved_salt.g, saved_salt.t, saved_salt.flags, hash, sizeof(hash));
		encode64(crypted+i*HASH_SIZE, HASH_SIZE, hash, sizeof(hash));
	}

	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * HASH_SIZE);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct yescrypt_salt *salt = (struct yescrypt_salt*)_salt;
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

static unsigned int tunable_cost_N(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->N;
}

static unsigned int tunable_cost_r(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->r;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->p;
}

static unsigned int tunable_cost_t(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->t;
}

static unsigned int tunable_cost_g(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->g;
}

#endif

struct fmt_main fmt_yescrypt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		HASH_SIZE,
		BINARY_ALIGN,
		sizeof(struct yescrypt_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"N",
			"r",
			"p",
			"t",
			"g"
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
			tunable_cost_N,
			tunable_cost_r,
			tunable_cost_p,
			tunable_cost_t,
			tunable_cost_g
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
