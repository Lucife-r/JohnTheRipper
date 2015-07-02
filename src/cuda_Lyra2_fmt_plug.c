/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main cuda_fmt_lyra2;
#elif FMT_REGISTERS_H
john_register_one(&cuda_fmt_lyra2);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "memdbg.h"
#include "misc.h"
#include "cuda_common.h"

#define FORMAT_LABEL			"Lyra2-cuda"
#define FORMAT_NAME			"Lyra2"
#define ALGORITHM_NAME			"Lyra2 CUDA"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125

#define BINARY_SIZE			256  //BIARY_SIZE in Lyra2 is unlimited

#define CIPHERTEXT_LENGTH		(2*BINARY_SIZE)

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define BLOCKS				32
#define THREADS				128
#define MAX_KEYS_PER_CRYPT		(BLOCKS*THREADS)
#define MIN_KEYS_PER_CRYPT		BLOCKS

static struct fmt_tests tests[] = {
	{"$Lyra2$8$8$256$2$salt$03cafef9b80e74342b781e0c626db07f4783210c99e94e5271845fd48c8f80af", "password"},
	{"$Lyra2$8$8$256$2$salt2$e61b2fc5a76d234c49188c2d6c234f5b5721382b127bea0177287bf5f765ec1a","password"},
	{"$Lyra2$1$12$256$3$salt$27a195d60ee962293622e2ee8c449102afe0e720e38cb0c4da948cfa1044250a","password"},
	{"$Lyra2$8$8$256$2$salt$23ac37677486f032bf9960968318b53617354e406ac8afcd","password"},
	{"$Lyra2$16$16$256$2$salt$f6ab1f65f93f2d491174f7f3c2a681fb95dadee998a014b90d78aae02bb099", "password"},
	{"$Lyra2$1$8$256$1$one$4b84f7d57b1065f1bd21130152d9f46b71f4537b7f9f31710fac6b87e5f480cb","pass"},
	{NULL}
};

extern void multPasswordCUDA(unsigned char *K, int kLen, unsigned char *passwords, int pwdLen, unsigned char *salt, int saltLen, unsigned int t_cost, unsigned int m_cost, unsigned int nPARALLEL, unsigned int C_COLS, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize);

struct lyra2_salt {
	uint32_t t_cost,m_cost;
	uint32_t nCols,nParallel;
	uint32_t hash_size;
	uint32_t salt_length;
	unsigned char salt[SALT_SIZE];
};

static struct lyra2_salt saved_salt;

static unsigned char *saved_key;

static unsigned char *crypted;

unsigned short N_COLS;
int nCols_is_2_power;

static void *get_salt(char *ciphertext);

static void init(struct fmt_main *self)
{
	saved_key =
	    malloc(MAX_KEYS_PER_CRYPT * (PLAINTEXT_LENGTH + 1));
	memset(saved_key, 0, MAX_KEYS_PER_CRYPT * (PLAINTEXT_LENGTH + 1));
	crypted =
	    malloc(MAX_KEYS_PER_CRYPT  * (BINARY_SIZE));
	memset(crypted, 0, MAX_KEYS_PER_CRYPT  * (BINARY_SIZE));

	cuda_init();
}

static void done(void)
{
	free(saved_key);
	free(crypted);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *next_dollar;
	char *i;
	struct lyra2_salt *salt;

	if (strncmp(ciphertext, "$Lyra2$", 7) &&
	    strncmp(ciphertext, "$lyra2$", 7))
		return 0;
	i = ciphertext + 7;
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
	//nCols
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//nParallel
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	
		i++;
	if (*i)
		return 0;
	
	salt=get_salt(ciphertext);

	if (salt->m_cost < 3) 
		return 0;

	if ((salt->m_cost / 2) % salt->nParallel != 0) 
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
	return (char*) (saved_key + index * (PLAINTEXT_LENGTH + 1));
}

static void char_to_bin(char *in, int char_length, char *bin)
{
	int i;
	for (i = 0; i < char_length; i += 2) {
		char a = in[i];
		char b = in[i + 1];
		if (a >= 97)
			a -= 87;
		else
			a -= 48;
		if (b >= 97)
			b -= 87;
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
	static struct lyra2_salt salt;
	char *i = ciphertext + 7;
	char *first_dollar,*second_dollar,*third_dollar,*fourth_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');
	fourth_dollar = strchr(third_dollar + 1, '$');

	salt.salt_length = last_dollar - fourth_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.nCols = atoi(second_dollar+1);
	salt.nParallel = atoi(third_dollar+1);

	memcpy(salt.salt, fourth_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static int is_power_of2(unsigned int x)
{
	int i=1;
	while(i<=x)
	{
		if (i==x)
			return 1;
		i*=2;
	}
	return 0;
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt,salt,sizeof(struct lyra2_salt));
	N_COLS=saved_salt.nCols;
	nCols_is_2_power=is_power_of2(N_COLS);
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted + i * saved_salt.hash_size, saved_salt.hash_size))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypted + index * saved_salt.hash_size,  saved_salt.hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	if(count*2>=THREADS)
		multPasswordCUDA(crypted, saved_salt.hash_size, saved_key, PLAINTEXT_LENGTH+1, saved_salt.salt, saved_salt.salt_length, saved_salt.t_cost,
		 saved_salt.m_cost, saved_salt.nParallel, saved_salt.nCols, count, saved_salt.nParallel*count/THREADS, THREADS);
	else
		multPasswordCUDA(crypted, saved_salt.hash_size, saved_key, PLAINTEXT_LENGTH+1, saved_salt.salt, saved_salt.salt_length, saved_salt.t_cost,
		 saved_salt.m_cost, saved_salt.nParallel, saved_salt.nCols, count, count, saved_salt.nParallel);
	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * saved_salt.hash_size);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct lyra2_salt *salt = (struct lyra2_salt*)_salt;
	unsigned int hash = 0;
	unsigned char *p = salt->salt;

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
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->m_cost;
}

#endif

struct fmt_main cuda_fmt_lyra2 = {
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
		sizeof(struct lyra2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
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

#endif
