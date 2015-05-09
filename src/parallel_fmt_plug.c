/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_parallel;
#elif FMT_REGISTERS_H
john_register_one(&fmt_parallel);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "parallel.h"
#include "memdbg.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"parallel"
#define FORMAT_NAME			"parallel SHA-512"

#ifdef __AVX2__
#define ALGORITHM_NAME			" "
#elif defined(SIMD_COEF_64)
#define ALGORITHM_NAME			" "
#else
#define ALGORITHM_NAME			" "
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125


#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			65

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#ifdef __AVX2__
#define OMP_SCALE 2 //to do
#elif  defined(SIMD_OEF_64)
#define OMP_SCALE 2
#else
#define OMP_SCALE 2
#endif

static struct fmt_tests tests[] = {
	{"$parallel$0$salt$6ee2fc021128a12b421606081687c7a5f17079400895a810ba4dffce1c5e4952a2c6ee370d7955bf9e479087405525dbdc62901e2851fd78ef4c42a8e2b8842d","password"},
	{"$parallel$0$salt$43dd067982f03038451443ee265ddee3b5c166d1c17bfa693c7ff90bbf3857fda16807e6f0f2a7d547b256846fa4708259c4520738bc107309af9dc6f9fb5f41","admin"},
	{"$parallel$0$salt$6ee2fc021128a12b421606081687c7a5f17079400895a810ba4dffce1c5e4952","password"},
	{"$parallel$1$salt$13528220310eb5bd3f91abf322a50b7846a90a67c83d2515a2d19fdf7c1dc227a8fadab0b81960357556255ccfc8306265b0d0b94bfe1b9530844effafdc86a2","password"},
	{"$parallel$2$salt$e1085b1a23f7f8d174ebd3d650e783d6a2b5880890cef82817b69ee5e82dbe3a9aec46925d26b4eab45fa3a3b6034e9c7a6669772d71259737d5f0bad5060113","password"},
	{"$parallel$3$salt$e210bcdc45b17f4a3751358f5f7b23fe0e70124e49b3a6be7204a047c7afba45febd59848e16dd4899043b9d40fe387865412c167dfb955d0a08c026ba424416","password"},
	{"$parallel$4$salt$7af24e632c782720c403b69b26b21ac81637c8184b03d9bb6c40429d0dfcc264a4107e0b78c0e49d949c1bb59b5185bf52cb57dd75b52b11d8bba75f7c0857e5","password"},
	{"$parallel$5$salt$f646ab7046d70581d4bbe95db0e93f82dcf6b322cad094e93eddf4969743af57cdcdcd45bcd8f0557924a86299040cd5f5ede5b8891ba62f33b08879fecb9cfc","password"},
	{"$parallel$6$salt$c9483307fe0c5f50c973a9cc2cfe2ea5e2786329ebad9a6aec2417caef16f559112788775479bf2e35d5f79ae8f3f66cbe5a7f9ddea9dd3aa5ddc70dbb162041","password"},
	{"$parallel$7$salt$2d6b048bcdf8155141d7f1cdacbe5bb9c9357f6396252c57c9bc705ca33b642b2ed6c21bfd81a43a7e929ae2610a69ec3db981db212480c81ed2ddc09846939a","password"},
	{"$parallel$8$salt$e7cf3fb36940b14a769271363195a4b9225e6fe133b053aad1240dd2ae18b6b39545b3ac13dd9e7ca96cf9b7b549007e4ff18c06cbfd9371660d5cf07433cd2b","password"},
	{"$parallel$9$salt$d7e332b70ae4411093a5470bfd3549b4fb3555990257363eca4e08e025fc47bd814bdace11056474ed8f23ea1ad7b48cac89aa0d7320fe8adca7e891629025ae","password"},
	{"$parallel$10$salt$cf5a271fee639cd226af08048c0762be506758ced831ef3238519bb3ea22f24c47c7e125542f7a1f7c9f8c0aa392a4b043051de5d1ed0467c7b144e05a356d3c","password"},
	{NULL}
};

static char saved_salt[SALT_SIZE];

static char *saved_key;

static unsigned char *crypted;
static int length_cipher;
static int length_salt;
static int cost;

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

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key =
	    malloc(self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	memset(saved_key, 0,
	    self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	crypted = malloc(self->params.max_keys_per_crypt * (BINARY_SIZE));
	memset(crypted, 0, self->params.max_keys_per_crypt * (BINARY_SIZE));
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

	if (strncmp(ciphertext, "$parallel$", 8) &&
	    strncmp(ciphertext, "$parallel$", 8))
		return 0;
	i = ciphertext + 10;
	//t_cost
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

static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[BINARY_SIZE];
	memset(out, 0, BINARY_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	out[0] = strlen(ii) / 2;
	char_to_bin(ii, strlen(ii), out + 1);
	return out;
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

static int salt_hash(void *salt)
{
	unsigned int hash = 0;
	char *p = (char *)salt;

	while (*p) {
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

static void *get_salt(char *ciphertext)//to do: change char to short integers
{
	static char salt[SALT_SIZE + 5];
	char *i = ciphertext + 10;
	char *first_dollar;
	char *last_dollar = strrchr(ciphertext, '$');
	char c_cost;

	//printf("get salt %s\n",ciphertext);

	memset(salt, 0, sizeof(salt));

	salt[0] = (char)(strlen(last_dollar + 1) / 2);

	salt[last_dollar - i + 4] = 0;
	salt[SALT_SIZE + 4] = 0;
	first_dollar = strchr(i, '$');

	c_cost = atoi(i);

	salt[1] = (char)(last_dollar - first_dollar - 1);
	salt[2] = c_cost;

	memcpy(salt + 3, first_dollar + 1, salt[1]);

	//printf("get salt end\n");

	return salt;
}

static void set_salt(void *salt)
{
	char *i = salt;
	unsigned char *o = salt;
	//printf("set salt %s\n",(char*)salt);
	length_cipher = (int)o[0];
	if (length_cipher == 0)
		length_cipher = 256;
	i = i + 3;
	cost = o[2];

	length_salt = o[1];
	memset(saved_salt, 0, sizeof(saved_salt));
	memcpy(saved_salt, i, length_salt);
	//printf("get salt end\n");
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		crypted[i * BINARY_SIZE] = (char)length_cipher;
#ifdef __AVX2__
		PARALLEL
#elif defined(SIMD_COEF_64)
		PARALLEL
#else
		PARALLEL
#endif
		    (crypted + 1 + i * BINARY_SIZE, length_cipher,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt,
		    length_salt, cost);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;
	int length;
	unsigned char *str_binary;

	str_binary = binary;
	length = str_binary[0];
	if (length == 0)
		length = 256;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted + i * BINARY_SIZE, length))
			return 1;
	}
	return 0;

}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	unsigned char *str_binary = binary;
	int len = str_binary[0];
	if (len == 0)
		len = 256;
	return !memcmp(binary, crypted + index * BINARY_SIZE, len);
}

#if FMT_MAIN_VERSION > 11
static unsigned int tunable_cost_N(void *salt)//to do: tez przerobic na shorta
{
	char *str = salt;
	return str[2];
}

#endif

struct fmt_main fmt_parallel = {
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
		    SALT_SIZE,
		    SALT_ALIGN,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		    FMT_OMP |
#endif
		    FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		    {
				"N"
		    },
#endif
	    tests}, {
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
				tunable_cost_N
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
			fmt_default_binary_hash_6},
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
			get_hash_6},
		    cmp_all,
		    cmp_one,
	    cmp_exact}
};

#endif
