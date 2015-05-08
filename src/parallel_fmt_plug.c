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
#define OMP_SCALE 2 #to do
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
	{"$parallel$11$salt$8af566c612e8ae9983dbfb144b931ba2f581d84f01b86a4979a343b91861f2eb14ec78d684b3044fe94d6ec1e7ea908fa806756a6393c29a5870a059e4bcd2d0","password"},
	{"$parallel$12$salt$1e68709d207baef85c760e80e9159f8cf4a6af91ffef050fdd47a769ba1e48903dd0e38d3ee46bbc8572f45404ed55cffb8b6e7a113002c613f5b5c9bec716b5","password"},
	{"$parallel$13$salt$cbfb755415d5ca82f08feb635b86efbad713221996ca9c45bb2f0d52ff070f872a8fbc839adc3c804c8c3aab1c1ce6f5ff38fc7a599864c012e4fa2f8c4f8800","password"},
	{"$parallel$14$salt$402ce53bd83c2f0471945d72feea6de41232880431b87501b50ef1d567af9c6ea2d95c161398f86b6f35d4ebd064da7673beffa59b134b2f7414d938cf68f176","password"},
	{"$parallel$15$salt$6b20c1a66413f27ce10997c9a90c035f809a8aa0ffcaecb6a821e1e7224dd5fc03cde9f3131dbdd812a0f6a45dcdd1061f42c228d3e69af2818077b8b22dbf22","password"},
	{"$parallel$16$salt$7aada6bd94776f275e6c9edd792cfe3f27301de55441426732708a1a75c8c595a24c9ce81c583b7c11da9c07e61f6fac4ed27756d23aacc5aae3d2361f2662a5","password"},
	{"$parallel$17$salt$189b628d2d10fd72c7d0d54e80cfb196cee9f04b95d7eb7d71caf3a3bffca5fd41a6b0fe4710ce13b060dbf51f07bc3e1b40c639933bcd9245d4a2998f3cd803","password"},
	{"$parallel$18$salt$311646d0787a94c8063bd5cf824891da62816393c9af58f255b0ee563aa75b5c639267bdfe0123ea14144b7b64ed9cad663d4bf328393165a15b076ae1c06b47","password"},
	{"$parallel$19$salt$28c5121ac2f6d5ffa6d57905fd25779a47c5ffb807b1ca72930a1cbfa0324f7d43e1af8364db4b203154c61344186e9153f2832694d7d6c4b90c85117cc79869","password"},
	{"$parallel$20$salt$fccc23b6cce4859d6342b6fe7be0b0fe90e60779b10b0ba11bbaac70797cb40219becabe17b83c8841420946eee4bfa081cf0e569301d49baed3887c939eccf4","password"},
	{"$parallel$21$salt$61a117040f1cf4f04103e007c81180f9232c519dda6cda4fe6c96ee915808d8b871241538dd92183cbfdc434edc28e2b1eb03fd4180fc181d9a6c76c35d1e52d","password"},
	{"$parallel$22$salt$cc4a44a54ec344e06d45b12b68becc8644ba8597ca5194c842a578a313efb91cc5752e5c54abce0c33fd67a3c16423263bf2ef1f63686054c81b8f4227830e2e","password"},
	{"$parallel$23$salt$bb6e5cb8789b44de5521ad940977f104e47dfd2202a84f1d7cf62406127450904f11e71114be6451f6061904fac74ca5ec9a6db3aba50e54dca57d7aa9eae400","password"},
	{"$parallel$24$salt$8932d435fd730b27ac40d2f38cc45bb6f82ba608d23f6c74e64dbbcd18cac7048d0bfdf11606f21d85904066102ace8ca62217ca4071e38bcb51f1fec65f6e88","password"},
	{"$parallel$25$salt$f9125322198af13edd6e7ed6c27ba06a8987a95f649b02f74351b62ef6b9cf1342d779a6b72e17d93bbcc5bf8341c6e23d6d1400afd7d10d8734882fd350528d","password"},
	{"$parallel$26$salt$a5cfbb7df58fcc79b99eb921bc7efcc9e5b1302efacf2eb9968770c39b65c826e452ddcf8f77b2601800f882976589dc26c385548c05946a8dd339fa5e0b806e","password"},
	{"$parallel$27$salt$b67469661eeffd401b32a0c520fd9554c576f45091352015820b7c9da93c152c9e3f16d03c15ff23bb0ab966c33a82e85a5e2f7780879a388f800bc320daa9b5","password"},
	{"$parallel$28$salt$b77579e037fd88876db9f416efdc447140ac9044c3bf8ff151ace55136a74e3775d899a2eb14d012731e927da20eee679cb67c61c1e2680708f1d5ae969adc79","password"},
	{"$parallel$29$salt$01cb55c6ac1f4c20dd36f7d940000a63c6420cdba2abe3315c26336d767cfda4cea542bcd6414ff959492ec653c407fff7710f51918988dbd72b7749e2fcf961","password"},
	{"$parallel$30$salt$b6d292d79d42d3d891bb6232d456c2341daca2e6111972032a59efba943c69e950f816c1020c1dd41f9c71c130854515cbc19a946bab02bf53f385fe6e6a8035","password"},
	{"$parallel$31$salt$01652d823a4c428c234d9040db22cd2874bc643136e571039eabe02577c872b0f396865d3c073fdd07a9e1fec5e6d95ba363ddd18a2969252f73f1a71c6ea4e4","password"},
	{"$parallel$32$salt$28460df329725f3d92ca7cd79d2e0b8805febeb922b77def46bf6733f1ecbff523400c89487d7a4ab7369789069b3926263a8a71e1a4350b97879f3df130ecad","password"},
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
