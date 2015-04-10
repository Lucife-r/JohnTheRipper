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

#define FORMAT_LABEL			"pomelo"
#define FORMAT_NAME			"Generic pomelo"
#define ALGORITHM_NAME			"Pomelo"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125
//256
//maks len word
#define CIPHERTEXT_LENGTH		512
//40

#define BINARY_SIZE			257
//length + 256
//20
#define BINARY_ALIGN			1
#define SALT_SIZE			32

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#ifdef SIMD_COEF_64
#define OMP_SCALE 16
#else
#define OMP_SCALE 16
#endif


static struct fmt_tests tests[] = {
	{"$POMELO$2$2$S$982D98794C7D4E728552970972665E6BF0B829353C846E5063B78FDC98F8A61473218A18D5DBAEB0F987400F2CC44865EB02", "password"},
	{"$POMELO$2$2$salt$CBA3E72A1F3CAD74AE0E33F353787E82E1D808C65908B2EA57BA5BDD435D3BC645937A1772D1AA18D91D7164616B010810C359B04F4FFA58E60C04C6B8A095DE4500C18CD815A8960E54B0777A3279485EC559BE34D5DBFBF2A66BA61F386FC8896A18D8", "pass"},
	{"$POMELO$3$3$s$8129F2646C7583D996A87937475F4C10747F4A6D23BB65B3B28AD1F61C5EFCA58969CE8472B49135BB870F0264AFB3E7AE2D9FD798C2852C60543ECFB06528CCC8390F749803ABF2D8F67DB4F4B07297174DF7628DC1EA58DB862DF4ECE41F1E829550E8DC2BDD6B4F44431B21A9C5657162E8BD2869A79F7B23BAD01D4417957CE5439691DA82F81B018CAB9F57B38AE19F2F307C849D2FE3A7CE38081175405DD71E08CA804D5DBEC6FAA623ADCFC67445DD0336A3F9BA91CF1EB7B0239138DD23FCB1989D2BF2EADADE2DC4639E5B811514A2885D7535C707D3003BDCCE59A9B5B9B085385B044EAE8527A31C5972B1A5F3F17F522899B8F0B2BF9036D697", "home"},
	{"$POMELO$5$5$zxc$CA9CC9943988222B2BBD837509382BE8833C5B462D2FDC603D38CDE1A7E74202C30CA726B3843E296C3FD06C8463C74E38868F839B629C7C148BBFB417D523673696B8A88D2C704927132ED43EB1F621BCA6C48535A2C28623D7EF0CD23EDB5305E9A564", "qwe"},
	{"$POMELO$3$2$salt$B67B3B3C000A400DC6A2473B736F00490E09CE307C6606269A212FD0DA5643562EFD5A99C215949F6721D814AD85754399043ED6587924E7656018D57A03BD68F98927D064ECAA80D269884F247A45B38AAD65D8E7AFEB4E486CA226BC9BF5994BE84781A2EC3336FEA9DED0A1F2D4011C6D988AE26A6753194F53E4F0649249AB1E39A3139A0BD04018F3A609FC07EDD7B81F50299785567AF5ADD9B1A80F3FBBEC960775CD7932D98F8B375F2F29E694A20B56FCF969DBA59D6C33977243E29DA1304B13F27F156EEE3BBE064A8D9755B4D2242F65CAB893D19E90D21E73E6C8ACA9340E0270BB93E395B3AD2DF7B789281A9C1D8595F889868855F6AC38", "password"},
	{"$POMELO$7$7$S$526089AF63BC802A2F6A29CFDFC67A8CAFFC173B8C11A5629065A51A03E35DD4D85B84879D90AB92D1A58305A95AA120683661E566DF4E1008099C3E252FC3F3BF1EABD3B96853A28D5918D569DBF0B8815D8C78050F2C19BE17A8E2F8F4D09957E82AFE36CF681617A63795BE488F371DA60947F184EF7F8B10547D8B51E33CFE609C8C8A893149B13FF7B065DB5424C812E66F794D7286C1CBD7CF1C2E4D4EE65E2AB2410C1860D24921BCC3C869BF642F74CD3FAA7A1868D1BAB9FE4732FBA5AB8F7CDAE65E9FDF1F864612DDF40C8FD236CB8EDA7EA89962EFA0B4DFA77B69BEEA78C37EA263C33CFA2578473A8E95FF0D3135E24D49300DF1C394A82F60", "pass"},
	{"$POMELO$3$2$double$6DB17CE2C801598F34DB", "float"},
	{"$POMELO$2$3$admin$224E2359D8590F0EB4719D06E42CD4903C711BCB4AA4661F179EB9FBB7D567A2A595C13598EEB47BF5D4737B034C73EC1C7F9561DFF6C6E64A492F180CD9DFF90D82DB281AD41E67D3CE7A42C0F20E3BCF4273456F2C19EF7ED2029ECC112ECD6DE2A4F9985167602520ED576F33606784F5D8440F6F3621764898DC27828C9F6A5F1AE28EE0CA80CED3AF9309DDF472D15325B0F80549428800671BB7915C5057E96783285EAB6EA682DEFEDE188AAA8BDA280F54F899AC162AE475724F54A26996B5504D65768F", "admin"},
	{"$POMELO$2$2$admin$9EDF16E5F280D7DDD5294AA6C67D79CF29DE634E1B24719FBE61074CE1039B49E20FA59C864D541A58906917F9553EEB81086EAAC13F5543A6F2110B963386A268C84B93ABABA7FE7803BC55493D2325F01A442D315DD65B6F76BE904B2300EFB2CD93BEAB5162DA381965B87EDC9C1A1B483D24F505832FCC959EA89788F06EF7EDE640695C549C3CED98486530DCB51D2652FF2538CA7730BE9F9CDB2BADD99D6B988B377E98FD808B7F8624AAD6DC3876F33CD656ABAC7D742183AF7BB003C9B16C268C409197", "admin"},
	{"$POMELO$3$2$admin$2BEB5C91261986C4BC83DEAD822099BEE8B6E72DE47D478D1D9DCCD92CFD171782C54C613E9114359D81877DA2F4C0183B76DDAB33432AF6C08F0D20432811BA4F55CEA1EAE18A8933A533B6F0F9D14D64EB8C7AE74104F7A50EFF2DBCACB53DF0D790614A144D6CC6988B1973E255C3E824A95FA7AE796A2009710F8AA4C82D2AD9998ADE58584B6DE6BE4B52BFCDA601DE8B40C060A9DBFF6E141632EE9F5AC01ECF62D0299585E9E2882165A287461F8EC19AF6E42A8249FFF1B904CE9332BEDEA5191DA85DFA", "admin"},
	{"$POMELO$3$4$admin$04A832CA5BBEE5A0989EC4EE3F3A5A3E33499754076AF19C548C5C2656109610B0EF0E81D97D96EE35C672635A06A00B65BE83FC0C72E303ECA5340C588A27AEAC29A3F75A2BBA95B21D5E8B874FAA92F570A0D112DEDAA5A9971DDE25ADA017F963FABCDBC5E3E19C3170AA009D305906C68A5DF9561CF5CC8208484E4F21DC270B9C55BD026C3B2ECA86BBD8B8045EEE926E57A2BDD9B6DEC69357ED2CD61F40741B258A0EBFC170A2D687017FB15DDC667A0394C8D8189213F425BD3E9145D9858373074F50F3", "admin"},
	{"$POMELO$3$4$admin$F245EBF6A345A0813F4CDDEF1635E4A784D5AFC0128C5E852EAA352AA52D2161D53BA52FADC63A05BB511D9C75B5A57E04B746EDD7F9D6DB605E9C22FC38667D9957F48E846BA59C908E4692E404E23EBE1F6284ACF6AE2FC104B22093728F06E15F9D1E940FCDE4B1CBE85E9BC8F888195B93D67BD2F2B6F1E70F3B99F9D5B89E54205A47163DD9EC1155B6BAAD902E6D29DD96859C0E7821C832A1469E95E099356AA372DCE208FA476205D46877FDA7378A6F34583187F69C7D77C7A480E46CCED7C7FFE8B07DD523C58710C563E64F43B30D02E131C24B2B2C4350F7CC357AB001885BA61663850160C4C0D826B7A8D185B36BF6B775B8FD", "admin"},
	{"$POMELO$4$4$admin$FAFDDF03DF15D158073568AD154989F3BE2A14AC792CE747E2969FE2CAD9A0083D1CCD80B37F42691F1425911D231212EA127332CB6AC3296E645905F2919D73E6D46934D7C0E931AE6863EA1F52701DCA34677B101F3347BEFD272ED4E36CD62330939922557F55A73A2408030B9639D8961A5B5742A1256E38F1DF04C58C54DB3089DBA7E4ED39E229FA0C7DBCF91DDB1773744B43F38EAF7F45E637957D4904663A3ABE8734DDBEFC43CEE21F7B05E28FEAC2C096C3CEF94C4AEC352AE2A429B062505F0434FB94B50D10CE1B2BBD262BFC32617D6BFE78F41591AB35F24EC2258C30C9E090D6FB6C3D86B3C819F89B83C6CCEDC6F6583747", "admin"},

	{NULL}
};

static char saved_salt[SALT_SIZE];
//static char saved_key[PLAINTEXT_LENGTH + 1];
static char *saved_key;

static unsigned char *crypted;
static int length_cipher;
static int length_salt;
static int m_cost;
static int t_cost;

static void char_to_bin(char *in, int char_length, char *bin)
{
	int i;
	for (i = 0; i < char_length; i += 2) {
		char a = in[i];
		char b = in[i + 1];
		if (a >= 60)
			a -= 55;
		else
			a -= 48;
		if (b >= 60)
			b -= 55;
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
	if (next_dollar == NULL || next_dollar - i > 32 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > 512 || strlen(i) == 0)
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

static void *get_salt(char *ciphertext)
{
	static char salt[SALT_SIZE + 5];
	char *i = ciphertext + 8;
        char *first_dollar,*second_dollar;
	char *last_dollar = strrchr(ciphertext, '$');
        char ct_cost,cm_cost;

	memset(salt, 0, sizeof(salt));
	
	salt[0] = (char)(strlen(last_dollar + 1) / 2);
	salt[1] = (char)(last_dollar - i);
	salt[last_dollar - i + 4] = 0;
	salt[SALT_SIZE + 4] = 0;
        first_dollar = strchr(i, '$');
        second_dollar=strchr(first_dollar+1,'$');

        ct_cost=atoi(i);

        cm_cost=atoi(first_dollar+1);
        
	salt[2]=ct_cost;
        salt[3]=cm_cost;	
	
	memcpy(salt + 4, second_dollar+1, salt[1]);

	return salt;
}

static void set_salt(void *salt)
{
	char *i = salt;
	unsigned char *o = salt;
	length_cipher = (int)o[0];
	if (length_cipher == 0)
		length_cipher = 256;
	i = i + 4;
	t_cost = o[2];
	m_cost = o[3];

	length_salt = strlen(i+4);
	memset(saved_salt,0,sizeof(saved_salt));
	memcpy(saved_salt, i, length_salt);
	saved_salt[length_salt] = 0;
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
                #ifdef SIMD_COEF_64
                POMELO_SSE2
                #else
		POMELO
                #endif
               (crypted + 1 + i * BINARY_SIZE, length_cipher,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt,
		    length_salt, t_cost, m_cost);
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
static unsigned int tunable_cost_N(void *salt)
{
	char *str=salt;
	return str[2];
}

static unsigned int tunable_cost_r(void *salt)
{
	char *str=salt;
	return str[3];
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
			"N",
			"r"
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
			tunable_cost_N,
			tunable_cost_r
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
