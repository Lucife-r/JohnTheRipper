/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on opencl_mysqlsha1_fmt_plug.c
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pomelo;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pomelo);
#else

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "pomelo-opencl"
#define FORMAT_NAME             "POMELO"
#define ALGORITHM_NAME          "POMELO OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

#define PLAINTEXT_LENGTH        55
#define CIPHERTEXT_LENGTH       600

#define BINARY_SIZE             257
#define BINARY_ALIGN            1
#define SALT_SIZE		32
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define MEM_SIZE                131072

#define STEP 0
#define SEED 256


//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer: ", "xfer: ", ", crypt: ", ", xfer: "
};

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

typedef struct {
	unsigned int h0, h1, h2, h3, h4;
} SHA_DEV_CTX;


static char *saved_key;
static unsigned int *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_result, cl_saved_real_salt,
    cl_saved_rest_salt, cl_memory;
static cl_mem pinned_key, pinned_idx, pinned_result, pinned_rest_salt,
    pinned_real_salt, pinned_memory;
static int partial_output;
static unsigned short int *saved_rest_salt;
static char *saved_real_salt, *output, *memory;


static struct fmt_tests tests[] = {
	{"$POMELO$2$2$S$982D98794C7D4E728552970972665E6BF0B829353C846E5063B78FDC98F8A61473218A18D5DBAEB0F987400F2CC44865EB02", "password"},
	{"$POMELO$2$2$salt$CBA3E72A1F3CAD74AE0E33F353787E82E1D808C65908B2EA57BA5BDD435D3BC645937A1772D1AA18D91D7164616B010810C359B04F4FFA58E60C04C6B8A095DE4500C18CD815A8960E54B0777A3279485EC559BE34D5DBFBF2A66BA61F386FC8896A18D8", "pass"},
	{"$POMELO$3$3$s$8129F2646C7583D996A87937475F4C10747F4A6D23BB65B3B28AD1F61C5EFCA58969CE8472B49135BB870F0264AFB3E7AE2D9FD798C2852C60543ECFB06528CCC8390F749803ABF2D8F67DB4F4B07297174DF7628DC1EA58DB862DF4ECE41F1E829550E8DC2BDD6B4F44431B21A9C5657162E8BD2869A79F7B23BAD01D4417957CE5439691DA82F81B018CAB9F57B38AE19F2F307C849D2FE3A7CE38081175405DD71E08CA804D5DBEC6FAA623ADCFC67445DD0336A3F9BA91CF1EB7B0239138DD23FCB1989D2BF2EADADE2DC4639E5B811514A2885D7535C707D3003BDCCE59A9B5B9B085385B044EAE8527A31C5972B1A5F3F17F522899B8F0B2BF9036D697", "home"},
	{NULL}
};

static char *saved_key;

static int length_cipher;
static int length_salt;

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
		    8 : 1;
	else
		return 64;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{

	pinned_key =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	pinned_rest_salt =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	    4 * sizeof(unsigned short int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");

	pinned_real_salt =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_SIZE, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");

	cl_saved_key =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_saved_real_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_SIZE, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_saved_rest_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    4 * sizeof(unsigned short int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	saved_key =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	saved_rest_salt =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_rest_salt, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, 4 * sizeof(unsigned short int), 0,
	    NULL, NULL, &ret_code);
	saved_real_salt =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_real_salt, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, SALT_SIZE, 0, NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	    sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * (gws + 1), 0,
	    NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    ((BINARY_SIZE * gws) + 4) / 4 * 4, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    ((BINARY_SIZE * gws) + 4) / 4 * 4, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, ((BINARY_SIZE * gws) + 4) / 4 * 4,
	    0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");



	pinned_memory =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    ((MEM_SIZE * gws) + 4) / 4 * 4, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_memory =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    ((MEM_SIZE * gws) + 4) / 4 * 4, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	memory =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_memory, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, ((MEM_SIZE * gws) + 4) / 4 * 4, 0,
	    NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping memory");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
		(void *)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_real_salt), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
		(void *)&cl_saved_rest_salt), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem),
		(void *)&cl_memory), "Error setting argument 5");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result,
		output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key,
		saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx,
		saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_real_salt,
		saved_real_salt, 0, NULL, NULL),
	    "Error Unmapping saved_real_salt");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_rest_salt,
		saved_rest_salt, 0, NULL, NULL),
	    "Error Unmapping saved_rest_salt");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_memory,
		memory, 0, NULL, NULL), "Error Unmapping memory");
	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	    "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result),
	    "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_memory),
	    "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key),
	    "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_idx),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_real_salt),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_rest_salt),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx),
	    "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_real_salt),
	    "Release real salt");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_rest_salt),
	    "Release rest salt");
	HANDLE_CLERROR(clReleaseMemObject(cl_memory), "Release memory");
}


static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
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


static void init(struct fmt_main *self)
{
	char build_opts[64];
	size_t gws_limit;


	opencl_init("$JOHN/kernels/pomelo_kernel.cl", gpu_id, build_opts);

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4M or so.
	gws_limit = MIN((1 << 26) * 4 / MEM_SIZE,
	    get_max_mem_alloc_size(gpu_id) / MEM_SIZE);


	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "pomelo_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 2, self, create_clobj, release_clobj, MEM_SIZE, gws_limit);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 100, 200);

}

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *key, int index)
{
	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;

	/* Early partial transfer to GPU every 256K keys */
	if (index && !(index & (256 * 1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
			cl_saved_key, CL_FALSE, key_offset,
			key_idx - key_offset, saved_key + key_offset, 0, NULL,
			NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
			cl_saved_idx, CL_FALSE, idx_offset,
			sizeof(cl_uint) * index - idx_offset,
			saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL,
			NULL), "Failed transferring index");
		idx_offset = sizeof(cl_uint) * index;
		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	}

}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index + 1] - saved_idx[index];
	char *key = (char *)&saved_key[saved_idx[index]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

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

static void *binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	char *ii;

	ciphertext += 1;

	memset(realcipher, 0, BINARY_SIZE);


	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	realcipher[0] = strlen(ii) / 2;
	char_to_bin(ii, strlen(ii), realcipher + 1);

	return (void *)realcipher;
}

static void *salt(char *ciphertext)
{
	static char salt[SALT_SIZE + 3];
	char *i = ciphertext + 8;
	char *last_dollar = strrchr(ciphertext, '$');
	memset(salt, 0, sizeof(salt));
	memcpy(salt + 2, i, last_dollar - i);
	salt[0] = (char)(strlen(last_dollar + 1) / 2);
	salt[1] = (char)(last_dollar - i);
	return salt;
}


static void set_salt(void *salt)
{
	int length_cipher;
	unsigned short int m_cost, t_cost;
	char *first_dollar, *second_dollar;
	char *i = salt;
	unsigned char *o = salt;
	char number[5];
	length_cipher = (int)o[0];
	if (length_cipher == 0)
		length_cipher = 256;
	i = i + 2;
	first_dollar = strchr(i, '$');
	second_dollar = strrchr(i, '$');
	memcpy(number, i, first_dollar - i);
	number[4] = 0;
	t_cost = atoi(number);
	memcpy(number, first_dollar + 1, second_dollar - first_dollar - 1);
	m_cost = atoi(number);
	length_salt = strlen(second_dollar + 1);
	memset(saved_real_salt, 0, SALT_SIZE);
	memcpy(saved_real_salt, second_dollar + 1, MIN(length_salt,
		SALT_SIZE));

	saved_rest_salt[0] = length_cipher;
	saved_rest_salt[1] = length_salt;
	saved_rest_salt[2] = t_cost;
	saved_rest_salt[3] = m_cost;
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
		if (!memcmp(binary, output + i * BINARY_SIZE, length))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	unsigned char *str_binary = binary;
	int len = str_binary[0];
	if (len == 0)
		len = 256;
	return !memcmp(binary, output + index * BINARY_SIZE, len);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;


	global_work_size =
	    local_work_size ? (count + local_work_size -
	    1) / local_work_size * local_work_size : count;

	/* Self-test cludge */
	if (idx_offset > 4 * (global_work_size + 1))
		idx_offset = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_rest_salt,
		CL_FALSE, 0, 4 * sizeof(unsigned short int), saved_rest_salt,
		0, NULL, multi_profilingEvent[0]), "Failed transferring keys");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_real_salt,
		CL_FALSE, 0, SALT_SIZE, saved_real_salt, 0, NULL,
		multi_profilingEvent[1]), "Failed transferring keys");

	if (key_idx > key_offset)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
			cl_saved_key, CL_FALSE, key_offset,
			key_idx - key_offset, saved_key + key_offset, 0, NULL,
			multi_profilingEvent[2]), "Failed transferring keys");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx,
		CL_FALSE, idx_offset,
		sizeof(cl_uint) * (global_work_size + 1) - idx_offset,
		saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL,
		multi_profilingEvent[3]), "Failed transferring index");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");


	// read back 
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE,
		0, BINARY_SIZE * count, output, 0, NULL,
		multi_profilingEvent[5]), "failed in reading data back");
	partial_output = 1;


	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0x7FFFFFF;
}


struct fmt_main fmt_opencl_pomelo = {
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
		    FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		    {NULL},
#endif
	    tests}, {
		    init,
		    done,
		    fmt_default_reset,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
#if FMT_MAIN_VERSION > 11
		    {NULL},
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
		    fmt_default_salt_hash,
		    NULL,
		    set_salt,
		    set_key,
		    get_key,
		    clear_keys,
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

#endif				/* plugin stanza */

#endif				/* HAVE_OPENCL */
