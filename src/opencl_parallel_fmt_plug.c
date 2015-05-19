/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on opencl_mysqlsha1_fmt_plug.c
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_parallel;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_parallel);
#else

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "common-opencl.h"


#define FORMAT_LABEL			"parallel-opencl"
#define FORMAT_NAME			"parallel SHA-512"

#define ALGORITHM_NAME			" "

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125
#define HASH_LENGTH			64

#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			64

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define SEED 256

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer salt1: ", ", xfer salt2: ", ", xfer keys: ", ", xfer idx: ",
	", crypt: ", ", xfer: "
};

#define MAX(a, b)		(((a) > (b)) ? (a) : (b))


static struct fmt_tests tests[] = {
	{"$parallel$0$salt$6ee2fc021128a12b421606081687c7a5f17079400895a810ba4dffce1c5e4952a2c6ee370d7955bf9e479087405525dbdc62901e2851fd78ef4c42a8e2b8842d","password"},
	{"$parallel$0$salt$43dd067982f03038451443ee265ddee3b5c166d1c17bfa693c7ff90bbf3857fda16807e6f0f2a7d547b256846fa4708259c4520738bc107309af9dc6f9fb5f41","admin"},
	{"$parallel$0$salt$6ee2fc021128a12b421606081687c7a5f17079400895a810ba4dffce1c5e4952","password"},
	{"$parallel$1$salt$13528220310eb5bd3f91abf322a50b7846a90a67c83d2515a2d19fdf7c1dc227a8fadab0b81960357556255ccfc8306265b0d0b94bfe1b9530844effafdc86a2","password"},
	{"$parallel$2$salt$e1085b1a23f7f8d174ebd3d650e783d6a2b5880890cef82817b69ee5e82dbe3a9aec46925d26b4eab45fa3a3b6034e9c7a6669772d71259737d5f0bad5060113","password"},
	{"$parallel$3$salt$e210bcdc45b17f4a3751358f5f7b23fe0e70124e49b3a6be7204a047c7afba45febd59848e16dd4899043b9d40fe387865412c167dfb955d0a08c026ba424416","password"},
	{"$parallel$65536$salt$af6cf841f2650c8ee1fe25bbc9308956bd43cb728eb290c031d8eb6edf22e055a02afcd4e54a1cab29d6b2ff1e0ee786d7ff1eaa52fb56cef57c0d0e993c9856","password"},
	{"$parallel$131073$salt$7ef6f47049e949e5fbdcd323c72b787dc33f3467d7c545b207434862d4df1d7f4a3864fcbc724d417c9b3144aa2ea1326f81f4c639b75509277df4237f0fc7","password"},
	{NULL}
};

struct parallel_salt {
	uint32_t cost;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

static char *saved_key;
static unsigned int *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_result, cl_saved_salt;
static cl_mem pinned_key, pinned_idx, pinned_result, pinned_salt;
static int partial_output;
static struct parallel_salt *saved_salt;
static char *output;
static char *saved_key;

int clobj_allocated;

static void *get_salt(char *ciphertext);

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
	if(clobj_allocated)
		release_clobj();
	
	clobj_allocated = 1;
	pinned_key =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");

	pinned_salt =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct parallel_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");


	cl_saved_key =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_saved_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct parallel_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	saved_key =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	saved_salt =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct parallel_salt), 0, NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping salt");

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

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
		(void *)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3");
}

static void release_clobj(void)
{
	if (!clobj_allocated)
		return;
	clobj_allocated = 0;
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result,
		output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key,
		saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx,
		saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt,
		saved_salt, 0, NULL, NULL),
	    "Error Unmapping saved_salt");

	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	    "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result),
	    "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key),
	    "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_idx),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx),
	    "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_salt),
	    "Release salt");
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
	size_t cost;

	if (strncmp(ciphertext, "$parallel$", 8) &&
	    strncmp(ciphertext, "$parallel$", 8))
		return 0;
	i = ciphertext + 10;
	//cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 10 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	cost=atoi(i);
	if ((cost & 0xffff) > 106 || (cost >> 16) > 126)
		return 0;
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


static void init(struct fmt_main *self)
{
	char build_opts[128];
	clobj_allocated = 0;

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d -DPLAINTEXT_LENGTH=%d -DHASH_LENGTH=%d", BINARY_SIZE, SALT_SIZE,PLAINTEXT_LENGTH,HASH_LENGTH);

	opencl_init("$JOHN/kernels/parallel_kernel.cl", gpu_id, build_opts);

	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "parallel_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");


	release_clobj();
	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, BINARY_SIZE*2, 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 100, 1000);
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
	static struct parallel_salt salt;
	char *i = ciphertext + 10;
	char *first_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');

	salt.salt_length = last_dollar - first_dollar - 1;
	salt.cost = atoi(i);

	memcpy(salt.salt, first_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct parallel_salt));
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary, output + i * BINARY_SIZE, saved_salt->hash_size))
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
	return !memcmp(binary, output + index * BINARY_SIZE,  saved_salt->hash_size);
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


	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct parallel_salt), saved_salt, 0, NULL,
		multi_profilingEvent[1]), "Failed transferring real salt");

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

static int salt_hash(void *_salt)
{
	int i;
	struct parallel_salt *salt = (struct parallel_salt*)_salt;
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
	struct parallel_salt *salt=(struct parallel_salt *)_salt;
	return salt->cost;
}

#endif

struct fmt_main fmt_opencl_parallel = {
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
		sizeof(struct parallel_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
				"N"
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
			fmt_default_binary_hash_6
		},
		salt_hash,
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
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif				/* plugin stanza */

#endif				/* HAVE_OPENCL */
