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
#define BENCHMARK_LENGTH        0

#define PLAINTEXT_LENGTH        125
#define CIPHERTEXT_LENGTH       512

#define BINARY_SIZE             256
#define BINARY_ALIGN            1
#define SALT_SIZE		64
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

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

static char *saved_key;
static unsigned int *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_result, cl_saved_salt, cl_memory;
static cl_mem pinned_key, pinned_idx, pinned_result,
    pinned_memory, pinned_salt;
static int partial_output;
static char *output, *memory;
static unsigned long long int MEM_SIZE;
static unsigned short cm_cost;
static struct pomelo_salt *saved_salt;
static char *saved_key;
static int clobj_allocated;


static struct fmt_main *self;

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
	if (clobj_allocated)
		return;
	clobj_allocated = 1;
	pinned_memory =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    MEM_SIZE * gws * 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_memory =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    MEM_SIZE * gws * 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	memory =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_memory, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, MEM_SIZE * gws * 8, 0,
	    NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping memory");


	pinned_key =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");

	pinned_salt =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct pomelo_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");


	cl_saved_key =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_saved_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct pomelo_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	saved_key =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	saved_salt =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct pomelo_salt), 0, NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");

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
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
		(void *)&cl_memory), "Error setting argument 4");
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
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_memory,
		memory, 0, NULL, NULL), "Error Unmapping memory");

	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	    "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_memory),
	    "Release pinned result buffer");
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
	    "Release real salt");
	HANDLE_CLERROR(clReleaseMemObject(cl_memory), "Release memory");
}


static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}


static unsigned short max_test_cost()
{
	int i;
	unsigned short M_COST = 0;
	for (i = 0; tests[i].ciphertext; i++) {
		get_salt(tests[i].ciphertext);
		M_COST = MAX(M_COST, cm_cost);
	}
	return M_COST;
}

static void reset_(unsigned short M_COST)
{
	char build_opts[128];
	MEM_SIZE = 1ULL << (10 + M_COST);	//13 for char, 10 for long

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d", BINARY_SIZE, SALT_SIZE);

	opencl_init("$JOHN/kernels/pomelo_kernel.cl", gpu_id, build_opts);


	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "pomelo_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");

	release_clobj();
	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, MEM_SIZE * 8, 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 1000, 10000);
}

static void reset(struct db_main *db)
{
	unsigned short M_COST;
	if (!db) {
		M_COST = max_test_cost();
		reset_(M_COST);
	} else {
		struct db_salt *salt = db->salts;
		M_COST = 0;
		while (salt != NULL) {
			M_COST = MAX(M_COST, salt->cost[1]);
			salt = salt->next;
		}
		reset_(M_COST);
	}
}

static void init(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
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
	if (next_dollar == NULL || next_dollar - i > 2 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE ||
	    next_dollar == i)
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

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
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
	cm_cost=salt.m_cost = atoi(first_dollar+1);

	memcpy(salt.salt, second_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct pomelo_salt));
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary,output + i * BINARY_SIZE, saved_salt->hash_size))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output + index * BINARY_SIZE,  saved_salt->hash_size);
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


	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct pomelo_salt), saved_salt, 0, NULL,
		multi_profilingEvent[0]), "Failed transferring salt");

	if (key_idx > key_offset)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
			cl_saved_key, CL_FALSE, key_offset,
			key_idx - key_offset, saved_key + key_offset, 0, NULL,
			multi_profilingEvent[1]), "Failed transferring keys");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx,
		CL_FALSE, idx_offset,
		sizeof(cl_uint) * (global_work_size + 1) - idx_offset,
		saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL,
		multi_profilingEvent[2]), "Failed transferring index");


	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");


	// read back 
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE,
		0, BINARY_SIZE * count, output, 0, NULL,
		multi_profilingEvent[4]), "failed in reading data back");
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
		sizeof(struct pomelo_salt),
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
		reset,
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
