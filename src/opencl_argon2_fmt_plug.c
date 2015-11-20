/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_argon2i;
extern struct fmt_main fmt_opencl_argon2d;
extern struct fmt_main fmt_opencl_argon2id;
extern struct fmt_main fmt_opencl_argon2ds;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_argon2i);
john_register_one(&fmt_opencl_argon2d);
john_register_one(&fmt_opencl_argon2id);
john_register_one(&fmt_opencl_argon2ds);
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

#include "common-opencl.h"

#define FORMAT_LABEL			"argon2-opencl" //todo: opencl_get_user_preferences(FORMAT_LABEL);

#define FORMAT_LABEL_i			"argon2i-opencl"
#define FORMAT_LABEL_d			"argon2d-opencl"
#define FORMAT_LABEL_id			"argon2id-opencl"
#define FORMAT_LABEL_ds			"argon2ds-opencl"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"Blake2 OpenCL"//todo: this is Blake or Blamka?

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

#define SEED 				256

#define PREFIX_i			"$argon2i$"
#define PREFIX_d			"$argon2d$"
#define PREFIX_id			"$argon2id$"
#define PREFIX_ds			"$argon2ds$"

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer salt1: ", ", xfer salt2: ", ", xfer keys: ", ", xfer lengths: ",
	", crypt: ", ", xfer: "
};

static struct fmt_tests tests_i[] = {
	{"$argon2i$3$1536$1$damage_done$DC62B7B469BDF17DB335062CDCEF7F565700B414D5EBEE2431D86001BC21385E","cathode_ray_sunshine"},
	{"$argon2i$3$1536$1$damage_done$CEA354D7561288FA131BD4E955B627ED729FAAD29D3A648D0C660CECB9BC8993","dry_run"},
	{"$argon2i$3$1536$2$character$CAF9D6C20D16FD3E31A15BD877E1A7E2D5A6773FFE472429B2605E2838A3C07C","out_of_nothing"},
	{"$argon2i$3$1536$2$character$5D33084B9E65DE8B530C129683608FF8DD62EB4C908EEC622C7F0331A90CF32A","mind_matters"},
	{NULL}
};

static struct fmt_tests tests_d[] = {
	{"$argon2d$3$1536$1$damage_done$248B76AE28BC53BAC90DDCEE5FC5EDF5202ADCA4EEED247422B9884A08F27F07","cathode_ray_sunshine"},
	{"$argon2d$3$1536$1$damage_done$E3346BB4F82CAB940B7076960B5EDA25C05CEB523833BBFCC4AF710C502F1EAE","dry_run"},
	{"$argon2d$3$1536$2$character$7B81912A94FBC8A89BEDB6115DCDE493588E22B8BA598F8F4F4CEA36AF24E495","out_of_nothing"},
	{"$argon2d$3$1536$2$character$9F377B08B12C69C777B5F914A3DAB2D241AB324632E49ADF74688BBB886F49B3","mind_matters"},
	{NULL}
};

static struct fmt_tests tests_id[] = {
	{"$argon2id$3$1536$1$damage_done$BCB4FA53A26DED26B15C4E38204548BC7B3069AFB3922A8B564A2AE1061E14BF","cathode_ray_sunshine"},
	{"$argon2id$3$1536$1$damage_done$3EA55DE5C5E5909920A9D312B7F8210A2531C5DF7965C031C24ADABB714EBEB3","dry_run"},
	{"$argon2id$3$1536$2$character$E3A380C483EDA431A8E0010A53FF839F06FBF30A3693E4AC48939AAD7EB014FD","out_of_nothing"},
	{"$argon2id$3$1536$2$character$3F2B03CC6BD8C9221720C6787706EBA2EFB98A3D22A2F66A56FD861E3486818B","mind_matters"},
	{NULL}
};

static struct fmt_tests tests_ds[] = {
	{"$argon2ds$3$1536$1$damage_done$B8E1B34ECA81A366CA5EC166BB1EC0079106846C3591F1635441016726D27B07","cathode_ray_sunshine"},
	{"$argon2ds$3$1536$1$damage_done$AB0AF8C9F5ACAA6D2077D4AEB816EF68B1A3C3FF13FA18EBBFF9128884B9E403","dry_run"},
	{"$argon2ds$3$1536$2$character$44A0849C6D7BFD33A7001CF368155195FCC5A2F73F9A90195467EDEA857960DC","out_of_nothing"},
	{"$argon2ds$3$1536$2$character$6C8E43855B9C6139F81D6CE95B38C75491CA6E9DD9DC116F31B8197307626C17","mind_matters"},
	{NULL}
};

struct argon2_salt {
	uint32_t t_cost;
	uint32_t m_cost;
	uint32_t lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	Argon2_type type;
	char salt[SALT_SIZE];
};

struct argon2_salt * saved_salt;
static char *saved_key;
static unsigned int *saved_lengths;
static cl_mem cl_saved_key, cl_saved_lengths, cl_result, cl_saved_salt, cl_memory, cl_pseudo_rands, cl_sbox;
static cl_mem pinned_key, pinned_lengths, pinned_result, pinned_salt;
static char *output;
static uint64_t MEM_SIZE, PSEUDO_RANDS_SIZE;
static char *saved_key;
static int clobj_allocated;
static uint saved_gws;

static struct fmt_main *self;

int DS, I;

static void *get_salt(char *ciphertext);

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void)
{
	if (!clobj_allocated)
		return;
	clobj_allocated = 0;

	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_lengths, saved_lengths, 0, NULL, NULL), "Error Unmapping saved_lengths");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_lengths), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_salt), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_lengths), "Release index buffer");

	HANDLE_CLERROR(clReleaseMemObject(cl_memory), "Release memory buffer");
	if(I)
	  HANDLE_CLERROR(clReleaseMemObject(cl_pseudo_rands), "Release memory buffer");
	if(DS)
	  HANDLE_CLERROR(clReleaseMemObject(cl_sbox), "Release memory buffer");
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	if (clobj_allocated)
		release_clobj();
	clobj_allocated = 1;

	saved_gws=gws;

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct argon2_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct argon2_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_salt = clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct argon2_salt), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");

	pinned_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_lengths = clEnqueueMapBuffer(queue[gpu_id], pinned_lengths, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_lengths");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BINARY_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	cl_memory = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MEM_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping memory");
	if(I)
	{
	  cl_pseudo_rands = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, PSEUDO_RANDS_SIZE * gws, NULL, &ret_code);
	  HANDLE_CLERROR(ret_code, "Error mapping pseudo_rands");
	}
	if(DS)
	{
	   cl_sbox = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (sizeof(uint64_t)*ARGON2_SBOX_SIZE) * gws, NULL, &ret_code);
	   HANDLE_CLERROR(ret_code, "Error mapping sbox");
	}

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *)&cl_saved_lengths), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
		(void *)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
		(void *)&cl_memory), "Error setting argument 4");
	if(I)
	  HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem),
		(void *)&cl_pseudo_rands), "Error setting argument 5");
	else
	  HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem),
		NULL), "Error setting argument 5");
	if(DS)
	  HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(cl_mem),
		(void *)&cl_sbox), "Error setting argument 6");
	else
	  HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(cl_mem),
		NULL), "Error setting argument 6");
}

static void done(void)
{
	if(autotuned)
	{
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
	}
}


static void reset_(uint64_t mem_size, uint64_t pseudo_rands)
{
	char build_opts[128];
	size_t size;
	
	MEM_SIZE=mem_size;
	PSEUDO_RANDS_SIZE=pseudo_rands;

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d -DPLAINTEXT_LENGTH=%d", BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH);

	opencl_init("$JOHN/kernels/argon2_kernel.cl", gpu_id, build_opts);


	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "argon2_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");

	release_clobj();
	
	size=MEM_SIZE+PSEUDO_RANDS_SIZE;
	if(DS)
	  size+=sizeof(uint64_t)*ARGON2_SBOX_SIZE;

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, size, 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
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
	size_t mem_size, pseudo_rands_size;
	uint32_t memory_blocks, segment_length;
	size_t max_mem_size, max_pseudo_rands_size;
	max_mem_size=max_pseudo_rands_size=0;
	if(!autotuned)
	{
		int i;
		uint32_t prev_memory;
		prev_memory=0;
		if (!db) { //self tests
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct argon2_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				
				memory_blocks = salt->m_cost;
				if (memory_blocks < 2 * ARGON2_SYNC_POINTS * salt->lanes) {
				      memory_blocks = 2 * ARGON2_SYNC_POINTS * salt->lanes;
				}
				segment_length = memory_blocks / (salt->lanes * ARGON2_SYNC_POINTS);
				// Ensure that all segments have equal length
				memory_blocks = segment_length * (salt->lanes * ARGON2_SYNC_POINTS);

				mem_size= sizeof(block)*memory_blocks;
				pseudo_rands_size=sizeof(uint64_t)*segment_length;
				
				max_mem_size = MAX(max_mem_size, mem_size);
				max_pseudo_rands_size = MAX(max_pseudo_rands_size, pseudo_rands_size);
				
				if(i==0)
				{
					if (options.verbosity > 3)
					{
					  printf("\n");
					  print_memory(mem_size+pseudo_rands_size);
					}
					prev_memory=mem_size+pseudo_rands_size; //for print max memory
				}
			}

			if(prev_memory!=max_mem_size+max_pseudo_rands_size)
			{
				if (options.verbosity > 3)
				{
				  printf("max ");
				  print_memory(max_mem_size+max_pseudo_rands_size);
				}
			}
			reset_(max_mem_size, max_pseudo_rands_size);
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct argon2_salt * salt=salts->salt;
				salts = salts->next;
				
				memory_blocks = salt->m_cost;
				if (memory_blocks < 2 * ARGON2_SYNC_POINTS * salt->lanes) {
					memory_blocks = 2 * ARGON2_SYNC_POINTS * salt->lanes;
				}
				segment_length = memory_blocks / (salt->lanes * ARGON2_SYNC_POINTS);
				// Ensure that all segments have equal length
				memory_blocks = segment_length * (salt->lanes * ARGON2_SYNC_POINTS);

				mem_size= sizeof(block)*memory_blocks;
				
				pseudo_rands_size=sizeof(uint64_t)*segment_length;
				
				max_mem_size = MAX(max_mem_size, mem_size);
				max_pseudo_rands_size = MAX(max_pseudo_rands_size, pseudo_rands_size);
			}

			if (options.verbosity > 3)
			{
			  printf("\n");
			  print_memory(max_mem_size+max_pseudo_rands_size);
			}
			reset_(max_mem_size, max_pseudo_rands_size);
		}
	}
}

static void init_i(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
	
	DS=0;
	I=1;
}

static void init_id(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
	
	DS=0;
	I=1;
}

static void init_d(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
	
	DS=0;
	I=0;
}

static void init_ds(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;

	DS=1;
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
	int i,len;
	len=strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len=PLAINTEXT_LENGTH;

	for(i=0;i<len;i++)
		saved_key[PLAINTEXT_LENGTH*index+i] = key[i];

	saved_lengths[index]=len;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_lengths[index];
	char *key = (char *)&saved_key[PLAINTEXT_LENGTH*index];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static void clear_keys(void)
{
	memset(saved_lengths,0,sizeof(cl_uint)*saved_gws);
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


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct argon2_salt));
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

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct argon2_salt), saved_salt, 0, NULL,
		multi_profilingEvent[0]), "Failed transferring salt");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
		cl_saved_key, CL_FALSE, 0,
		count*PLAINTEXT_LENGTH, saved_key, 0, NULL,
		multi_profilingEvent[1]), "Failed transferring keys");


	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_lengths,
		CL_FALSE, 0, sizeof(cl_uint) * (global_work_size),
		saved_lengths, 0, NULL, multi_profilingEvent[2]), "Failed transferring index");


	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");


	// read back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE,
		0, BINARY_SIZE * count, output, 0, NULL,
		multi_profilingEvent[4]), "failed in reading data back");


	return count;
}


static int crypt_all_i(int *pcount, struct db_salt *salt)
{
	saved_salt->type=Argon2_i;
	return crypt_all(pcount, salt);
}

static int crypt_all_d(int *pcount, struct db_salt *salt)
{
	saved_salt->type=Argon2_d;
	return crypt_all(pcount, salt);
}

static int crypt_all_id(int *pcount, struct db_salt *salt)
{
	saved_salt->type=Argon2_id;
	return crypt_all(pcount, salt);
}

static int crypt_all_ds(int *pcount, struct db_salt *salt)
{
	saved_salt->type=Argon2_ds;
	return crypt_all(pcount, salt);
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

struct fmt_main fmt_opencl_argon2i = {
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
		init_i,
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
		clear_keys,
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

struct fmt_main fmt_opencl_argon2d = {
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
		init_d,
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
		clear_keys,
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

struct fmt_main fmt_opencl_argon2id = {
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
		init_id,
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
		clear_keys,
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

struct fmt_main fmt_opencl_argon2ds = {
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
		done,
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
		clear_keys,
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

#endif //#ifdef HAVE_OPENCL
