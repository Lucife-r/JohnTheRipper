// PHC submission:  POMELO v2  
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)  
// This code was written by Hongjun Wu on Jan 31, 2015.  

// This codes gives the C implementation of POMELO on 64-bit platform (little-endian) 

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes   
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)    
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;   
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)    

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pomelo.h"


int POMELO(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	unsigned long long i, j, temp;
	unsigned long long i0, i1, i2, i3, i4;
	unsigned long long *S;
	unsigned long long random_number, index_global, index_local;
	unsigned long long state_size, mask, mask1;

	//check the size of password, salt and output. Password is at most 256 bytes; the salt is at most 32 bytes. 
	if (inlen > 256 || saltlen > 64 || outlen > 256 || inlen < 0 ||
	    saltlen < 0 || outlen < 0)
		return 1;

	//Step 1: Initialize the state S          
	state_size = 1ULL << (13 + m_cost);	// state size is 2**(13+m_cost) bytes 
	S = (unsigned long long *)malloc(state_size);
	mask = (1ULL << (8 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1ULL << (10 + m_cost)) - 1;	// mask is used for modulation: modulo size_size/8; 

	//Step 2: Load the password, salt, input/output sizes into the state S
	for (i = 0; i < inlen; i++)
		((unsigned char *)S)[i] = ((unsigned char *)in)[i];	// load password into S
	for (i = 0; i < saltlen; i++)
		((unsigned char *)S)[inlen + i] = ((unsigned char *)salt)[i];	// load salt into S
	for (i = inlen + saltlen; i < 384; i++)
		((unsigned char *)S)[i] = 0;
	((unsigned char *)S)[384] = inlen & 0xff;	// load password length (in bytes) into S;
	((unsigned char *)S)[385] = (inlen >> 8) & 0xff;	// load password length (in bytes) into S;
	((unsigned char *)S)[386] = saltlen;	// load salt length (in bytes) into S;
	((unsigned char *)S)[387] = outlen & 0xff;	// load output length (in bytes into S)
	((unsigned char *)S)[388] = (outlen >> 8) & 0xff;	// load output length (in bytes into S) 
	((unsigned char *)S)[389] = 0;
	((unsigned char *)S)[390] = 0;
	((unsigned char *)S)[391] = 0;

	((unsigned char *)S)[392] = 1;
	((unsigned char *)S)[393] = 1;
	for (i = 394; i < 416; i++)
		((unsigned char *)S)[i] =
		    ((unsigned char *)S)[i - 1] + ((unsigned char *)S)[i - 2];

	//Step 3: Expand the data into the whole state  
	for (i = 13 * 4; i < (1ULL << (10 + m_cost)); i = i + 4)
		F0(i);

	//Step 4: Update the state using function G  
	random_number = 123456789ULL;
	for (i = 0; i < (1ULL << (9 + m_cost + t_cost)); i = i + 128)
		G(i, random_number);

	//Step 5: Update the state using function H     
	for (i = 1ULL << (9 + m_cost + t_cost);
	    i < (1ULL << (10 + m_cost + t_cost)); i = i + 128)
		H(i, random_number);

	//Step 6: Update the state using function F 
	for (i = 0; i < (1ULL << (10 + m_cost)); i = i + 4)
		F(i);

	//Step 7: Generate the output   
	memcpy(out, ((unsigned char *)S) + state_size - outlen, outlen);
	memset(S, 0, state_size);	// clear the memory 
	free(S);		// free the memory

	return 0;
}


static void bin_to_char(unsigned char *bin, int bin_length, unsigned char *out)
{
	int i;
	for (i = 0; i < bin_length; i++) {
		out[i * 2] = (bin[i] >> 4);
		out[i * 2 + 1] = (bin[i]) << 4;
		out[i * 2 + 1] = out[i * 2 + 1] >> 4;
		if (out[i * 2] >= 10)
			out[i * 2] += 55;
		else
			out[i * 2] += 48;
		if (out[i * 2 + 1] >= 10)
			out[i * 2 + 1] += 55;
		else
			out[i * 2 + 1] += 48;
	}
}


void POMELO_gen(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	char *m = malloc(512);
	char *cout = malloc(1024);
	POMELO(m, outlen, in, inlen, salt, saltlen, t_cost, m_cost);
	bin_to_char(m, outlen, cout);

	sprintf(out, "$POMELO$%d$%d$%s$%s\n", t_cost, m_cost, salt, cout);
	free(m);
	free(cout);
}
