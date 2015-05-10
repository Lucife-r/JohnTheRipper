// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>
// modified in 2015 by Agnieszka Bielec <bielecagnieszka8 at gmail.com>

#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include "parallel.h"

#define HASH_LENGTH 64

void printHash(uint64_t *hash,int i)
{
	char buf[HASH_LENGTH*2+1];
	memset(buf,0,HASH_LENGTH*2+1);
	snprintf(buf,i*2+1,
		"%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 
		"%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 ,
		WRITE_BIG_ENDIAN_64(hash[0]),
		WRITE_BIG_ENDIAN_64(hash[1]),
		WRITE_BIG_ENDIAN_64(hash[2]),
		WRITE_BIG_ENDIAN_64(hash[3]),
		WRITE_BIG_ENDIAN_64(hash[4]),
		WRITE_BIG_ENDIAN_64(hash[5]),
		WRITE_BIG_ENDIAN_64(hash[6]),
		WRITE_BIG_ENDIAN_64(hash[7]));
      printf("%s",buf);
}

int main(int argc,char **argv)
{
	if (argc < 5)
		return 1;

	uint64_t *out=new uint64_t[(atoi(argv[3])+7)/8];

	PHS(out, atoi(argv[3]), argv[1], strlen(argv[1]), argv[2], strlen(argv[2]), atoi(argv[4]), 0);
	//printf("{\"$parallel$%d$%s$",atoi(argv[4]), argv[2]);
	printf("$parallel$%d$%s$",atoi(argv[4]), argv[2]);
	printHash(out,atoi(argv[3]));
	printf("\n");
	//printf("\",\"%s\"},\n",argv[1]);

	return 0;
}
