#include <stdlib.h>
#include <stdio.h>

#include "gxlimg.h"
#include "bl3.h"

int gi_bl3_create_img(char const *fin, char const *fout)
{
	DBG("Encode bl3 %s in %s\n", fin, fout);
	return 0;
}

int gi_bl3_extract(char const *fin, char const *fout)
{
	(void)fin;
	(void)fout;

	ERR("BL3 decoding is not supported yet\n");

	return -1;
}
