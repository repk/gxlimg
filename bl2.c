#include <stdlib.h>
#include <stdio.h>

#include "gxlimg.h"
#include "bl2.h"

int gi_bl2_create_img(char const *fin, char const *fout)
{
	DBG("Encode bl2 %s in %s\n", fin, fout);
	return 0;
}

int gi_bl2_extract(char const *fin, char const *fout)
{
	(void)fin;
	(void)fout;

	ERR("BL2 decoding is not implemented yet\n");

	return -1;
}
