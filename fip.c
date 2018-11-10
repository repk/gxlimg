#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "gxlimg.h"

int gi_fip_create(char const *bl2, char const *bl30, char const *bl31,
		char const *bl33, char const *fout)
{
	(void)bl2;
	(void)bl30;
	(void)bl31;
	(void)bl33;
	(void)fout;
	ERR("FIP final image creation not implemented yet\n");
	return -EINVAL;
}
