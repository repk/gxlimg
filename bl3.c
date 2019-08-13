#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "gxlimg.h"
#include "bl3.h"
#include "amlcblk.h"

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

/**
 * Create a BL3 boot image
 *
 * @param fin: Path of BL3 binary input file
 * @param fout: Path of BL3 boot image output file
 * @return: 0 on success, negative number otherwise
 */
int gi_bl3_encrypt_img(char const *fin, char const *fout)
{
	struct amlcblk acb;
	int fdin = -1, fdout = -1, ret;

	DBG("Encode bl3 %s in %s\n", fin, fout);

	fdin = open(fin, O_RDONLY);
	if(fdin < 0) {
		PERR("Cannot open file %s", fin);
		ret = -errno;
		goto out;
	}

	fdout = open(fout, O_RDWR | O_CREAT, FOUT_MODE_DFT);
	if(fdout < 0) {
		PERR("Cannot open file %s", fout);
		ret = -errno;
		goto out;
	}

	ret = ftruncate(fdout, 0);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_init(&acb, fdin);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_aes_enc(&acb, fdout, fdin);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_dump_hdr(&acb, fdout);
out:
	if(fdout >= 0)
		close(fdout);
	if(fdin >= 0)
		close(fdin);
	return ret;
}

/**
 * Extract and decode a BL3 boot image
 *
 * @param fin: Path of BL3 boot image to decode
 * @param fout: Path of result BL3 binary file
 * @return: 0 on success, negative number otherwise
 */
int gi_bl3_extract(char const *fin, char const *fout)
{
	(void)fin;
	(void)fout;

	ERR("BL3 decoding is not supported yet\n");

	return -1;
}
