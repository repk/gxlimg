#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include "gxlimg.h"
#include "bl3.h"
#include "amlcblk.h"
#include "amlsblk.h"
#include "ssl.h"

#include <lz4hc.h>

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

struct lz4_header {
	uint32_t magic;
	uint16_t unk0;
	uint16_t header_size;
	uint32_t original_size;
	uint32_t compressed_size;
	uint8_t file_sha256[32];
	char timestamp[32];
	uint8_t random_nonce[12];
	uint32_t magic_2;
	uint8_t header_sha256[32];
};

static int gi_bl3_lz4_wrap(char const *fin, char *fout,
		size_t fout_sz)
{
	struct stat st;
	struct lz4_header hdr;
	EVP_MD_CTX *ctx = NULL;
	uint8_t *src = NULL;
	uint8_t *dst = NULL;
	int fdin = -1, fdout = -1;
	int ret;
	int clen;

	ret = snprintf(fout, fout_sz, "%s.lz4", fin);
	if((ret < 0) || ((size_t)ret >= fout_sz)) {
		ret = -EINVAL;
		goto out;
	}

	fdin = open(fin, O_RDONLY);
	if(fdin < 0) {
		ret = -errno;
		goto out;
	}

	if(fstat(fdin, &st) < 0) {
		ret = -errno;
		goto out;
	}

	if((st.st_size < 0) || ((size_t)st.st_size > UINT32_MAX)) {
		ret = -EINVAL;
		goto out;
	}

	src = malloc((size_t)st.st_size);
	if(src == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	if(read(fdin, src, (size_t)st.st_size) != st.st_size) {
		ret = -errno;
		goto out;
	}

	dst = malloc((size_t)st.st_size + 0x400);
	if(dst == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	clen = LZ4_compress_HC((char const *)src, (char *)dst,
			(int)st.st_size, (int)st.st_size + 0x400, 0xc);
	if(clen <= 0) {
		ret = -EINVAL;
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = 0x43345a4c;
	hdr.magic_2 = 0x43345a4c;
	hdr.header_size = 0x80;
	hdr.original_size = (uint32_t)st.st_size;
	hdr.compressed_size = (uint32_t)clen;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL) {
		SSLERR(ret, "Cannot create digest context: ");
		goto out;
	}

	if(((size_t)st.st_size & 0xf) == 0) {
		ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
		if(ret != 1) {
			SSLERR(ret, "Cannot init digest context: ");
			goto out;
		}

		ret = EVP_DigestUpdate(ctx, src, (size_t)st.st_size);
		if(ret != 1) {
			SSLERR(ret, "Cannot hash file data: ");
			goto out;
		}

		ret = EVP_DigestFinal_ex(ctx, hdr.file_sha256, NULL);
		if(ret != 1) {
			SSLERR(ret, "Cannot finalize file hash: ");
			goto out;
		}
	}

	{
		time_t now = time(NULL);
		struct tm *tm = localtime(&now);
		if(tm == NULL) {
			ret = -EINVAL;
			goto out;
		}
		if(strftime(hdr.timestamp, sizeof(hdr.timestamp),
			"%Y%m%d%H:%M:%S", tm) == 0) {
			ret = -EINVAL;
			goto out;
		}
	}

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot init digest context: ");
		goto out;
	}

	ret = EVP_DigestUpdate(ctx, (uint8_t *)&hdr, 0x60);
	if(ret != 1) {
		SSLERR(ret, "Cannot hash lz4 header: ");
		goto out;
	}

	ret = EVP_DigestFinal_ex(ctx, hdr.header_sha256, NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot finalize lz4 header hash: ");
		goto out;
	}

	fdout = open(fout, O_WRONLY | O_CREAT | O_TRUNC, FOUT_MODE_DFT);
	if(fdout < 0) {
		ret = -errno;
		goto out;
	}

	if(write(fdout, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
		ret = -errno;
		goto out;
	}

	if(write(fdout, dst, (size_t)clen) != clen) {
		ret = -errno;
		goto out;
	}

	ret = 0;
out:
	if(fdout >= 0)
		close(fdout);
	if(fdin >= 0)
		close(fdin);
	EVP_MD_CTX_free(ctx);
	free(src);
	free(dst);
	return ret;
}

/**
 * Sign a BL3 boot image
 *
 * @param fin: Path of BL3 binary input file
 * @param fout: Path of BL3 boot image output file
 * @return: 0 on success, negative number otherwise
 */
int gi_bl3_sign_img(char const *fin, char const *fout,
		char const *compress)
{
	struct amlsblk asb;
	char lz4_path[512];
	char const *input = fin;
	int fdin = -1, fdout = -1, ret;

	DBG("Sign bl3x %s in %s\n", fin, fout);

	if(compress != NULL) {
		if(strcmp(compress, "lz4") != 0)
			return -EINVAL;
		ret = gi_bl3_lz4_wrap(fin, lz4_path, sizeof(lz4_path));
		if(ret < 0)
			return ret;
		input = lz4_path;
	}

	fdin = open(input, O_RDONLY);
	if(fdin < 0) {
		PERR("Cannot open file %s", input);
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

	ret = gi_amlsblk_init(&asb, fdin);
	if(ret < 0)
		goto out;

	ret = gi_amlsblk_hash_payload(&asb, fdin);
	if(ret < 0)
		goto out;

	ret = gi_amlsblk_build_header(&asb);
	if(ret < 0)
		goto out;

	ret = gi_amlsblk_flush_data(&asb, fdin, fdout);
out:
	if(fdout >= 0)
		close(fdout);
	if(fdin >= 0)
		close(fdin);
	if(input != fin)
		(void)unlink(input);
	return ret;
}

/**
 * Encrypt a BL3 boot image
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
 * Decrypt a BL3 boot image
 *
 * @param fin: Path of BL3 boot image to decode
 * @param fout: Path of result BL3 binary file
 * @return: 0 on success, negative number otherwise
 */
int gi_bl3_decrypt_img(char const *fin, char const *fout)
{
	struct amlcblk acb;
	int fdin = -1, fdout = -1, ret;

	DBG("Decrypt bl3 %s in %s\n", fin, fout);

	fdin = open(fin, O_RDONLY);
	if(fdin < 0) {
		PERR("Cannot open file %s", fin);
		ret = -errno;
		goto out;
	}

	fdout = open(fout, O_WRONLY | O_CREAT, FOUT_MODE_DFT);
	if(fdout < 0) {
		PERR("Cannot open file %s", fout);
		ret = -errno;
		goto out;
	}

	ret = ftruncate(fdout, 0);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_read_hdr(&acb, fdin);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_aes_dec(&acb, fdout, fdin);
	if(ret < 0)
		goto out;

out:
	if(fdout >= 0)
		close(fdout);
	if(fdin >= 0)
		close(fdin);
	return ret;
}
