#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "gxlimg.h"
#include "amlcblk.h"

#define SSLERR(ret, ...) do						\
{									\
	char __sslerrbuf[256];						\
	fprintf(stderr, __VA_ARGS__);					\
	ERR_error_string_n(-ret, __sslerrbuf, sizeof(__sslerrbuf));	\
	fprintf(stderr, "%s\n", __sslerrbuf);				\
} while(0)


#define AMLCBLK_ENCRYPT (1 << 0)
#define AMLCBLK_HDR (1 << 1)
#define AMLCBLK_IS_ENCRYPT(h) ((h)->flag & (AMLCBLK_ENCRYPT))
#define AMLCBLK_SET_ENCRYPT(h) ((h)->flag |= (AMLCBLK_ENCRYPT))
#define AMLCBLK_HAS_HDR(h) ((h)->flag & (AMLCBLK_HDR))
#define AMLCBLK_SET_HDR(h) ((h)->flag |= (AMLCBLK_HDR))

#define bh_wr(h, sz, off, val)						\
	(*(uint ## sz ## _t *)((h) + off) = htole ## sz(val))
#define bh_rd(h, sz, off)						\
	(le ## sz ## toh(*(uint ## sz ## _t *)((h) + off)))

#define AMLCBLKSZ 256

#define BL31_MAGIC (0x12348765)
#define AMLCBLK_MAGIC (*(uint32_t *)"AMLC")

/**
 * Read a block of data from a file
 *
 * @param fd: File descriptor to read a block from
 * @param blk: Filled with read data
 * @param sz: Size of block to read from file
 * @return: Negative number on error, read size otherwise. The only reason that
 * return value could be different from sz on success is when EOF has been
 * encountered while reading the file.
 */
static ssize_t gi_amlcblk_read_blk(int fd, uint8_t *blk, size_t sz)
{
	size_t i;
	ssize_t nr = 1;

	for(i = 0; (i < sz) && (nr != 0); i += nr) {
		nr = read(fd, blk + i, sz - i);
		if(nr < 0)
			goto out;
	}
	nr = i;
out:
	return nr;
}

/**
 * Write a block of data into a file
 *
 * @param fd: File descriptor to write a block into
 * @param blk: Actual block data
 * @param sz: Size of block to write into file
 * @return: Negative number on error, sz otherwise.
 */
static ssize_t gi_amlcblk_write_blk(int fd, uint8_t *blk, size_t sz)
{
	size_t i;
	ssize_t nr;

	for(i = 0; i < sz; i += nr) {
		nr = write(fd, blk + i, sz - i);
		if(nr < 0)
			goto out;
	}
	nr = i;
out:
	return nr;
}

/**
 * Pad a partial filled block
 *
 * @param acb: Amlogic Control block descriptor
 * @param blk: block to pad
 * @param sz: Size of actual data in blk
 */
static void gi_amlcblk_blk_pad(struct amlcblk const *acb, uint8_t *blk,
		size_t off)
{
	memset(blk, 0, acb->blksz - off);
}

/**
 * Initialize Amlogic Control block descriptor from binary file
 *
 * @param acb: Amlogic Control block descriptor to init
 * @param fd: Binary file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlcblk_init(struct amlcblk *acb, int fd)
{
	size_t i, nr;
	off_t fsz;
	uint8_t hdr[AMLCBLKSZ];

	acb->flag = 0;
	srand(time(NULL));
	lseek(fd, 0, SEEK_SET);
	nr = gi_amlcblk_read_blk(fd, hdr, sizeof(hdr));
	if(nr != sizeof(hdr)) {
		PERR("Cannot read input header: ");
		return -EINVAL;
	}

	if(bh_rd(hdr, 32, 0) == BL31_MAGIC)
		AMLCBLK_SET_HDR(acb);

	acb->blksz = 0x200;
	fsz = lseek(fd, 0, SEEK_END);
	fsz = ROUNDUP(fsz, acb->blksz);
	if(AMLCBLK_HAS_HDR(acb))
		fsz -= acb->blksz;
	acb->firstblk = fsz;
	acb->encsz = 0;
	acb->payloadsz = fsz;
	for(i = 0; i < sizeof(acb->iv); ++i)
		acb->iv[i] = rand();
	for(i = 0; i < sizeof(acb->aeskey); ++i)
		acb->aeskey[i] = rand();
	return 0;
}

/**
 * Compute payload sha256 hash
 *
 * @param acb: control block descriptor
 * @param fd: output boot image file descriptor
 * @param hash: Filled with the sha256 hash
 * @return: 0 on success, negative number otherwise
 */
static int gi_amlcblk_sha256(struct amlcblk const *acb, int fd,
		uint8_t hash[32])
{
	EVP_MD_CTX *ctx;
	uint8_t *tmp = NULL;
	size_t i;
	ssize_t nr;
	int ret;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot create digest context: ");
		goto out;
	}

	ret = -ENOMEM;
	tmp = malloc(acb->blksz);
	if(tmp == NULL)
		goto out;

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot init digest context: ");
		goto out;
	}

	lseek(fd, acb->firstblk, SEEK_SET);
	for(i = 0; i < acb->encsz; i += nr) {
		nr = gi_amlcblk_read_blk(fd, tmp, acb->blksz);
		if((nr < 0) || ((size_t)nr != acb->blksz)) {
			PERR("Cannot read fd %d:", fd);
			ret = (int)nr;
			goto out;
		}
		ret = EVP_DigestUpdate(ctx, tmp, acb->blksz);
		if(ret != 1) {
			ret = -ERR_get_error();
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}
		if(i == 0)
			lseek(fd, acb->blksz, SEEK_SET);
	}
	ret = EVP_DigestFinal_ex(ctx, hash, NULL);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot finalize hash: ");
		goto out;
	}
	ret = 0;
out:
	EVP_MD_CTX_free(ctx);
	free(tmp);
	return ret;
}

/**
 * Dump control block boot image cipher description
 *
 * @param acb: Control block descriptor
 * @param buf: Buffer to dump cipher description into
 * @return: 0 on success negative number otherwise
 */
static int gi_amlcblk_set_desc(struct amlcblk const *acb, uint8_t buf[96])
{
	struct tm lt;
	time_t t;

	if(time(&t) == ((time_t)-1)) {
		PERR("Cannot get current time: ");
		return -errno;
	}

	if(localtime_r(&t, &lt) == NULL) {
		PERR("Cannot convert current time: ");
		return -errno;
	}

	if(!AMLCBLK_IS_ENCRYPT(acb)) {
		ERR("Boot image should be encrypted\n");
		return -EINVAL;
	}

	snprintf((char *)buf, 96, "AES-CBC%04d/%02d/%02d %02d:%02d:%02d",
			lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
			lt.tm_hour, lt.tm_min, lt.tm_sec);
	return 0;
}

/**
 * Dump amlogic control block into boot image file
 *
 * @param acb: Control block descriptor
 * @param fd: boot image output file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlcblk_dump_hdr(struct amlcblk const *acb, int fd)
{
	int ret;
	uint8_t hash[32];
	uint8_t data[AMLCBLKSZ] = {};

	ret = gi_amlcblk_sha256(acb, fd, hash);
	if(ret < 0)
		goto out;

	bh_wr(data, 16, 2, acb->blksz);
	bh_wr(data, 16, 250, acb->blksz);
	bh_wr(data, 32, 20, acb->blksz); /* TODO Why 32bits here ? */
	bh_wr(data, 16, 4, (AMLCBLK_IS_ENCRYPT(acb)) ? 1 : 0);
	bh_wr(data, 16, 6, 1); /* TODO find meaning of that */
	bh_wr(data, 32, 12, AMLCBLK_MAGIC);
	bh_wr(data, 32, 252, AMLCBLK_MAGIC);
	bh_wr(data, 32, 16, acb->firstblk);
	bh_wr(data, 32, 24, acb->encsz);
	bh_wr(data, 32, 28, acb->payloadsz);
	memcpy(data + 32, hash, sizeof(hash));
	memcpy(data + 64, acb->aeskey, sizeof(acb->aeskey));
	memcpy(data + 96, acb->iv, sizeof(acb->iv));
	gi_amlcblk_set_desc(acb, data + 136);

	lseek(fd, 0, SEEK_SET);
	ret = gi_amlcblk_write_blk(fd, data, AMLCBLKSZ);
out:
	return ret;
}

/**
 * Encode a binary input file into a boot image output file
 *
 * @param acb: Amlogic Control Block descriptor
 * @param fout: Boot image output file descriptor
 * @param fin: Binary input file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlcblk_aes_enc(struct amlcblk *acb, int fout, int fin)
{
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t *block = NULL, *enc = NULL;
	size_t i;
	ssize_t nr, wnr;
	int ret;
	uint8_t hdr[AMLCBLKSZ] = {};

	ret = -EINVAL;
	if(acb->payloadsz % acb->payloadsz)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot create cipher context: ");
		goto out;
	}

	ret = -ENOMEM;
	block = malloc(acb->blksz);
	if(block == NULL)
		goto out;

	enc = malloc(acb->blksz);
	if(enc == NULL)
		goto out;

	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
			acb->aeskey, acb->iv);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot init cipher context: ");
		goto out;
	}

	ret = EVP_CIPHER_CTX_set_padding(ctx, 0);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot disable cipher padding: ");
		goto out;
	}

	lseek(fin, 0, SEEK_SET);
	if(AMLCBLK_HAS_HDR(acb)) {
		nr = gi_amlcblk_read_blk(fin, hdr, AMLCBLKSZ);
		if(nr != AMLCBLKSZ) {
			PERR("Cannot read fin header\n");
			ret = (int)nr;
			goto out;
		}
		lseek(fin, acb->blksz, SEEK_SET);
	}

	lseek(fout, AMLCBLKSZ, SEEK_SET);
	wnr = gi_amlcblk_write_blk(fout, hdr, AMLCBLKSZ);
	if(wnr < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		ret = (int)wnr;
		goto out;
	}

	lseek(fout, acb->firstblk, SEEK_SET);

	/* Encrypt each binary block and write them in boot image */
	for(i = 0; i < acb->payloadsz; i += nr) {
		nr = gi_amlcblk_read_blk(fin, block, acb->blksz);
		if(nr <= 0) {
			PERR("Cannot read fd %d: ", fin);
			ret = (int)nr;
			goto out;
		}

		if((size_t)nr < acb->blksz)
			gi_amlcblk_blk_pad(acb, block, nr);

		nr = acb->blksz;
		ret = EVP_EncryptUpdate(ctx, enc, (int *)&nr, block, nr);
		if((ret != 1) || ((size_t)nr != acb->blksz)) {
			ret = -ERR_get_error();
			SSLERR(ret, "Cannot Encrypt block: ");
			goto out;
		}

		wnr = gi_amlcblk_write_blk(fout, enc, acb->blksz);
		if(wnr < 0) {
			PERR("Cannot write into fd %d: ", fout);
			ret = (int)wnr;
			goto out;
		}

		if(i == 0)
			lseek(fout, nr, SEEK_SET);
	}
	ret = EVP_EncryptFinal_ex(ctx, enc, (int *)&nr);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot finalise binary payload: ");
		goto out;
	}
	acb->encsz = 0;
	AMLCBLK_SET_ENCRYPT(acb);
	ret = 0;

out:
	free(enc);
	free(block);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}
