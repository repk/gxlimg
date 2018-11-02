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
#include "bl3.h"

#define SSLERR(ret, ...) do						\
{									\
	char __sslerrbuf[256];						\
	fprintf(stderr, __VA_ARGS__);					\
	ERR_error_string_n(-ret, __sslerrbuf, sizeof(__sslerrbuf));	\
	fprintf(stderr, "%s\n", __sslerrbuf);				\
} while(0)

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define BL3_HDRSZ 256

/* BL3 binary description */
struct bl3 {
	size_t blksz; /* Size of one output block */
	size_t firstblk; /* Offset of first block */
	size_t encsz; /* Size of encrypted payload */
	size_t payloadsz; /* Size of decrypted payload */
	uint8_t iv[16]; /* AES-256-CBC Initialization vector */
	uint8_t aeskey[32]; /* AES-256-CBC key */
	uint8_t flag; /* BL3 flags */
};
#define BL3_ENCRYPT (1 << 0)
#define BL3_HDR (1 << 1)
#define BL3_IS_ENCRYPT(h) ((h)->flag & (BL3_ENCRYPT))
#define BL3_SET_ENCRYPT(h) ((h)->flag |= (BL3_ENCRYPT))
#define BL3_HAS_HDR(h) ((h)->flag & (BL3_HDR))
#define BL3_SET_HDR(h) ((h)->flag |= (BL3_HDR))

#define bh_wr(h, sz, off, val)						\
	(*(uint ## sz ## _t *)((h) + off) = htole ## sz(val))
#define bh_rd(h, sz, off)						\
	(le ## sz ## toh(*(uint ## sz ## _t *)((h) + off)))

#define BCTL_MAGIC (*(uint32_t *)"AMLC")
#define BL31_MAGIC (0x12348765)

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
static ssize_t gi_bl3_read_blk(int fd, uint8_t *blk, size_t sz)
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
static ssize_t gi_bl3_write_blk(int fd, uint8_t *blk, size_t sz)
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
 * @param bl3: BL3 binary descriptor
 * @param blk: block to pad
 * @param sz: Size of actual data in blk
 */
static void gi_bl3_blk_pad(struct bl3 const *bl3, uint8_t *blk,
		size_t off)
{
	memset(blk, 0, bl3->blksz - off);
}

/**
 * Initialize bl3 context from BL3 binary file descriptor
 *
 * @param bl3: BL3 binary descriptor to init
 * @param fd: BL3 binary file descriptor
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl3_init(struct bl3 *bl3, int fd)
{
	size_t i, nr;
	off_t fsz;
	uint8_t hdr[BL3_HDRSZ];

	srand(time(NULL));
	lseek(fd, 0, SEEK_SET);
	nr = gi_bl3_read_blk(fd, hdr, sizeof(hdr));
	if(nr != sizeof(hdr)) {
		PERR("Cannot read input header: ");
		return -EINVAL;
	}

	if(bh_rd(hdr, 32, 0) == BL31_MAGIC)
		BL3_SET_HDR(bl3);

	bl3->blksz = 0x200;
	fsz = lseek(fd, 0, SEEK_END);
	fsz = ROUNDUP(fsz, bl3->blksz);
	if(BL3_HAS_HDR(bl3))
		fsz -= bl3->blksz;
	bl3->firstblk = fsz;
	bl3->encsz = fsz;
	bl3->payloadsz = fsz;
	BL3_SET_ENCRYPT(bl3);
	for(i = 0; i < sizeof(bl3->iv); ++i)
		bl3->iv[i] = rand();
	for(i = 0; i < sizeof(bl3->aeskey); ++i)
		bl3->aeskey[i] = rand();
	return 0;
}

/**
 * Compute BL3 final payload sha256 hash
 *
 * @param bl3: BL3 descriptor
 * @param fd: BL3 output boot image file descriptor
 * @param hash: Filled with the sha256 hash
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl3_sha256(struct bl3 const *bl3, int fd, uint8_t hash[32])
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
	tmp = malloc(bl3->blksz);
	if(tmp == NULL)
		goto out;

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot init digest context: ");
		goto out;
	}

	lseek(fd, bl3->firstblk, SEEK_SET);
	for(i = 0; i < bl3->encsz; i += nr) {
		nr = gi_bl3_read_blk(fd, tmp, bl3->blksz);
		if((nr < 0) || ((size_t)nr != bl3->blksz)) {
			PERR("Cannot read fd %d:", fd);
			ret = (int)nr;
			goto out;
		}
		ret = EVP_DigestUpdate(ctx, tmp, bl3->blksz);
		if(ret != 1) {
			ret = -ERR_get_error();
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}
		if(i == 0)
			lseek(fd, bl3->blksz, SEEK_SET);
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
 * Dump BL3 boot image cipher description
 *
 * @param bl3: BL3 descriptor
 * @param buf: Buffer to dump cipher description into
 * @return: 0 on success negative number otherwise
 */
static int gi_bl3_set_desc(struct bl3 const *bl3, uint8_t buf[96])
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

	if(!BL3_IS_ENCRYPT(bl3)) {
		ERR("BL3 boot image should be encrypted\n");
		return -EINVAL;
	}

	snprintf((char *)buf, 96, "AES-CBC%04d/%02d/%02d %02d:%02d:%02d",
			lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
			lt.tm_hour, lt.tm_min, lt.tm_sec);
	return 0;
}

/**
 * Dump BL3 header in BL3 boot image file
 *
 * @param bl3: BL3 descriptor
 * @param fd: BL3 boot image output file descriptor
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl3_dump_hdr(struct bl3 const *bl3, int fd)
{
	int ret;
	uint8_t hash[32];
	uint8_t data[BL3_HDRSZ] = {};

	ret = gi_bl3_sha256(bl3, fd, hash);
	if(ret < 0)
		goto out;

	bh_wr(data, 16, 2, bl3->blksz);
	bh_wr(data, 16, 250, bl3->blksz);
	bh_wr(data, 32, 20, bl3->blksz); /* TODO Why 32bits here ? */
	bh_wr(data, 16, 4, (BL3_IS_ENCRYPT(bl3)) ? 1 : 0);
	bh_wr(data, 16, 6, 1); /* TODO find meaning of that */
	bh_wr(data, 32, 12, BCTL_MAGIC);
	bh_wr(data, 32, 252, BCTL_MAGIC);
	bh_wr(data, 32, 16, bl3->firstblk);
	bh_wr(data, 32, 24, bl3->encsz);
	bh_wr(data, 32, 28, bl3->payloadsz);
	memcpy(data + 32, hash, sizeof(hash));
	memcpy(data + 64, bl3->aeskey, sizeof(bl3->aeskey));
	memcpy(data + 96, bl3->iv, sizeof(bl3->iv));
	gi_bl3_set_desc(bl3, data + 136);

	lseek(fd, 0, SEEK_SET);
	ret = gi_bl3_write_blk(fd, data, BL3_HDRSZ);
out:
	return ret;
}

/**
 * Encode a BL3 binary file into a BL3 boot image output file
 *
 * @param bl3: BL3 descriptor
 * @param fout: BL3 boot image output file descriptor
 * @param fin: BL3 binary input file descriptor
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl3_aes_enc(struct bl3 const *bl3, int fout, int fin)
{
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t *block = NULL, *enc = NULL;
	size_t i;
	ssize_t nr, wnr;
	int ret;
	uint8_t hdr[BL3_HDRSZ] = {};

	ret = -EINVAL;
	if(bl3->payloadsz % bl3->payloadsz)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL) {
		ret = -ERR_get_error();
		SSLERR(ret, "Cannot create cipher context: ");
		goto out;
	}

	ret = -ENOMEM;
	block = malloc(bl3->blksz);
	if(block == NULL)
		goto out;

	enc = malloc(bl3->blksz);
	if(enc == NULL)
		goto out;

	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
			bl3->aeskey, bl3->iv);
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
	if(BL3_HAS_HDR(bl3)) {
		nr = gi_bl3_read_blk(fin, hdr, BL3_HDRSZ);
		if(nr != BL3_HDRSZ) {
			PERR("Cannot read fin header\n");
			ret = (int)nr;
			goto out;
		}
		lseek(fin, bl3->blksz, SEEK_SET);
	}

	lseek(fout, BL3_HDRSZ, SEEK_SET);
	wnr = gi_bl3_write_blk(fout, hdr, BL3_HDRSZ);
	if(wnr < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		ret = (int)wnr;
		goto out;
	}

	lseek(fout, bl3->firstblk, SEEK_SET);

	/* Encrypt each BL3 binary block and write them in BL3 boot image */
	for(i = 0; i < bl3->payloadsz; i += nr) {
		nr = gi_bl3_read_blk(fin, block, bl3->blksz);
		if(nr <= 0) {
			PERR("Cannot read fd %d: ", fin);
			ret = (int)nr;
			goto out;
		}

		if((size_t)nr < bl3->blksz)
			gi_bl3_blk_pad(bl3, block, nr);

		nr = bl3->blksz;
		ret = EVP_EncryptUpdate(ctx, enc, (int *)&nr, block, nr);
		if((ret != 1) || ((size_t)nr != bl3->blksz)) {
			ret = -ERR_get_error();
			SSLERR(ret, "Cannot Encrypt block: ");
			goto out;
		}

		wnr = gi_bl3_write_blk(fout, enc, bl3->blksz);
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
		SSLERR(ret, "Cannot finalise BL3 binary payload: ");
		goto out;
	}
	ret = 0;

out:
	free(enc);
	free(block);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/**
 * Create a BL3 boot image
 *
 * @param fin: Path of BL3 binary input file
 * @param fout: Path of BL3 boot image output file
 * @return: 0 on success, negative number otherwise
 */
int gi_bl3_create_img(char const *fin, char const *fout)
{
	struct bl3 bl3;
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

	ret = gi_bl3_init(&bl3, fdin);
	if(ret < 0)
		goto out;

	ret = gi_bl3_aes_enc(&bl3, fdout, fdin);
	if(ret < 0)
		goto out;

	ret = gi_bl3_dump_hdr(&bl3, fdout);
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
