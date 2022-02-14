#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>

#include "gxlimg.h"
#include "bl2.h"
#include "ssl.h"

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define htole8(val)	(val)
#define le8toh(val)	(val)
#define bh_wr(h, sz, off, val)						\
	(*(uint ## sz ## _t *)((h) + off) = htole ## sz(val))
#define bh_rd(h, sz, off)						\
	(le ## sz ## toh(*(uint ## sz ## _t *)((h) + off)))

#define BL2HDR_SZ	0x1000
#define BL2IV_SZ	0x10
#define BL2BLKHDR_SZ	0x40
#define BL2SIG_SZ	0x200
#define BL2KEY_SZ	0xD80
#define BL2KEYHDR_SZ	0x30
#define BL2SHA2_SZ	0x20

#define BL2HDR_MAGIC	(*(uint32_t *)"@AML")

/**
 * BL2 binary file context
 */
struct bl2 {
	size_t payloadsz;
	size_t totlen;
	size_t hash_start; /* Start of Hashed payload */
	size_t hash_size; /* Size of hashed payload */
	uint8_t flag;
};
#define BF_RSA (1 << 0)
#define BF_IS_RSA(h) ((h)->flag & BF_RSA)
#define BF_SET_RSA(h) ((h)->flag |= BF_RSA)

/**
 * Initialize bl2 context from BL2 binary file descriptor
 *
 * @param bl2: BL2 binary descriptor to init
 * @param fd: BL2 binary file descriptor
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl2_init(struct bl2 *bl2, int fd)
{
	off_t fsz;

	fsz = lseek(fd, 0, SEEK_END);
	if(fsz < 0) {
		PERR("Cannot seek file: ");
		return (int)fsz;
	}

	bl2->payloadsz = fsz;
	if (fsz == 0xc000) /* GXL */
		bl2->payloadsz -= BL2HDR_SZ;

	bl2->totlen = bl2->payloadsz + BL2HDR_SZ;
	bl2->flag = 0; /* Not RSA signature support yet */
	bl2->hash_start = BL2BLKHDR_SZ + BL2SHA2_SZ;
	bl2->hash_size = bl2->totlen - BL2IV_SZ - bl2->hash_start;

	return 0;
}

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
static ssize_t gi_bl2_read_blk(int fd, uint8_t *blk, size_t sz)
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
static ssize_t gi_bl2_write_blk(int fd, uint8_t *blk, size_t sz)
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

static int gi_bl2_dump_hdr(struct bl2 const *bl2, int fd)
{
	uint8_t hdr[BL2BLKHDR_SZ] = {};
	uint8_t rd[BL2IV_SZ];
	ssize_t nr;
	off_t off;
	int ret;

	if(BF_IS_RSA(bl2)) {
		ERR("BL2 RSA signature not supported yet\n");
		ret = -EINVAL;
		goto out;
	}

	ret = gi_random(rd, BL2IV_SZ);
	if(ret < 0)
		goto out;

	off = lseek(fd, 0, SEEK_SET);
	if(off < 0) {
		PERR("Cannot seek file: ");
		return (int)off;
	}
	bh_wr(hdr, 32, 0x00, BL2HDR_MAGIC);
	bh_wr(hdr, 32, 0x04, bl2->totlen - BL2IV_SZ);
	bh_wr(hdr, 8,  0x08, BL2BLKHDR_SZ);
	bh_wr(hdr, 8,  0x0a, 1);
	bh_wr(hdr, 8,  0x0b, 1);
	bh_wr(hdr, 32, 0x10, 0); /* SHA256 signature, no RSA */
	bh_wr(hdr, 32, 0x14, BL2BLKHDR_SZ);
	bh_wr(hdr, 32, 0x18, BL2SIG_SZ);
	bh_wr(hdr, 32, 0x1c, bl2->hash_start); /* Beginning of hashed payload */
	bh_wr(hdr, 32, 0x20, 0); /* Null RSA KEY type */
	bh_wr(hdr, 32, 0x24, BL2BLKHDR_SZ + BL2SIG_SZ); /* RSA KEY Offset */
	bh_wr(hdr, 32, 0x28, BL2HDR_SZ - BL2IV_SZ - BL2BLKHDR_SZ - BL2SIG_SZ);
	bh_wr(hdr, 32, 0x2c, bl2->hash_size);
	bh_wr(hdr, 32, 0x34, BL2HDR_SZ - BL2IV_SZ); /* Payload offset */
	bh_wr(hdr, 32, 0x38, bl2->totlen - BL2HDR_SZ);

	nr = gi_bl2_write_blk(fd, rd, sizeof(rd));
	if(nr != sizeof(rd)) {
		PERR("Failed to write random number in bl2 boot img: ");
		ret = (int)nr;
		goto out;
	}

	nr = gi_bl2_write_blk(fd, hdr, sizeof(hdr));
	if(nr != sizeof(hdr)) {
		PERR("Failed to write header in bl2 boot img: ");
		ret = (int)nr;
		goto out;
	}
	ret = 0;
out:
	return ret;
}

/**
 * Read BL2 header from image
 *
 * @param bl2: Filled up with BL2 header info
 * @param fd: File to read header from
 *
 * @return: 0 on success, negative number otherwise
 */
static int gi_bl2_read_hdr(struct bl2 *bl2, int fd)
{
	uint8_t hdr[BL2BLKHDR_SZ];
	off_t off;
	int ret;

	off = lseek(fd, BL2IV_SZ, SEEK_SET); /* Skip IV */
	if(off < 0) {
		PERR("Cannot seek file: ");
		return (int)off;
	}

	ret = gi_bl2_read_blk(fd, hdr, sizeof(hdr));
	if(ret < 0) {
		ERR("Cannot get header from bl2 file\n");
		goto out;
	}

	ret = -EINVAL;
	if(bh_rd(hdr, 32, 0x00) != BL2HDR_MAGIC) {
		ERR("Invalid BL2 header\n");
		goto out;
	}
	bl2->totlen = bh_rd(hdr, 32, 0x04) + BL2IV_SZ;
	bl2->hash_start = bh_rd(hdr, 32, 0x1c); /* Beginning of hashed payload */
	bl2->hash_size = bh_rd(hdr, 32, 0x2c);
	bl2->payloadsz = bl2->totlen - BL2HDR_SZ;

	ret = 0;
out:
	return ret;
}

static int gi_bl2_dump_key(struct bl2 const *bl2, int fd)
{
	uint32_t val;
	off_t off;
	int ret;

	if(BF_IS_RSA(bl2)) {
		ERR("BL2 RSA signature not supported yet\n");
		return -EINVAL;
	}

	off = lseek(fd, BL2IV_SZ + BL2BLKHDR_SZ + BL2SIG_SZ + 0x18, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	val = htole32(0x298);
	gi_bl2_write_blk(fd, (uint8_t *)(&val), 4);

	/* TODO What is this offset */
	off = lseek(fd, BL2IV_SZ + 0x8ec, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	val = htole32(0x240);
	gi_bl2_write_blk(fd, (uint8_t *)(&val), 4);

	/* TODO What is this offset */
	off = lseek(fd, BL2IV_SZ + 0xb20, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	val = htole32(0x298);
	gi_bl2_write_blk(fd, (uint8_t *)(&val), 4);
	ret = 0;
out:
	return ret;
}

static int gi_bl2_dump_binary(struct bl2 const *bl2, int fout, int fin)
{
	uint8_t block[1024];
	size_t nr;
	ssize_t rd, wr;
	off_t off;
	int ret;

	off = lseek(fin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	off = lseek(fout, BL2HDR_SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	for(nr = 0; nr < bl2->payloadsz; nr += rd) {
		rd = gi_bl2_read_blk(fin, block, sizeof(block));
		if(rd <= 0) {
			ret = (int)rd;
			goto out;
		}
		wr = gi_bl2_write_blk(fout, block, sizeof(block));
		if(wr != rd) {
			ret = (int)wr;
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

static int gi_bl2_sign(struct bl2 const *bl2, int fd)
{
	EVP_MD_CTX *ctx;
	uint8_t tmp[1024];
	uint8_t hash[BL2SHA2_SZ];
	size_t i;
	ssize_t nr;
	off_t off;
	int ret;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL) {
		SSLERR(ret, "Cannot create digest context: ");
		goto out;
	}

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot init digest context: ");
		goto out;
	}

	/* Hash header */
	off = lseek(fd, BL2IV_SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_bl2_read_blk(fd, tmp, BL2BLKHDR_SZ);
	if((nr < 0) || (nr != BL2BLKHDR_SZ)) {
		PERR("Cannot read header from fd %d: ", fd);
		ret = (int)nr;
		goto out;
	}
	ret = EVP_DigestUpdate(ctx, tmp, nr);
	if(ret != 1) {
		SSLERR(ret, "Cannot hash header block: ");
		goto out;
	}

	/* Hash payload */
	off = lseek(fd, BL2IV_SZ + bl2->hash_start, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	for(i = 0; i < bl2->hash_size; i += nr) {
		nr = gi_bl2_read_blk(fd, tmp, sizeof(tmp));
		if(nr < 0) {
			PERR("Cannot read fd %d:", fd);
			ret = (int)nr;
			goto out;
		}
		ret = EVP_DigestUpdate(ctx, tmp, nr);
		if(ret != 1) {
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}
	}

	ret = EVP_DigestFinal_ex(ctx, hash, NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot finalize hash: ");
		goto out;
	}

	/* Only SHA256 signature is supported so far */
	off = lseek(fd, BL2IV_SZ + BL2BLKHDR_SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_bl2_write_blk(fd, hash, BL2SHA2_SZ);
	if(nr != BL2SHA2_SZ) {
		PERR("Cannot write SHA sig in fd %d:", fd);
		ret = (int)nr;
		goto out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

int gi_bl2_sign_img(char const *fin, char const *fout)
{
	struct bl2 bl2;
	int fdin = -1, fdout = -1, ret;

	DBG("Create bl2 boot image from %s in %s\n", fin, fout);

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

	ret = gi_bl2_init(&bl2, fdin);
	if(ret < 0)
		goto out;

	/* Fill the whole file with zeros */
	ret = ftruncate(fdout, bl2.totlen);
	if(ret < 0)
		goto out;

	ret = gi_bl2_dump_hdr(&bl2, fdout);
	if(ret < 0)
		goto out;

	ret = gi_bl2_dump_key(&bl2, fdout);
	if(ret < 0)
		goto out;

	ret = gi_bl2_dump_binary(&bl2, fdout, fdin);
	if(ret < 0)
		goto out;

	ret = gi_bl2_sign(&bl2, fdout);
out:
	if(fdin >= 0)
		close(fdin);
	if(fdout >= 0)
		close(fdout);
	return ret;
}

int gi_bl2_unsign_img(char const *fin, char const *fout)
{
	struct bl2 bl2 = {};
	ssize_t rd, wr;
	size_t len;
	off_t off;
	int fdin = -1, fdout = -1, ret;
	uint8_t block[1024];

	DBG("Extract bl2 boot image from signed %s in %s\n", fin, fout);

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

	ret = gi_bl2_read_hdr(&bl2, fdin);
	if(ret != 0) {
		ERR("Cannot get BL2 header\n");
		goto out;
	}

	ret = ftruncate(fdout, 0);
	if(ret < 0)
		goto out;

	off = lseek(fdin, BL2HDR_SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	len = bl2.payloadsz;
	if (len + BL2HDR_SZ == 0xc000) /* GXL */
		len = 0xc000;

	ret = ftruncate(fdout, len);
	if(ret < 0)
		goto out;

	do {
		rd = gi_bl2_read_blk(fdin, block, MIN(len, sizeof(block)));
		if(rd <= 0) {
			ret = (int)rd;
			goto out;
		}
		wr = gi_bl2_write_blk(fdout, block, rd);
		if(wr != rd) {
			ret = (int)wr;
			goto out;
		}
		len -= rd;
	} while((rd != 0) && (len != 0));

	ret = 0;
out:
	if(fdin >= 0)
		close(fdin);
	if(fdout >= 0)
		close(fdout);
	return ret;
}
