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
#include "amlsblk.h"
#include "ssl.h"

#define AMLSBLK_HDR		(1 << 1)
#define AMLSBLK_HAS_HDR(h)	((h)->flag & (AMLSBLK_HDR))
#define AMLSBLK_SET_HDR(h)	((h)->flag |= (AMLSBLK_HDR))

#define htole8(val)		(val)
#define le8toh(val)		(val)
#define bh_wr(h, sz, off, val)	(*(uint ## sz ## _t *)((h) + off) = htole ## sz(val))
#define bh_rd(h, sz, off)	(le ## sz ## toh(*(uint ## sz ## _t *)((h) + off)))

#define BL31_MAGIC		(0x12348765)

#define AMLSBLK_MAGIC		(*(uint32_t *)"@AML")
#define AMLSBLK_KEY_MAGIC	(*(uint32_t *)"@KEY")

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
static ssize_t gi_amlsblk_read_blk(int fd, uint8_t *blk, size_t sz)
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
static ssize_t gi_amlsblk_write_blk(int fd, uint8_t *blk, size_t sz)
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
 * Hash the header
 *
 * @param asb: control signature descriptor
 * @return: 0 on success, negative number otherwise
 */
static int gi_amlsblk_hash_header(struct amlsblk *asb)
{
	EVP_MD_CTX *ctx;
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

	ret = EVP_DigestUpdate(ctx, asb->hdr, sizeof(asb->hdr));
	if(ret != 1) {
		SSLERR(ret, "Cannot hash data block: ");
		goto out;
	}

	ret = EVP_DigestFinal_ex(ctx, asb->hdr_hash, NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot finalize hash: ");
		goto out;
	}
	ret = 0;
out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

/**
 * Build the two headers and flush the payload
 *
 * @param asb: control signature descriptor
 * @param fin: input image file descriptor
 * @param fout: output image file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlsblk_flush_data(struct amlsblk *asb, int fin, int fout)
{
	uint8_t key_hdr[BL3xKEYHDR_SZ] = { 0 };
	uint8_t empty_nonce[BL3xIV_SZ] = { 0 };
	uint8_t block[512];
	ssize_t rd, wr;
	off_t off;
	size_t nr;
	int ret;

	bh_wr(key_hdr, 32, 0x0, AMLSBLK_KEY_MAGIC);
	bh_wr(key_hdr, 32, 0x4, BL3xKEYHDR_SZ);
	bh_wr(key_hdr, 8,  0x8, 0x1);
	bh_wr(key_hdr, 8,  0xa, BL3xKEYHDR_SZ);

	off = lseek(fout, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	ret = gi_amlsblk_write_blk(fout, key_hdr, sizeof(key_hdr));
	if(ret < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		goto out;
	}

	off = lseek(fout, 0x490, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	ret = gi_amlsblk_write_blk(fout, empty_nonce, sizeof(empty_nonce));
	if(ret < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		goto out;
	}

	ret = gi_amlsblk_write_blk(fout, asb->hdr, sizeof(asb->hdr));
	if(ret < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		goto out;
	}

	ret = gi_amlsblk_write_blk(fout, asb->hdr_hash, sizeof(asb->hdr_hash));
	if(ret < 0) {
		PERR("Cannot write header in fd %d: ", fout);
		goto out;
	}

	off = lseek(fin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	if(AMLSBLK_HAS_HDR(asb)) {
		off = lseek(fin, IMGHDR_SZ, SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}
	}

	for(nr = 0; nr < asb->hashsz; nr += rd) {
		rd = gi_amlsblk_read_blk(fin, block, sizeof(block));
		if(rd <= 0) {
			ret = (int)rd;
			goto out;
		}
		if((size_t)rd < asb->blksz) {
			memset(block + rd, 0, asb->blksz - rd);
			rd += asb->topad;
		}
		wr = gi_amlsblk_write_blk(fout, block, rd);
		if(wr != rd) {
			ret = (int)wr;
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

/**
 * Build the first header and hash it
 *
 * @param asb: control signature descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlsblk_build_header(struct amlsblk *asb)
{
	memset(asb->hdr, 0, sizeof(asb->hdr));

	bh_wr(asb->hdr, 32, 0x0,  AMLSBLK_MAGIC);
	bh_wr(asb->hdr, 32, 0x4,  0x1);
	bh_wr(asb->hdr, 32, 0x8,  0x0);
	bh_wr(asb->hdr, 32, 0xc,  0x0);
	bh_wr(asb->hdr, 64, 0x10, asb->hashsz);
	bh_wr(asb->hdr, 64, 0x18, BL3xHDR_SZ);
	memcpy(asb->hdr + 32, asb->hash, sizeof(asb->hash));

	return gi_amlsblk_hash_header(asb);
}

/**
 * Compute payload sha256 hash
 *
 * @param asb: control signature descriptor
 * @param fin: input image file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlsblk_hash_payload(struct amlsblk *asb, int fin)
{
	uint8_t *block = NULL;
	EVP_MD_CTX *ctx;
	ssize_t nr;
	off_t off;
	size_t i;
	int ret;

	ctx = EVP_MD_CTX_new();
	if(ctx == NULL) {
		SSLERR(ret, "Cannot create digest context: ");
		goto out;
	}

	ret = -ENOMEM;
	block = malloc(asb->blksz);
	if(block == NULL)
		goto out;

	ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot init digest context: ");
		goto out;
	}

	off = lseek(fin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	if(AMLSBLK_HAS_HDR(asb)) {
		off = lseek(fin, IMGHDR_SZ, SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}
	}

	for(i = 0; i < asb->hashsz; i += nr) {
		nr = gi_amlsblk_read_blk(fin, block, asb->blksz);
		if(nr < 0) {
			PERR("Cannot read fd %d:", fin);
			ret = (int)nr;
			goto out;
		}

		if((size_t)nr < asb->blksz) {
			memset(block + nr, 0, asb->blksz - nr);
			nr += asb->topad;
		}

		ret = EVP_DigestUpdate(ctx, block, nr);
		if(ret != 1) {
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}
	}

	ret = EVP_DigestFinal_ex(ctx, asb->hash, NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot finalize hash: ");
		goto out;
	}
	ret = 0;
out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

/**
 * Initialize Amlogic Signature block descriptor from binary file
 *
 * @param asb: Amlogic Signature block descriptor to init
 * @param fd: Binary file descriptor
 * @return: 0 on success, negative number otherwise
 */
int gi_amlsblk_init(struct amlsblk *asb, int fd)
{
	uint8_t img_hdr[IMGHDR_SZ];
	size_t nr;
	off_t fsz;
	int ret;

	asb->flag = 0;
	fsz = lseek(fd, 0, SEEK_SET);
	if(fsz < 0) {
		SEEK_ERR(fsz, ret);
		goto out;
	}

	nr = gi_amlsblk_read_blk(fd, img_hdr, sizeof(img_hdr));
	if(nr != sizeof(img_hdr)) {
		PERR("Cannot read input header: ");
		ret = -EINVAL;
		goto out;
	}

	if(bh_rd(img_hdr, 32, 0) == BL31_MAGIC)
		AMLSBLK_SET_HDR(asb);

	asb->blksz = 0x200;
	fsz = lseek(fd, 0, SEEK_END);
	if(fsz < 0) {
		SEEK_ERR(fsz, ret);
		goto out;
	}

	if(AMLSBLK_HAS_HDR(asb))
		fsz -= IMGHDR_SZ;
	asb->payloadsz = fsz;

	asb->totsz = ROUNDUP(fsz + BL3xHDR_SZ, asb->blksz);
	asb->hashsz = (asb->totsz - BL3xHDR_SZ);
	asb->topad = asb->hashsz - asb->payloadsz;

out:
	return ret;
}
