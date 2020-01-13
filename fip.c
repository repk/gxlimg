#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <sys/stat.h>

#include "gxlimg.h"
#include "fip.h"
#include "amlcblk.h"

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define BL31_ENTRY_MAGIC (0x87654321)
#define BL31_MAGIC (0x12348765)
#define BL2SZ (0xc000)

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
static ssize_t gi_fip_read_blk(int fd, uint8_t *blk, size_t sz)
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
static ssize_t gi_fip_write_blk(int fd, uint8_t *blk, size_t sz)
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
 * Safely create a temporary file
 *
 * @param path: Path of temporary file, should ends with 6 X. On success those
 * X will be replaced with the unique file suffix created.
 * @return: fd on success, negative number otherwise
 */
static int gi_fip_create_tmp(char *path)
{
	mode_t oldmask;
	int fd;

	oldmask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
	fd = mkstemp(path);
	(void)umask(oldmask);

	return fd;
}

/**
 * List of supported boot image
 */
enum FIP_BOOT_IMG {
	FBI_BL2,
	FBI_BL30,
	FBI_BL31,
	FBI_BL32,
	FBI_BL33,
	FBI_UNKNOWN,
};

typedef uint8_t uuid_t[16];

/**
 * Default uuid for each boot image
 */
static uuid_t const uuid_list[] = {
	[FBI_BL2] = {
		0x5f, 0xf9, 0xec, 0x0b, 0x4d, 0x22, 0x3e, 0x4d,
		0xa5, 0x44, 0xc3, 0x9d, 0x81, 0xc7, 0x3f, 0x0a
	},
	[FBI_BL30] = {
		0x97, 0x66, 0xfd, 0x3d, 0x89, 0xbe, 0xe8, 0x49,
		0xae, 0x5d, 0x78, 0xa1, 0x40, 0x60, 0x82, 0x13
	},
	[FBI_BL31] = {
		0x47, 0xd4, 0x08, 0x6d, 0x4c, 0xfe, 0x98, 0x46,
		0x9b, 0x95, 0x29, 0x50, 0xcb, 0xbd, 0x5a, 0x00
	},
	[FBI_BL32] = {
		0x05, 0xd0, 0xe1, 0x89, 0x53, 0xdc, 0x13, 0x47,
		0x8d, 0x2b, 0x50, 0x0a, 0x4b, 0x7a, 0x3e, 0x38
	},
	[FBI_BL33] = {
		0xd6, 0xd0, 0xee, 0xa7, 0xfc, 0xea, 0xd5, 0x4b,
		0x97, 0x82, 0x99, 0x34, 0xf2, 0x34, 0xb6, 0xe4
	},
};

/**
 * Get FIP image type from its uuid
 *
 * @param uuid: UUID to find image type from
 * @return: FIP image type if found FIP_UNKNOWN otherwise
 */
static enum FIP_BOOT_IMG uuid_get_type(uuid_t uuid)
{
	size_t i;

	for(i = 0; i < ARRAY_SIZE(uuid_list); ++i)
		if(memcmp(uuid_list[i], uuid, sizeof(uuid_list[i])) == 0)
			goto out;

	i = FBI_UNKNOWN;

out:
	return (enum FIP_BOOT_IMG)i;
}

/**
 * FIP header structure
 */
#pragma pack(push, 1)
struct  fip_toc_header {
	/**
	 * FIP magic
	 */
	uint32_t name;
	/**
	 * Vendor specific number
	 */
	uint32_t serial_number;
	/**
	 * Flags, reserved for later use
	 */
	uint64_t flags;
};
#pragma pack(pop)
#define FT_NAME 0xaa640001
#define FT_SERIAL 0x12345678
#define FIP_TOC_HEADER							\
	&((struct fip_toc_header){					\
		.name = htole32(FT_NAME),				\
		.serial_number = htole32(FT_SERIAL)			\
	})

/**
 * Header for a FIP table of content entry
 */
#pragma pack(push, 1)
struct fip_toc_entry {
	/**
	 * uuid of the image entry
	 */
	uuid_t uuid;
	/**
	 * Offset of the image from the FIP base address
	 */
	uint64_t offset;
	/**
	 * Size of the FIP entry image
	 */
	uint64_t size;
	/**
	 * Flags for the FIP entry image
	 */
	uint64_t flags;
};
#pragma pack(pop)

#define FTE_BL31HDR_SZ 0x50
#define FTE_BL31HDR_OFF(nr) (0x430 + FTE_BL31HDR_SZ * (nr))
/* Get fip entry offset from fip base */
#define FTE_OFF(nr)							\
	(sizeof(struct fip_toc_header) + nr * sizeof(struct fip_toc_entry))

#define FIP_SZ 0x4000
#define FIP_TEMPPATH "/tmp/fip.bin.XXXXXX"
#define FIP_TEMPPATHSZ sizeof(FIP_TEMPPATH)
/**
 * FIP handler
 */
struct fip {
	/**
	 * Current image copied data size
	 */
	size_t cursz;
	/**
	 * Number of entry in FIP table of content
	 */
	size_t nrentries;
	/**
	 * Temporary Fip file descriptor
	 */
	int fd;
	/**
	 * Temporary file path
	 */
	char path[FIP_TEMPPATHSZ];
};

/**
 * Init a FIP handler
 *
 * @param fip: FIP handler to init
 * @return: 0 on success, negative number otherwise
 */
static inline int fip_init(struct fip *fip)
{
	unsigned long long init = 0xffffffffffffffffULL;
	ssize_t nr;
	size_t i;
	off_t off;
	int ret;

	strncpy(fip->path, FIP_TEMPPATH, sizeof(fip->path));
	fip->cursz = FIP_SZ;
	fip->nrentries = 0;
	fip->fd = gi_fip_create_tmp(fip->path);
	if(fip->fd < 0) {
		PERR("Cannot create fip temp: ");
		ret =  -errno;
		goto out;
	}

	ret = ftruncate(fip->fd, FIP_SZ - 0x200);
	if(ret < 0) {
		PERR("Cannot truncate fip toc header: ");
		close(fip->fd);
		ret = -errno;
		goto out;
	}

	nr = gi_fip_write_blk(fip->fd, (uint8_t *)FIP_TOC_HEADER,
			sizeof(*FIP_TOC_HEADER));
	if(nr < 0) {
		PERR("Cannot write fip toc header: ");
		close(fip->fd);
		ret = -errno;
		goto out;
	}

	/* End of toc entry */
	off = lseek(fip->fd, 0xc00, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	for(i = 0; i < 0x80 / sizeof(init); ++i) {
		nr = gi_fip_write_blk(fip->fd, (uint8_t *)&init, sizeof(init));
		if(nr < 0) {
			PERR("Cannot write fip toc last entry: ");
			close(fip->fd);
			ret = -errno;
			goto out;
		}
	}
	ret = 0;

out:
	return ret;
}

/**
 * Cleanup a FIP handler
 *
 * @param fip: FIP handler to clean
 */
static inline void fip_cleanup(struct fip *fip)
{
	close(fip->fd);
	(void)remove(fip->path);
}

/**
 * Binary file info found in FIP ToC entry
 */
struct fip_entry_info {
	enum FIP_BOOT_IMG type;
	size_t offset;
	size_t size;
};

/**
 * List of binaries file info found in FIP ToC
 */
#define MAX_FIP_FILE 10
struct fip_toc_info {
	size_t nr_files;
	struct fip_entry_info files[MAX_FIP_FILE];
};

/**
 * Read a fip header from image
 *
 * @param fip: fill up with FIP informations
 * @param fd: FIP image to read header from
 * @return: 0 on success, negative number otherwise
 */
static int fip_read_toc(struct fip_toc_info *toc, int fd)
{
	struct fip_toc_header tochdr;
	struct fip_toc_entry entry;
	ssize_t nr;
	size_t i;
	off_t off;
	enum FIP_BOOT_IMG type;
	int ret;

	off = lseek(fd, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	/* Verify FIP TOC header first */
	ret = gi_fip_read_blk(fd, (uint8_t *)&tochdr, sizeof(tochdr));
	if(ret < 0) {
		PERR("Cannot read FIP header\n");
		ret = -errno;
		goto out;
	}

	if(memcmp((uint8_t *)&tochdr, (uint8_t *)FIP_TOC_HEADER,
				sizeof(tochdr)) != 0) {
		ERR("Invalid FIP Header\n");
		ret = -EINVAL;
		goto out;
	}

	/* Now read table of content entries */
	for(i = 0; i < ARRAY_SIZE(toc->files); ++i) {
		nr = gi_fip_read_blk(fd, (uint8_t *)&entry, sizeof(entry));
		if(nr <= 0) {
			PERR("Cannot read TOC entry\n");
			ret = -errno;
			goto out;
		}
		type = uuid_get_type(entry.uuid);
		if(type == FBI_UNKNOWN)
			break;
		toc->files[i].type = type;
		toc->files[i].offset = entry.offset;
		toc->files[i].size = entry.size;
	}

	toc->nr_files = i;
	ret = 0;
out:
	return ret;
}

/**
 * Copy part of a file as-is in another file at specific offset
 *
 * @param fdin: Src file to copy
 * @param fdout: Dest file to copy into
 * @param size: Maximum size to copy from fdin
 * @return: actual number of bytes copied from fdin on success, negative number
 * otherwise.
 */
static ssize_t gi_copy_file(int fdin, int fdout, size_t len)
{
	ssize_t nrd, nwr, tot;
	uint8_t block[512];

	tot = 0;
	do {
		nrd = gi_fip_read_blk(fdin, block,
				MIN(len - tot, sizeof(block)));
		if(nrd < 0)
			continue;
		nwr = gi_fip_write_blk(fdout, block, nrd);
		if(nwr < 0) {
			PERR("Cannot write to file\n");
			tot = -errno;
			goto out;
		}
		tot += nrd;
	} while((nrd > 0) && ((size_t)tot < len));

	if(nrd < 0) {
		PERR("Cannot read file\n");
		tot = -errno;
		goto out;
	}
out:
	return tot;
}

/**
 * Copy a file as-is in another file at specific offset
 *
 * @param fdin: Src file to copy
 * @param fdout: Dest file to copy into
 * @param off: Offset at which src file should be copy into dest file
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_dump_img(int fdin, int fdout, size_t off)
{
	ssize_t len;
	off_t o;
	int ret;

	o = lseek(fdout, off, SEEK_SET);
	if(o < 0) {
		SEEK_ERR(o, ret);
		goto out;
	}

	len = gi_copy_file(fdin, fdout, (size_t)-1);
	if(len < 0) {
		ret = (int)len;
		goto out;
	}

	ret = 0;
out:
	return ret;
}

/**
 * Add a bootloder image in boot image
 *
 * @param fip: Fip handler
 * @param fdout: Final boot image file
 * @param fdin: Bootloader image to add
 * @param type: Type of bootloader image
 */
static int gi_fip_add(struct fip *fip, int fdout, int fdin,
		enum FIP_BOOT_IMG type)
{
	static uint32_t const bl31magic[] = {
		BL31_ENTRY_MAGIC,
		0x1,
	};
	struct fip_toc_entry entry;
	size_t sz;
	ssize_t nr;
	off_t off;
	int ret;
	uint8_t buf[FTE_BL31HDR_SZ];

	off = lseek(fdin, 0, SEEK_END);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	sz = (size_t)off;
	memcpy(entry.uuid, uuid_list[type], sizeof(entry.uuid));
	entry.offset = fip->cursz;
	entry.flags = 0;
	entry.size = sz;

	off = lseek(fip->fd, FTE_OFF(fip->nrentries), SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_fip_write_blk(fip->fd, (uint8_t *)&entry, sizeof(entry));
	if(nr < 0) {
		PERR("Cannot write FIP entry\n");
		ret = -errno;
		goto out;
	}

	off = lseek(fdin, 256, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_fip_read_blk(fdin, buf, sizeof(buf));
	if(nr <= 0) {
		PERR("Cannot read BL image entry\n");
		ret = -errno;
		goto out;
	}

	/*
	 * BL31 binary store information about load address and entry point in
	 * the FIP data
	 */
	if(le32toh(*(uint32_t *)buf) == BL31_MAGIC) {
		off = lseek(fip->fd, 1024, SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}
		nr = gi_fip_write_blk(fip->fd, (uint8_t *)&bl31magic,
				sizeof(bl31magic));
		if(nr < 0) {
			PERR("Cannot write BL31 entry header\n");
			ret = -errno;
			goto out;
		}
		off = lseek(fip->fd, FTE_BL31HDR_OFF(fip->nrentries),
				SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}
		nr = gi_fip_write_blk(fip->fd, buf, sizeof(buf));
		if(nr < 0) {
			PERR("Cannot write BL31 entry header data\n");
			ret = -errno;
			goto out;
		}
	}

	off = lseek(fdin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	gi_fip_dump_img(fdin, fdout, BL2SZ + entry.offset);
	fip->cursz += ROUNDUP(sz, 0x4000);
	++fip->nrentries;
	ret = 0;

out:
	return ret;
}

/**
 * Create a Amlogic bootable image
 *
 * @param bl2: BL2 boot image to add
 * @param bl30: BL30 boot image to add
 * @param bl31: BL31 boot image to add
 * @param bl33: BL33 boot image to add
 * @return: 0 on success, negative number otherwise
 */
int gi_fip_create(char const *bl2, char const *bl30, char const *bl31,
		char const *bl33, char const *fout)
{
	struct fip fip;
	struct amlcblk acb;
	struct {
		char const *path;
		enum FIP_BOOT_IMG type;
	} fip_bin_path[] = {
		{
			.path = bl30,
			.type = FBI_BL30,
		},
		{
			.path = bl31,
			.type = FBI_BL31,
		},
		{
			.path = bl33,
			.type = FBI_BL33,
		},
	};
	size_t i;
	off_t off;
	int fdin = -1, fdout = -1, tmpfd = -1, ret;
	char fippath[] = "/tmp/fip.enc.XXXXXX";

	DBG("Create FIP final image in %s\n", fout);

	ret = fip_init(&fip);
	if(ret < 0)
		goto exit;

	fdout = open(fout, O_RDWR | O_CREAT, FOUT_MODE_DFT);
	if(fdout < 0) {
		PERR("Cannot open file %s", fout);
		ret = -errno;
		goto out;
	}

	ret = ftruncate(fdout, 0);
	if(ret < 0)
		goto out;

	fdin = open(bl2, O_RDONLY);
	if(fdin < 0) {
		PERR("Cannot open bl2 %s", bl2);
		ret = -errno;
		goto out;
	}

	ret = gi_fip_dump_img(fdin, fdout, 0);
	if(ret < 0)
		goto out;

	/* Add all BL3* images */
	for(i = 0; i < ARRAY_SIZE(fip_bin_path); ++i) {
		close(fdin);
		fdin = open(fip_bin_path[i].path, O_RDONLY);
		if(fdin < 0) {
			PERR("Cannot open bl %s: ", fip_bin_path[i].path);
			ret = -errno;
			goto out;
		}
		ret = gi_fip_add(&fip, fdout, fdin, fip_bin_path[i].type);
		if(ret < 0)
			goto out;
	}

	tmpfd = gi_fip_create_tmp(fippath);
	if(tmpfd < 0)
		goto out;

	ret = gi_amlcblk_init(&acb, fip.fd);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_aes_enc(&acb, tmpfd, fip.fd);
	if(ret < 0)
		goto out;

	ret = gi_amlcblk_dump_hdr(&acb, tmpfd);
	if(ret < 0)
		goto out;

	off = lseek(tmpfd, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	ret = gi_fip_dump_img(tmpfd, fdout, BL2SZ);
out:
	if(tmpfd >= 0) {
		close(tmpfd);
		(void)remove(fippath);
	}
	if(fdout >= 0)
		close(fdout);
	if(fdin >= 0)
		close(fdin);
	fip_cleanup(&fip);
exit:
	return ret;
}

/**
 * Extract bl2 binary from an Amlogic bootable image
 *
 * @param fdin: Amlogic bootable image
 * @param dir: Output directory
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_extract_bl2(int fdin, char const *dir)
{
	int fdout = -1, ret;
	char path[PATH_MAX];

	ret = snprintf(path, sizeof(path) - 1, "%s/%s", dir, "bl2.sign");
	if((ret < 0) || (ret > (int)(sizeof(path) - 1))) {
		ERR("Filename too long");
		ret = -EINVAL;
		goto out;
	}

	fdout = open(path, O_WRONLY | O_CREAT, FOUT_MODE_DFT);
	if(fdout < 0) {
		PERR("Cannot open file %s", path);
		ret = -errno;
		goto out;
	}

	ret = gi_copy_file(fdin, fdout, BL2SZ);
	if(ret < 0) {
		ERR("Cannot extract BL2 from fip\n");
		goto out;
	}
	if(ret < BL2SZ) {
		ERR("BL2 is too small\n");
		ret = -EINVAL;
		goto out;
	}
	ret = 0;

out:
	if(fdout >= 0)
		close(fdout);
	return ret;
}

/**
 * Extract FIP decode it and read ToC from an Amlogic bootable image
 *
 * @param toc: Filled up with FIP ToC infos
 * @param fdin: Amlogic bootable image
 * @param dir: Output directory
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_extract_fip(struct fip_toc_info *toc, int fdin,
		char const *dir)
{
	struct amlcblk acb;
	char path[PATH_MAX];
	int fip_enc = -1, fip = -1, ret;
	ssize_t off;

	/* Read Amlogic control block */
	off = lseek(fdin, BL2SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	ret = gi_amlcblk_read_hdr(&acb, fdin);
	if(ret < 0)
		goto out;

	ret = snprintf(path, sizeof(path) - 1, "%s/%s", dir, "fip.enc");
	if((ret < 0) || (ret > (int)(sizeof(path) - 1))) {
		ERR("Filename too long");
		ret = -EINVAL;
		goto out;
	}

	fip_enc = open(path, O_RDWR | O_CREAT, FOUT_MODE_DFT);
	if(fip_enc < 0) {
		PERR("Cannot open file %s", path);
		ret = -errno;
		goto out;
	}

	off = lseek(fdin, BL2SZ, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	ret = gi_copy_file(fdin, fip_enc, FIP_SZ);
	if(ret < 0) {
		ERR("Cannot extract encrypted fip from boot image\n");
		goto out;
	}
	if(ret < FIP_SZ) {
		ERR("Encrypted fip is too small\n");
		ret = -EINVAL;
		goto out;
	}

	ret = snprintf(path, sizeof(path) - 1, "%s/%s", dir, "fip");
	if((ret < 0) || (ret > (int)(sizeof(path) - 1))) {
		ERR("Filename too long");
		ret = -EINVAL;
		goto out;
	}

	fip = open(path, O_RDWR | O_CREAT, FOUT_MODE_DFT);
	if(fip < 0) {
		PERR("Cannot open file %s", path);
		ret = -errno;
		goto out;
	}

	ret = gi_amlcblk_aes_dec(&acb, fip, fip_enc);
	if(ret != 0) {
		ERR("Cannot decode FIP header");
		goto out;
	}

	ret = fip_read_toc(toc, fip);
	if(ret != 0) {
		ERR("Cannot read fip");
		goto out;
	}

out:
	if(fip_enc >= 0)
		close(fip_enc);
	if(fip >= 0)
		close(fip);
	return ret;
}

/**
 * Extract bl3x binaries from an Amlogic bootable image
 *
 * @param toc: FIP ToC infos
 * @param fdin: Amlogic bootable image
 * @param dir: Output directory
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_extract_bl3x(struct fip_toc_info const *toc, int fdin,
		char const *dir)
{
	static char const *_fname[] = {
		[FBI_BL30] = "bl30.enc",
		[FBI_BL31] = "bl31.enc",
		[FBI_BL32] = "bl32.enc",
		[FBI_BL33] = "bl33.enc",
	};
	enum FIP_BOOT_IMG type;
	char path[PATH_MAX];
	off_t off;
	ssize_t len;
	size_t i;
	int binfd = -1, ret = 0;

	for(i = 0; i < toc->nr_files; ++i) {
		type = toc->files[i].type;
		if((type >= ARRAY_SIZE(_fname)) || (_fname[type] == NULL)) {
			DBG("Unknown binary %d\n", type);
			continue;
		}
		ret = snprintf(path, sizeof(path) - 1, "%s/%s", dir,
				_fname[type]);
		if((ret < 0) || (ret > (int)(sizeof(path) - 1))) {
			ERR("Filename too long");
			ret = -EINVAL;
			goto out;
		}

		binfd = open(path, O_WRONLY | O_CREAT, FOUT_MODE_DFT);
		if(binfd < 0) {
			PERR("Cannot open file %s", path);
			ret = -errno;
			goto out;
		}

		off = lseek(fdin, BL2SZ + toc->files[i].offset, SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}

		len = gi_copy_file(fdin, binfd, toc->files[i].size);
		if(len < 0) {
			PERR("Cannot copy binary file %s", path);
			ret = -errno;
			goto out;
		}
		if((size_t)len != toc->files[i].size)
			DBG("Binary file is truncated %s", path);
		close(binfd);
		binfd=-1;
	}

out:
	if(binfd >= 0)
		close(binfd);
	return ret;
}

/**
 * Extract encrypted binaries from an Amlogic bootable image
 *
 * @param fip: Amlogic bootable image
 * @param dir: Output directory
 * @return: 0 on success, negative number otherwise
 */
int gi_fip_extract(char const *fip, char const *dir)
{
	struct fip_toc_info toc;
	struct stat st;
	int fdin = -1;
	int ret;

	ret = stat(dir, &st);
	if(ret != 0) {
		PERR("Cannot open dir %s", dir);
		ret = -errno;
		goto out;
	}
	if((st.st_mode & S_IFDIR) == 0) {
		ERR("%s is not a directory", dir);
		ret = -EINVAL;
		goto out;
	}

	fdin = open(fip, O_RDONLY);
	if(fdin < 0) {
		PERR("Cannot open file %s", fip);
		ret = -errno;
		goto out;
	}

	ret = gi_fip_extract_bl2(fdin, dir);
	if(ret < 0)
		goto out;

	ret = gi_fip_extract_fip(&toc, fdin, dir);
	if(ret < 0)
		goto out;

	ret = gi_fip_extract_bl3x(&toc, fdin, dir);
out:
	if(fdin >= 0)
		close(fdin);
	return ret;
}
