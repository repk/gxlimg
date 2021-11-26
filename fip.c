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
#include "ssl.h"

#define FOUT_MODE_DFT (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define BL31_ENTRY_MAGIC (0x87654321)
#define BL31_MAGIC (0x12348765)
#define AMLSBLK_KEY_MAGIC	(*(uint32_t *)"@KEY")
#define BL2SZ (0xc000)
#define TOC_OFFSET_V3 (0x10)

#define SHA2_SZ (0x20)

/**
 * FIP Format Revision
 */
enum fip_rev {
	GI_FIP_V2,	/* GXL, GXM */
	GI_FIP_V3,	/* G12A, G12B, SM1 */
};

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
	FBI_BL301,
	FBI_BL31,
	FBI_BL32,
	FBI_BL33,
	FBI_BL2_DATA,
	FBI_BL30_DATA,
	FBI_BL31_DATA,
	FBI_BL32_DATA,
	FBI_BL33_DATA,
	FBI_EMPTY,
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
	[FBI_BL301] = {
		0xdd, 0xcc, 0xbb, 0xaa, 0xcd, 0xab, 0xef, 0xef,
		0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd
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
	[FBI_BL2_DATA] = {
		0xf4, 0x1d, 0x14, 0x86, 0xcb, 0x95, 0xe6, 0x11,
                0x84, 0x88, 0x84, 0x2b, 0x2b, 0x01, 0xca, 0x38
	},
	[FBI_BL30_DATA] = {
		0x48, 0x56, 0xcc, 0xc2, 0xcc, 0x85, 0xe6, 0x11,
                0xa5, 0x36, 0x3c, 0x97, 0x0e, 0x97, 0xa0, 0xee
	},
	[FBI_BL31_DATA] = {
		0xca, 0xaf, 0xb0, 0x33, 0xce, 0x85, 0xe6, 0x11,
                0x8c, 0x32, 0x00, 0x22, 0x19, 0xc7, 0x77, 0x2f
	},
	[FBI_BL32_DATA] = {
		0x34, 0xa1, 0x48, 0xb8, 0xbc, 0x90, 0xe6, 0x11,
                0x8f, 0xef, 0xa4, 0xba, 0xdb, 0x19, 0xde, 0x03
	},
	[FBI_BL33_DATA] = {
		0x8e, 0x59, 0xd6 ,0x5d, 0x5e, 0x8b, 0xe6, 0x11,
                0xbc, 0xb5, 0xf0, 0xde, 0xf1, 0x83, 0x72, 0x96,
	},
	[FBI_EMPTY] = {},
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

#define FT_DATA_SIZE (0x468)
/**
 * Image fixed data for V3, usage & meaning is unknown
 * We find some similar data in bl32.img header
 * Probably used for secure boot
 */
static uint8_t const uuid_data[][FT_DATA_SIZE] = {
	[FBI_BL2_DATA] =  {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00
		/* Rest is 0x0 */
	},
	[FBI_BL30_DATA] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20, 0x00,
		/* Rest is 0x0 */
	},
	[FBI_BL31_DATA] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x30, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x30, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x30, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01,
		/* Rest is 0x0 */
	},
	[FBI_BL32_DATA] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
		/* Rest is 0x0 */
	},
	[FBI_BL33_DATA] = {},
};
#define FT_DATA_START (0x188)

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
static inline int fip_init(struct fip *fip, enum fip_rev rev)
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

	switch (rev) {
	case GI_FIP_V2:
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
			nr = gi_fip_write_blk(fip->fd, (uint8_t *)&init,
					sizeof(init));
			if(nr < 0) {
				PERR("Cannot write fip toc last entry: ");
				close(fip->fd);
				ret = -errno;
				goto out;
			}
		}
		break;
	case GI_FIP_V3:
		ret = ftruncate(fip->fd, FIP_SZ - SHA2_SZ);
		if(ret < 0) {
			PERR("Cannot truncate fip toc header: ");
			close(fip->fd);
			ret = -errno;
			goto out;
		}

		off = lseek(fip->fd, TOC_OFFSET_V3, SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
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
		break;
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
 * @param rev: FIP Format revision
 * @param bl2sz: BL2 Size
 * @return: 0 on success, negative number otherwise
 */
static int fip_read_toc(struct fip_toc_info *toc, int fd, enum fip_rev rev,
		size_t bl2sz)
{
	struct fip_toc_header tochdr;
	struct fip_toc_entry entry;
	ssize_t nr;
	size_t i;
	off_t off;
	enum FIP_BOOT_IMG type;
	int ret;

	off = lseek(fd, rev == GI_FIP_V3 ? bl2sz + TOC_OFFSET_V3 : 0,
			SEEK_SET);
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
		toc->files[i].type = type;
		if(type == FBI_EMPTY)
			continue;
		if(type == FBI_UNKNOWN)
			break;
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
 * @param rev: FIP Format revision
 * @param bl2sz: BL2 Image Size
 */
static int gi_fip_add(struct fip *fip, int fdout, int fdin,
		enum FIP_BOOT_IMG type, enum fip_rev rev, size_t bl2sz)
{
	static uint32_t const bl31magic[] = {
		BL31_ENTRY_MAGIC,
		0x1,
	};
	struct fip_toc_entry entry;
	size_t sz;
	ssize_t nr;
	size_t skip = 0;
	off_t off;
	int ret;
	uint8_t buf[FTE_BL31HDR_SZ];

	if (fdin >= 0) {
		off = lseek(fdin, 0, SEEK_END);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}
		sz = (size_t)off;

		/* Detect a AMLSBLK image a skip header if found on V3 */
		if (rev == GI_FIP_V3) {
			off = lseek(fdin, 0, SEEK_SET);
			if(off < 0) {
				SEEK_ERR(off, ret);
				goto out;
			}

			nr = gi_fip_read_blk(fdin, buf, 4);
			if(nr <= 0) {
				PERR("Cannot read BL image entry\n");
				ret = -errno;
				goto out;
			}

			if (le32toh(*(uint32_t *)buf) == AMLSBLK_KEY_MAGIC) {
				skip = 0x490;
				sz -= skip;
			}
		}
	} else
		sz = 0;

	memcpy(entry.uuid, uuid_list[type], sizeof(entry.uuid));
	entry.offset = fip->cursz;
	entry.flags = 0;
	entry.size = sz;

	off = FTE_OFF(fip->nrentries);
	if (rev == GI_FIP_V3)
		off += TOC_OFFSET_V3;
	
	off = lseek(fip->fd, off, SEEK_SET);
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

	/* Skip writting data if file is not available */
	if (!sz)
		goto nofdin;

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

	off = lseek(fdin, skip, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	gi_fip_dump_img(fdin, fdout, bl2sz + entry.offset);
	fip->cursz += ROUNDUP(sz, 0x4000);

nofdin:
	++fip->nrentries;
	ret = 0;

out:
	return ret;
}

/**
 * Add a bootloader image data in boot image TOC
 *
 * @param fip: Fip handler
 * @param type: Type of bootloader image data
 * @param index: Index of bootloader image data
 */
static int gi_fip_data_add(struct fip *fip, enum FIP_BOOT_IMG type,
			unsigned int index)
{
	struct fip_toc_entry entry;
	ssize_t nr;
	off_t off;
	int ret;

	memcpy(entry.uuid, uuid_list[type], sizeof(entry.uuid));
	entry.offset = FT_DATA_START + (index * FT_DATA_SIZE);
	entry.flags = 0;
	entry.size = FT_DATA_SIZE;

	off = lseek(fip->fd, TOC_OFFSET_V3 + FTE_OFF(fip->nrentries),
			SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_fip_write_blk(fip->fd, (uint8_t *)&entry,
				sizeof(entry));
	if(nr < 0) {
		PERR("Cannot write FIP entry\n");
		ret = -errno;
		goto out;
	}

	off = lseek(fip->fd, entry.offset, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_fip_write_blk(fip->fd, (uint8_t *)&uuid_data[type],
			FT_DATA_SIZE);
	if(nr < 0) {
		PERR("Cannot write FIP data entry\n");
		ret = -errno;
		goto out;
	}

	++fip->nrentries;
	ret = 0;

out:
	return ret;
}

/**
 * DDRFW header structure
 */
#pragma pack(push, 1)
struct fip_ddrfw_toc_header {
	/**
	 * DDRFW magic
	 */
	uint32_t magic;
	/**
	 * DDR Firmware count
	 */
	uint32_t count;
	/**
	 * Flags, reserved for later use
	 */
	uint64_t flags;
};
#pragma pack(pop)
#define DDRFW_MAGIC (0x4d464440)
#define FIP_DDRFW_TOC_HEADER(ddrfw_count)				\
	{								\
		.magic = htole32(DDRFW_MAGIC),				\
		.count = htole32(ddrfw_count),				\
		.flags = 0						\
	}
#define DDRFW_OFF (0x1790)

/**
 * Initialize the DDR firmware TOC
 *
 * @param fip: Fip handler
 * @param ddrfw_count: Number of DDR firmwares
 */
static int gi_fip_ddrfw_init(struct fip *fip, unsigned int ddrfw_count)
{
	struct fip_ddrfw_toc_header toc = FIP_DDRFW_TOC_HEADER(ddrfw_count);
	ssize_t nr;
	off_t off;
	int ret = 0;

	off = lseek(fip->fd, DDRFW_OFF, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	nr = gi_fip_write_blk(fip->fd, (uint8_t *)&toc,	sizeof(toc));
	if(nr < 0) {
		PERR("Cannot write fip toc header: ");
		close(fip->fd);
		ret = -errno;
		goto out;
	}

out:
	return ret;
}

/**
 * DDRFW entry structure
 */
#pragma pack(push, 1)
struct fip_ddrfw_toc_entry {
	/**
	 * DDRFW magic
	 */
	uint8_t magic[8];
	/**
	 * DDRFW offset
	 */
	uint32_t offset;
	/**
	 * DDRFW size
	 */
	uint32_t size;
	/**
	 * DDRFW properties
	 */
	uint8_t props[16];
	/**
	 * DDRFW hash
	 */
	uint8_t hash[SHA2_SZ];
};
#pragma pack(pop)

#define FTE_DDRFW_OFF(i)						\
	(DDRFW_OFF + sizeof(struct fip_ddrfw_toc_header) + 		\
	 (i * sizeof(struct fip_ddrfw_toc_entry)))

/**
 * Add a DDR Firmware data in boot image TOC
 *
 * @param fip: Fip handler
 * @param fdout: Final boot image file
 * @param fdin: Bootloader image to add
 * @param index: Index of DDR Firmware
 * @param bl2sz: Size of BL2 image
 */
static int gi_fip_ddrfw_add(struct fip *fip, int fdout, int fdin,
		size_t index, size_t bl2sz)
{
	struct fip_ddrfw_toc_entry entry;
	uint8_t tmp[1024];
	EVP_MD_CTX *ctx;
	size_t sz;
	ssize_t nr;
	off_t off;
	size_t i;
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

	off = lseek(fdin, 0, SEEK_END);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	sz = (size_t)off;

	entry.offset = fip->cursz;
	/* Align size on 16k */
	entry.size = ((sz - 0x60) + 0x3fff) & 0xffffc000;

	off = lseek(fdin, 0x20, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	nr = gi_fip_read_blk(fdin, (uint8_t *)&entry.magic, sizeof(entry.magic));
	if(nr <= 0) {
		PERR("Cannot read DDRFW magic\n");
		ret = -errno;
		goto out;
	}

	off = lseek(fdin, 0x30, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	nr = gi_fip_read_blk(fdin, (uint8_t *)&entry.props, sizeof(entry.props));
	if(nr <= 0) {
		PERR("Cannot read DDRFW properties\n");
		ret = -errno;
		goto out;
	}

	off = lseek(fdin, 0x60, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	for(i = 0; i < (sz - 0x60); i += nr) {
		nr = gi_fip_read_blk(fdin, tmp, sizeof(tmp));
		if(nr < 0) {
			PERR("Cannot read fd %d:", fdin);
			ret = (int)nr;
			goto out;
		}
		ret = EVP_DigestUpdate(ctx, tmp, nr);
		if(ret != 1) {
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}
	}

	/* Add potential padding to digest aswell */
	while (i < entry.size) {
		memset(tmp, 0, sizeof(tmp));
		nr = MIN(entry.size - i, sizeof(tmp));

		ret = EVP_DigestUpdate(ctx, tmp, nr);
		if(ret != 1) {
			SSLERR(ret, "Cannot hash data block: ");
			goto out;
		}

		i += nr;
	}

	ret = EVP_DigestFinal_ex(ctx, (uint8_t *)&entry.hash, NULL);
	if(ret != 1) {
		SSLERR(ret, "Cannot finalize hash: ");
		goto out;
	}

	off = lseek(fip->fd, FTE_DDRFW_OFF(index), SEEK_SET);
		if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}
	nr = gi_fip_write_blk(fip->fd, (uint8_t *)&entry, sizeof(entry));
	if(nr < 0) {
		PERR("Cannot write DDRFW entry\n");
		ret = -errno;
		goto out;
	}

	off = lseek(fdin, 0x60, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	gi_fip_dump_img(fdin, fdout, bl2sz + entry.offset);
	fip->cursz += entry.size;

	ret = 0;

out:
	return ret;
}

/**
 * Calculate final FIP toc hash
 *
 * @param fip: Fip handler
 */
static int gi_fip_v3_fini(int fipfd)
{
	EVP_MD_CTX *ctx;
	uint8_t tmp[1024];
	uint8_t hash[SHA2_SZ];
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

	off = lseek(fipfd, TOC_OFFSET_V3, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	/* SHA256 is from 0x10 to (FIP_SZ - 0x40) */
	for(i = 0; i < (FIP_SZ - (2 * SHA2_SZ)); i += nr) {
		nr = gi_fip_read_blk(fipfd, tmp, sizeof(tmp));
		if(nr < 0) {
			PERR("Cannot read fd %d:", fipfd);
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

	off = lseek(fipfd, (FIP_SZ - SHA2_SZ), SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	ret = gi_fip_write_blk(fipfd, hash, sizeof(hash));
	if (ret < 0)
		goto out;
	ret = 0;

	off = lseek(fipfd, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

out:
	EVP_MD_CTX_free(ctx);
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
int gi_fip_create(char const *bl2, char const **ddrfw,
		unsigned int ddrfw_count, char const *bl30, char const *bl301,
		char const *bl31, char const *bl33, char const *fout,
		char const *revc)
{
	struct fip fip;
	struct amlcblk acb;
	enum fip_rev rev = GI_FIP_V2;
	struct {
		char const *path;
		enum FIP_BOOT_IMG type;
	} fip_bin_path[] = {
		{
			.path = bl30,
			.type = FBI_BL30,
		},
		{
			.path = bl301,
			.type = FBI_BL301,
		},
		{
			.path = bl31,
			.type = FBI_BL31,
		},
		/* BL32 entry, even empty is required needed for V3 */
		{
			.path = NULL,
			.type = FBI_BL32,
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
	off_t bl2sz;

	if (revc && !strcmp(revc, "v3")) {
		DBG("Creating a v3 FIP\n");
		rev = GI_FIP_V3;

		if (ddrfw_count > 0)
			DBG("Adding %d DDR firmwares in %s\n",
				ddrfw_count, fout);
	}

	DBG("Create FIP final image in %s\n", fout);

	ret = fip_init(&fip, rev);
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

	off = lseek(fdin, 0, SEEK_END);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	if (rev == GI_FIP_V2 && off != BL2SZ) {
		PERR("Invalid bl2 size %lx", off);
		ret = -EINVAL;
		goto out;
	}
	bl2sz = off;

	off = lseek(fdin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

	ret = gi_fip_dump_img(fdin, fdout, 0);
	if(ret < 0)
		goto out;

	/* Add the DDR firmwares entries */
	if (rev == GI_FIP_V3 && ddrfw_count) {
		ret = gi_fip_ddrfw_init(&fip, ddrfw_count);
		if (ret < 0)
			goto out;

		for (i = 0; i < ddrfw_count; ++i) {
			close(fdin);
			fdin = open(ddrfw[i], O_RDONLY);
			if(fdin < 0) {
				PERR("Cannot open bl %s: ", ddrfw[i]);
				ret = -errno;
				goto out;
			}
			ret = gi_fip_ddrfw_add(&fip, fdout, fdin, i, bl2sz);
			if (ret < 0)
				goto out;
		}
	}

	/* Add all BL3* images */
	for(i = 0; i < ARRAY_SIZE(fip_bin_path); ++i) {
		/* FBI_BL301 is no more for V3 */
		if (rev == GI_FIP_V3 && fip_bin_path[i].type == FBI_BL301)
			continue;
		/* Do not add entry if missing on V2 */
		if (rev == GI_FIP_V2 && !fip_bin_path[i].path)
			continue;
		if (fdin >= 0)
			close(fdin);
		if(fip_bin_path[i].path) {
			fdin = open(fip_bin_path[i].path, O_RDONLY);
			if(fdin < 0) {
				PERR("Cannot open bl %s: ",
					fip_bin_path[i].path);
				ret = -errno;
				goto out;
			}
		} else
			fdin = -1;
		ret = gi_fip_add(&fip, fdout, fdin, fip_bin_path[i].type,
					rev, bl2sz);
		if(ret < 0)
			goto out;
	}

	/* Add the Image DATA entries, even if the image still boots without */
	if (rev == GI_FIP_V3) {
		static enum FIP_BOOT_IMG const data_list[] = {
			FBI_BL2_DATA,
			FBI_BL30_DATA,
			FBI_BL31_DATA,
			FBI_BL32_DATA,
			FBI_BL33_DATA
		};

		for(i = 0; i < ARRAY_SIZE(data_list); ++i) {
			ret = gi_fip_data_add(&fip, data_list[i], i);
			if (ret < 0)
				goto out;
		}
	}

	if (rev == GI_FIP_V2) {
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
	} else {
		ret = gi_fip_v3_fini(fip.fd);
		if(ret < 0)
			goto out;

		ret = gi_fip_dump_img(fip.fd, fdout, bl2sz);
	}
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
 * @param bl2sz: BL2 Size
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_extract_bl2(int fdin, char const *dir, int bl2sz)
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

	ret = gi_copy_file(fdin, fdout, bl2sz);
	if(ret < 0) {
		ERR("Cannot extract BL2 from fip\n");
		goto out;
	}
	if(ret < bl2sz) {
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
 * @param rev: FIP Format revision
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

	ret = fip_read_toc(toc, fip, GI_FIP_V2, BL2SZ);
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
 * @param bl2sz: BL2 Size
 * @return: 0 on success, negative number otherwise
 */
static int gi_fip_extract_bl3x(struct fip_toc_info const *toc, int fdin,
		char const *dir, int bl2sz)
{
	static char const *_fname[] = {
		[FBI_BL30] = "bl30.enc",
		[FBI_BL301] = "bl301.enc",
		[FBI_BL31] = "bl31.enc",
		[FBI_BL32] = "bl32.enc",
		[FBI_BL33] = "bl33.enc",
		[FBI_BL2_DATA] = "bl2.dat",
		[FBI_BL30_DATA] = "bl30.dat",
		[FBI_BL31_DATA] = "bl31.dat",
		[FBI_BL32_DATA] = "bl32.dat",
		[FBI_BL33_DATA] = "bl33.dat",
	};
	enum FIP_BOOT_IMG type;
	char path[PATH_MAX];
	off_t off;
	ssize_t len;
	size_t i;
	int binfd = -1, ret = 0;

	for(i = 0; i < toc->nr_files; ++i) {
		type = toc->files[i].type;
		if (type == FBI_EMPTY)
			continue;
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

		off = lseek(fdin, bl2sz + toc->files[i].offset, SEEK_SET);
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
 * Determine the FIP version and BL2 size
 *
 * @param fdin: Amlogic bootable image file descriptor
 * @param rev: FIP Format revision
 * @param bl2sz: BL2 Size
 * @return: 0 on success, negative number otherwise
 */
int gi_fip_check(int fdin, enum fip_rev *rev, size_t *bl2sz)
{
	struct fip_toc_header tochdr;
	static size_t known_sizes[] = {
		BL2SZ, 0x10000, 0
	};
	int size_id = 0;
	off_t off;
	int ret;

	/* Default to V2 values */
	*rev = GI_FIP_V2;
	*bl2sz = BL2SZ;

	while (known_sizes[size_id]) {
		/* Check if v3 */
		off = lseek(fdin, known_sizes[size_id] + TOC_OFFSET_V3,
				SEEK_SET);
		if(off < 0) {
			SEEK_ERR(off, ret);
			goto out;
		}

		/* Verify FIP TOC header first */
		ret = gi_fip_read_blk(fdin, (uint8_t *)&tochdr,
					sizeof(tochdr));
		if(ret < 0) {
			PERR("Cannot read FIP header\n");
			ret = -errno;
			goto out;
		}

		if(!memcmp((uint8_t *)&tochdr, (uint8_t *)FIP_TOC_HEADER,
					sizeof(tochdr))) {
			DBG("Detected FIP v3 format at offset 0x%lx\n",
				known_sizes[size_id] + TOC_OFFSET_V3);
			*rev = GI_FIP_V3;
			*bl2sz = known_sizes[size_id];
			break;
		}

		size_id++;
	}

	off = lseek(fdin, 0, SEEK_SET);
	if(off < 0) {
		SEEK_ERR(off, ret);
		goto out;
	}

out:
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
	enum fip_rev rev = GI_FIP_V2;
	size_t bl2sz = BL2SZ;
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

	ret = gi_fip_check(fdin, &rev, &bl2sz);
	if (ret < 0) {
		PERR("Cannot check FIP revision\n");
		goto out;
	}

	ret = gi_fip_extract_bl2(fdin, dir, bl2sz);
	if(ret < 0)
		goto out;

	if (rev == GI_FIP_V3)
		ret = fip_read_toc(&toc, fdin, rev, bl2sz);
	else
		ret = gi_fip_extract_fip(&toc, fdin, dir);
	if(ret < 0)
		goto out;

	ret = gi_fip_extract_bl3x(&toc, fdin, dir, bl2sz);
out:
	if(fdin >= 0)
		close(fdin);
	return ret;
}
