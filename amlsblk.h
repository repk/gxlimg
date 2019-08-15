#ifndef _AMLSBLK_H_
#define _AMLSBLK_H_

#define IMGHDR_SZ	0x200
#define BL3xIV_SZ	0x10
#define BL3xSB_SZ	0x80
#define BL3xSIG_SZ	0x200
#define BL3xKEYHDR_SZ	0x30
#define BL3xSHA2_SZ	0x20

#define BL3xHDR_SZ	(BL3xIV_SZ + BL3xSB_SZ + BL3xSIG_SZ)

/* Amlogic signature block description */
struct amlsblk {
	size_t payloadsz;
	size_t blksz;
	size_t totsz;
	size_t hashsz;
	size_t topad;
	uint8_t flag;
	uint8_t hash[BL3xSHA2_SZ];
	uint8_t hdr_hash[BL3xSHA2_SZ];
	uint8_t hdr[BL3xHDR_SZ - BL3xIV_SZ - BL3xSHA2_SZ];
};

int gi_amlsblk_init(struct amlsblk *asb, int fd);
int gi_amlsblk_hash_payload(struct amlsblk *asb, int fin);
int gi_amlsblk_build_header(struct amlsblk *asb);
int gi_amlsblk_flush_data(struct amlsblk *asb, int fin, int fout);

#endif
