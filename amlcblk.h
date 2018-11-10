#ifndef _AMLCBLK_H_
#define _AMLCBLK_H_

/* Amlogic control block description */
struct amlcblk {
	size_t blksz; /* Size of one output block */
	size_t firstblk; /* Offset of first block */
	size_t encsz; /* Size of encrypted payload */
	size_t payloadsz; /* Size of decrypted payload */
	uint8_t iv[16]; /* AES-256-CBC Initialization vector */
	uint8_t aeskey[32]; /* AES-256-CBC key */
	uint8_t flag; /* AMLCBLK flags */
};

int gi_amlcblk_init(struct amlcblk *acb, int fd);
int gi_amlcblk_dump_hdr(struct amlcblk const *acb, int fd);
int gi_amlcblk_aes_enc(struct amlcblk *acb, int fout, int fin);

#endif
