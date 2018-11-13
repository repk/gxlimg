#ifndef _SSL_H_
#define _SSL_H_

#include <openssl/evp.h>
#include <openssl/err.h>

#define SSLERR(ret, ...) do						\
{									\
	char __sslerrbuf[256];						\
	fprintf(stderr, __VA_ARGS__);					\
	ret = -ERR_get_error();						\
	ERR_error_string_n(-ret, __sslerrbuf, sizeof(__sslerrbuf));	\
	fprintf(stderr, "%s\n", __sslerrbuf);				\
} while(0)

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline void *OPENSSL_zalloc(size_t num)
{
	void *ret = OPENSSL_malloc(num);

	if (ret != NULL)
		memset(ret, 0, num);
	return ret;
}

static inline EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

static inline void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif

/**
 * Fill a buffer with random data
 *
 * @param buf: Buffer to fill with random data
 * @param sz: Number of random byte to read
 *
 * @return: 0 on success negative number otherwise
 */
static inline int gi_random(uint8_t *buf, size_t sz)
{
	int ret, fd = -1;
	size_t i;
	ssize_t nr;

	ret = open("/dev/urandom", O_RDONLY);
	if(ret < 0) {
		PERR("Cannot open /dev/urandom: ");
		goto out;
	}
	fd = ret;

	for(i = 0; i < sz; i += nr) {
		nr = read(fd, buf, sz - i);
		if(nr < 0) {
			PERR("Cannot read /dev/urandom: ");
			ret = (int)nr;
			goto out;
		}
	}
	ret = 0;
out:
	if(fd >= 0)
		close(fd);
	return ret;
}

#endif
