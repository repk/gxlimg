#ifndef _GXLIMG_H_
#define _GXLIMG_H_

#define ROUNDUP(val, rnd) ((((val) + (rnd) - 1) / (rnd)) * (rnd))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

#define ERR(...) fprintf(stderr, __VA_ARGS__)
#define PERR(...) do {							\
	fprintf(stderr, "%s(%d): ", __FILE__, __LINE__);		\
	fprintf(stderr, __VA_ARGS__);					\
	perror("");							\
} while(0)
#define SEEK_ERR(off, ret) do {						\
	PERR("Cannot seek file: ");					\
	ret = (int)off;							\
} while(0)
#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) do {} while(0)
#endif

#endif
