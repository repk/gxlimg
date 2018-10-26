#ifndef _GXLIMG_H_
#define _GXLIMG_H_

#define ROUNDUP(val, rnd) ((((val) + (rnd) - 1) / (rnd)) * (rnd))

#define ERR(...) fprintf(stderr, __VA_ARGS__)
#define PERR(...) fprintf(stderr, __VA_ARGS__); perror("")
#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) do {} while(0)
#endif

#endif
