#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "gxlimg.h"
#include "bl2.h"
#include "bl3.h"
#include "fip.h"

#define _PROGNAME_DFT "gxlimg"
#define PROGNAME(argc, argv) (((argc) > 0) ? (argv)[0] : _PROGNAME_DFT)
#define USAGE(argc, argv) usage(PROGNAME(argc, argv))

/**
 * Supported actions (e.g. create a boot image, ...)
 */
enum gi_act {
	GA_INVAL,
	GA_BLSIGN,
	GA_BLUNSIGN,
	GA_BLENC,
	GA_BLDEC,
	GA_BLDECRYPT,
	GA_FIPIMG,
	GA_EXTIMG,
};

/**
 * Type of binary file (e.g. BL2, BL3)
 */
enum gi_type {
	GT_INVAL,
	GT_BL2,
	GT_DDRFW,
	GT_BL3X,
	GT_BL30,
};

/**
 * Parsed options for BL2/BL3 image creation
 */
struct gi_blopt {
	enum gi_type type;
	char const *fin;
	char const *fout;
};
#define GI_BLOPT_INIT(go) do						\
{									\
	(go)->type = GT_INVAL;						\
	(go)->fin = NULL;						\
	(go)->fout = NULL;						\
} while(0)

/**
 * Maximum number of DDR Firmwares
 */
#define MAX_DDRFW	9

/**
 * Parsed options for FIP image creation
 */
struct gi_fipopt {
	char const *bl2;
	char const *ddrfw[MAX_DDRFW];
	unsigned int ddrfw_count;
	char const *bl30;
	char const *bl301;
	char const *bl31;
	char const *bl33;
	char const *fout;
	char const *rev;
};
#define GI_FIPOPT_INIT(go) do						\
{									\
	(go)->bl2 = NULL;						\
	memset(&(go)->ddrfw, 0, sizeof((go)->ddrfw));			\
	(go)->ddrfw_count = 0;						\
	(go)->bl30 = NULL;						\
	(go)->bl301 = NULL;						\
	(go)->bl31 = NULL;						\
	(go)->bl33 = NULL;						\
	(go)->fout = NULL;						\
	(go)->rev = NULL;						\
} while(0)

/**
 * Parsed options for FIP image extraction
 */
struct gi_extopt {
	char const *fip;
	char const *dir;
};
#define GI_EXTOPT_INIT(go) do						\
{									\
	(go)->fip = NULL;						\
	(go)->dir = NULL;						\
} while(0)


/**
 * Parsed options
 */
struct gi_opt {
	enum gi_act act;
	union {
		struct gi_blopt blopt;
		struct gi_fipopt fipopt;
		struct gi_extopt extopt;
	};
};
#define GI_OPT_INIT(go) do						\
{									\
	(go)->act = GA_INVAL;						\
} while(0)

#define GI_FIPOPT_VALID(go)						\
	(((go)->act == GA_FIPIMG) && ((go)->fipopt.bl2 != NULL) &&	\
	((go)->fipopt.bl30 != NULL) && ((go)->fipopt.bl31 != NULL) &&	\
	((go)->fipopt.bl33 != NULL) && ((go)->fipopt.fout != NULL))

#define GI_EXTOPT_VALID(go)						\
	(((go)->act == GA_EXTIMG) && ((go)->extopt.fip != NULL) &&	\
	((go)->extopt.dir != NULL))

#define GI_BLOPT_VALID(go)						\
	(((go)->act != GA_INVAL) && ((go)->blopt.type != GT_INVAL) &&	\
	((go)->blopt.fin != NULL) && ((go)->blopt.fout != NULL))

#define GI_OPT_VALID(go) (GI_FIPOPT_VALID(go) || GI_EXTOPT_VALID(go) ||	\
		GI_BLOPT_VALID(go))

static void usage(char const *progname)
{
	ERR("Usage:\n");
	ERR("\t%s [OPTION] <fin> <fout>\n", progname);
	ERR("\t%s -t fip [OPTION] <fout>\n\n", progname);
	ERR("\t-t, --type\n");
	ERR("\t\ttype of <fin> file (bl2 or bl30 or bl3x or fip)\n");
	ERR("\n\tbl2 and bl3x options :\n");
	ERR("\t---------------------\n");
	ERR("\t-e, --extract\n");
	ERR("\t\textract the different binary images from <fin> boot image\n");
	ERR("\t\tand store them in fout directory\n");
	ERR("\t-s, --sign\n");
	ERR("\t\tsign a boot image from <fin> binary image\n");
	ERR("\t-u, --unsign\n");
	ERR("\t\tget a boot image from <fin> signed binary image\n");
	ERR("\t-c, --encrypt\n");
	ERR("\t\tcreate and encrypt a bl boot image from <fin> binary image\n");
	ERR("\t-d, --decrypt\n");
	ERR("\t\tdecrypt a bl boot image from <fin> store it in <fout>\n");
	ERR("\n\tfip options :\n");
	ERR("\t--------------\n");
	ERR("\t--bl2\n");
	ERR("\t\tBL2 boot file to add in final boot image\n");
	ERR("\t--ddrfw\n");
	ERR("\t\tDDR Firmware(s) file(s) to add in final boot image\n");
	ERR("\t--bl30\n");
	ERR("\t\tBL30 boot file to add in final boot image\n");
	ERR("\t--bl301\n");
	ERR("\t\tBL301 optional boot file to add in final boot image\n");
	ERR("\t--bl31\n");
	ERR("\t\tBL31 boot file to add in final boot image\n");
	ERR("\t--bl33\n");
	ERR("\t\tBL31 boot file to add in final boot image\n");
	ERR("\t--rev\n");
	ERR("\t\tFIP format revision (v2 or v3)\n");
}

/**
 * Sign a bootloader boot image ready to be flashed onto a SD card
 *
 * @param gopt: Boot image creating options
 * @return: 0 on success, negative number otherwise
 */
static int gi_sign_img(struct gi_opt *gopt)
{
	int ret = -1;

	switch(gopt->blopt.type) {
	case GT_BL2:
	case GT_BL30:
		ret = gi_bl2_sign_img(gopt->blopt.fin, gopt->blopt.fout);
		break;
	case GT_BL3X:
		ret = gi_bl3_sign_img(gopt->blopt.fin, gopt->blopt.fout);
		break;
	default:
		break;
	}
	return ret;
}

/**
 * Extract a bootloader boot image from a signed one
 *
 * @param gopt: Boot image creating options
 * @return: 0 on success, negative number otherwise
 */
static int gi_unsign_img(struct gi_opt *gopt)
{
	int ret = -1;

	switch(gopt->blopt.type) {
	case GT_BL2:
	case GT_BL30:
		ret = gi_bl2_unsign_img(gopt->blopt.fin, gopt->blopt.fout);
		break;
	default:
		break;
	}
	return ret;
}

/**
 * Encrypt a bootloader boot image ready to be flashed onto a SD card
 *
 * @param gopt: Boot image options
 * @return: 0 on success, negative number otherwise
 */
static int gi_encrypt_img(struct gi_opt *gopt)
{
	int ret = -1;

	switch(gopt->blopt.type) {
	case GT_BL3X:
		ret = gi_bl3_encrypt_img(gopt->blopt.fin, gopt->blopt.fout);
		break;
	default:
		break;
	}
	return ret;
}

/**
 * Decrypt a bootloader boot image
 *
 * @param gopt: Boot image options
 * @return: 0 on success, negative number otherwise
 */
static int gi_decrypt_img(struct gi_opt *gopt)
{
	int ret = -1;

	switch(gopt->blopt.type) {
	case GT_BL3X:
		ret = gi_bl3_decrypt_img(gopt->blopt.fin, gopt->blopt.fout);
		break;
	default:
		break;
	}
	return ret;
}

/**
 * Extract all bootloader binaries from a boot image
 *
 * @param gopt: Boot image extraction options
 * @return: 0 on success, negative number otherwise
 */
static int gi_extract(struct gi_opt *gopt)
{
	int ret;

	DBG("Extract files from FIP boot image %s\n", gopt->extopt.fip);
	ret = gi_fip_extract(gopt->extopt.fip, gopt->extopt.dir);
	return ret;
}

/**
 * Create a FIP boot final image
 *
 * @param gopt: Boot image creation options
 * @return: 0 on success, negative number otherwise
 */
static int gi_fipimg_create(struct gi_opt *gopt)
{
	int ret;

	DBG("Creating final FIP boot image %s\n", gopt->fipopt.fout);
	ret = gi_fip_create(gopt->fipopt.bl2, gopt->fipopt.ddrfw,
			gopt->fipopt.ddrfw_count, gopt->fipopt.bl30,
			gopt->fipopt.bl301, gopt->fipopt.bl31,
			gopt->fipopt.bl33, gopt->fipopt.fout,
			gopt->fipopt.rev);
	return ret;
}
/**
 * Parse program arguments
 *
 * @param gopt: Filled with parsed options
 * @param argc: number of argument to parse
 * @param argv: Array of argument
 * @return: 0 on success, negative number otherwise
 */
static int parse_args(struct gi_opt *gopt, int argc, char *argv[])
{
	struct option opt[] = {
		{
			.name = "type",
			.has_arg = 1,
			.flag = NULL,
			.val = 't',
		},
		{
			.name = "sign",
			.has_arg = 0,
			.flag = NULL,
			.val = 's',
		},
		{
			.name = "unsign",
			.has_arg = 0,
			.flag = NULL,
			.val = 'u',
		},
		{
			.name = "encrypt",
			.has_arg = 0,
			.flag = NULL,
			.val = 'c',
		},
		{
			.name = "decrypt",
			.has_arg = 0,
			.flag = NULL,
			.val = 'd',
		},
		{
			.name = "extract",
			.has_arg = 0,
			.flag = NULL,
			.val = 'e',
		},
		{
			.name = "bl2",
			.has_arg = 1,
			.flag = NULL,
			.val = '2',
		},
		{
			.name = "ddrfw",
			.has_arg = 1,
			.flag = NULL,
			.val = '6',
		},
		{
			.name = "bl30",
			.has_arg = 1,
			.flag = NULL,
			.val = '0',
		},
		{
			.name = "bl301",
			.has_arg = 1,
			.flag = NULL,
			.val = '4',
		},
		{
			.name = "bl31",
			.has_arg = 1,
			.flag = NULL,
			.val = '1',
		},
		{
			.name = "bl33",
			.has_arg = 1,
			.flag = NULL,
			.val = '3',
		},
		{
			.name = "rev",
			.has_arg = 1,
			.flag = NULL,
			.val = '5',
		},
	};
	struct gi_blopt blopt;
	struct gi_fipopt fipopt;
	struct gi_extopt extopt;
	int ret;
	int idx;

	GI_OPT_INIT(gopt);
	GI_BLOPT_INIT(&blopt);
	GI_FIPOPT_INIT(&fipopt);
	GI_EXTOPT_INIT(&extopt);

	while((ret = getopt_long(argc, argv, "ecdsut:", opt, &idx)) != -1) {
		switch(ret) {
		case 't':
			if(strcmp(optarg, "bl2") == 0) {
				blopt.type = GT_BL2;
			} else if(strcmp(optarg, "bl3x") == 0) {
				blopt.type = GT_BL3X;
			} else if(strcmp(optarg, "bl30") == 0) {
				blopt.type = GT_BL30;
			} else if(strcmp(optarg, "fip") == 0) {
				gopt->act = GA_FIPIMG;
			} else {
				ERR("%s: invalid <fin> type %s\n",
						PROGNAME(argc, argv), optarg);
				goto out;
			}
			break;
		case 's':
			gopt->act = GA_BLSIGN;
			break;
		case 'u':
			gopt->act = GA_BLUNSIGN;
			break;
		case 'c':
			gopt->act = GA_BLENC;
			break;
		case 'd':
			gopt->act = GA_BLDEC;
			break;
		case 'e':
			gopt->act = GA_EXTIMG;
			break;
		case '2':
			fipopt.bl2 = optarg;
			break;
		case '6':
			fipopt.ddrfw[fipopt.ddrfw_count++] = optarg;
			break;
		case '0':
			fipopt.bl30 = optarg;
			break;
		case '4':
			fipopt.bl301 = optarg;
			break;
		case '1':
			fipopt.bl31 = optarg;
			break;
		case '3':
			fipopt.bl33 = optarg;
			break;
		case '5':
			fipopt.rev = optarg;
			break;
		case '?':
			goto out;
		};
	}

	if(gopt->act == GA_FIPIMG) {
		if(optind + 1 > argc) {
			ERR("%s: <fout> is mandatory\n", PROGNAME(argc, argv));
			goto out;
		}

		fipopt.fout = argv[optind];
		memcpy(&gopt->fipopt, &fipopt, sizeof(fipopt));
	} else {
		if(optind + 2 > argc) {
			ERR("%s: <fin> and <fout> are mandatory\n",
					PROGNAME(argc, argv));
			goto out;
		}

		if(gopt->act == GA_EXTIMG) {
			extopt.fip = argv[optind];
			extopt.dir = argv[optind + 1];
			memcpy(&gopt->extopt, &extopt, sizeof(extopt));
		} else {
			blopt.fin = argv[optind];
			blopt.fout = argv[optind + 1];
			memcpy(&gopt->blopt, &blopt, sizeof(blopt));
		}
	}

out:
	return (GI_OPT_VALID(gopt)) ? 0 : -1;
}

int main(int argc, char *argv[])
{
	struct gi_opt opt;
	int ret;

	ret = parse_args(&opt, argc, argv);
	if(ret < 0) {
		USAGE(argc, argv);
		goto out;
	}

	switch(opt.act) {
	case GA_BLSIGN:
		ret = gi_sign_img(&opt);
		break;
	case GA_BLUNSIGN:
		ret = gi_unsign_img(&opt);
		break;
	case GA_BLENC:
		ret = gi_encrypt_img(&opt);
		break;
	case GA_BLDEC:
		ret = gi_decrypt_img(&opt);
		break;
	case GA_EXTIMG:
		ret = gi_extract(&opt);
		break;
	case GA_FIPIMG:
		ret = gi_fipimg_create(&opt);
		break;
	default:
		ERR("Invalid action %d\n", opt.act);
		ret = -1;
		break;
	}

out:
	return ret;
}
