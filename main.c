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
	GA_BLENC,
	GA_BLEXTRACT,
	GA_FIPIMG,
};

/**
 * Type of binary file (e.g. BL2, BL3)
 */
enum gi_type {
	GT_INVAL,
	GT_BL2,
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
 * Parsed options for FIP image creation
 */
struct gi_fipopt {
	char const *bl2;
	char const *bl30;
	char const *bl31;
	char const *bl33;
	char const *fout;
};
#define GI_FIPOPT_INIT(go) do						\
{									\
	(go)->bl2 = NULL;						\
	(go)->bl30 = NULL;						\
	(go)->bl31 = NULL;						\
	(go)->bl33 = NULL;						\
	(go)->fout = NULL;						\
} while(0)

/**
 * Parsed options
 */
struct gi_opt {
	enum gi_act act;
	union {
		struct gi_blopt blopt;
		struct gi_fipopt fipopt;
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

#define GI_BLOPT_VALID(go)						\
	(((go)->act != GA_INVAL) && ((go)->blopt.type != GT_INVAL) &&	\
	((go)->blopt.fin != NULL) && ((go)->blopt.fout != NULL))

#define GI_OPT_VALID(go) (GI_FIPOPT_VALID(go) || GI_BLOPT_VALID(go))

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
	ERR("\t\textract and decode a binary image from <fin> boot image\n");
	ERR("\t-s, --sign\n");
	ERR("\t\tsign a boot image from <fin> binary image\n");
	ERR("\t-c, --encrypt\n");
	ERR("\t\tcreate and encrypt a boot image from <fin> binary image\n");
	ERR("\n\tfip options :\n");
	ERR("\t--------------\n");
	ERR("\t--bl2\n");
	ERR("\t\tBL2 boot file to add in final boot image\n");
	ERR("\t--bl30\n");
	ERR("\t\tBL30 boot file to add in final boot image\n");
	ERR("\t--bl31\n");
	ERR("\t\tBL31 boot file to add in final boot image\n");
	ERR("\t--bl33\n");
	ERR("\t\tBL31 boot file to add in final boot image\n");
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
 * Encrypt a bootloader boot image ready to be flashed onto a SD card
 *
 * @param gopt: Boot image creating options
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
 * Extract a bootloader code from a bootloader boot image
 *
 * @param gopt: Boot image extraction options
 * @return: 0 on success, negative number otherwise
 */
static int gi_extract(struct gi_opt *gopt)
{
	(void)gopt;
	ERR("Extracting a binary bl from boot image is not implemented yet\n");
	return -1;
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
	ret = gi_fip_create(gopt->fipopt.bl2, gopt->fipopt.bl30,
			gopt->fipopt.bl31, gopt->fipopt.bl33,
			gopt->fipopt.fout);
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
			.name = "enc",
			.has_arg = 0,
			.flag = NULL,
			.val = 'c',
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
			.name = "bl30",
			.has_arg = 1,
			.flag = NULL,
			.val = '0',
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
	};
	struct gi_blopt blopt;
	struct gi_fipopt fipopt;
	int ret;
	int idx;

	GI_OPT_INIT(gopt);
	GI_BLOPT_INIT(&blopt);
	GI_FIPOPT_INIT(&fipopt);

	while((ret = getopt_long(argc, argv, "ecst:", opt, &idx)) != -1) {
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
		case 'c':
			gopt->act = GA_BLENC;
			break;
		case 'e':
			gopt->act = GA_BLEXTRACT;
			break;
		case '2':
			fipopt.bl2 = optarg;
			break;
		case '0':
			fipopt.bl30 = optarg;
			break;
		case '1':
			fipopt.bl31 = optarg;
			break;
		case '3':
			fipopt.bl33 = optarg;
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

		blopt.fin = argv[optind];
		blopt.fout = argv[optind + 1];
		memcpy(&gopt->blopt, &blopt, sizeof(blopt));
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
	case GA_BLENC:
		ret = gi_encrypt_img(&opt);
		break;
	case GA_BLEXTRACT:
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
