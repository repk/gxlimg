#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "gxlimg.h"
#include "bl2.h"
#include "bl3.h"

#define _PROGNAME_DFT "gxlimg"
#define PROGNAME(argc, argv) (((argc) > 0) ? (argv)[0] : _PROGNAME_DFT)
#define USAGE(argc, argv) usage(PROGNAME(argc, argv))

/**
 * Supported actions (e.g. create a boot image, ...)
 */
enum gi_act {
	GA_INVAL,
	GA_CREATE,
	GA_EXTRACT,
};

/**
 * Type of binary file (e.g. BL2, BL3)
 */
enum gi_type {
	GT_INVAL,
	GT_BL2,
	GT_BL3,
};

/**
 * Parsed options
 */
struct gi_opt {
	enum gi_act act;
	enum gi_type type;
	char const *fin;
	char const *fout;
};
#define GI_OPT_INIT(go) do						\
{									\
	(go)->act = GA_INVAL;						\
	(go)->type = GT_INVAL;						\
	(go)->fin = NULL;						\
	(go)->fout = NULL;						\
} while(0)

#define GI_OPT_VALID(go)						\
	(((go)->act != GA_INVAL) && ((go)->type != GT_INVAL) &&		\
	((go)->fin != NULL) && ((go)->fout != NULL))

static void usage(char const *progname)
{
	ERR("Usage: %s [OPTION] <fin> <fout>\n", progname);
	ERR("\t-t, --type\n");
	ERR("\t\ttype of <fin> file (bl2 or bl3)\n");
	ERR("\t-e, --extract\n");
	ERR("\t\textract and decode a BL3 binary from <fin> boot image\n");
	ERR("\t-c, --create\n");
	ERR("\t\tcreate and encode a boot image from <fin> BL3 binary\n");
}

/**
 * Create a bootloader boot image ready to be flashed onto a SD card
 *
 * @param gopt: Boot image creating options
 * @return: 0 on success, negative number otherwise
 */
static int gi_create_img(struct gi_opt *gopt)
{
	int ret = -1;

	switch(gopt->type) {
	case GT_BL2:
		ret = gi_bl2_create_img(gopt->fin, gopt->fout);
		break;
	case GT_BL3:
		ret = gi_bl3_create_img(gopt->fin, gopt->fout);
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
			.name = "create",
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
	};
	int ret;
	int idx;

	GI_OPT_INIT(gopt);

	while((ret = getopt_long(argc, argv, "ect:", opt, &idx)) != -1) {
		switch(ret) {
		case 't':
			if(strcmp(optarg, "bl2") == 0) {
				gopt->type = GT_BL2;
			} else if(strcmp(optarg, "bl3") == 0) {
				gopt->type = GT_BL3;
			} else {
				ERR("%s: invalid <fin> type %s\n",
						PROGNAME(argc, argv), optarg);
				goto out;
			}
			break;
		case 'c':
			gopt->act = GA_CREATE;
			break;
		case 'e':
			gopt->act = GA_EXTRACT;
			break;
		case '?':
			goto out;
		};
	}

	if(optind + 2 > argc) {
		ERR("%s: <fin> and <fout> are mandatory\n",
				PROGNAME(argc, argv));
		goto out;
	}

	gopt->fin = argv[optind];
	gopt->fout = argv[optind + 1];

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
	case GA_CREATE:
		ret = gi_create_img(&opt);
		break;
	case GA_EXTRACT:
		ret = gi_extract(&opt);
		break;
	default:
		ERR("Invalid action %d\n", opt.act);
		ret = -1;
		break;
	}

out:
	return ret;
}
