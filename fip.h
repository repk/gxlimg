#ifndef _FIP_H_
#define _FIP_H_

int gi_fip_create(char const *bl2, char const **ddrfw,
		unsigned int ddrfw_count, char const *bl30, char const *bl301,
		char const *bl31, char const *bl33, char const *fout,
		char const *rev);
int gi_fip_extract(char const *fip, char const *dir);

#endif
