#ifndef _FIP_H_
#define _FIP_H_

int gi_fip_create(char const *bl2, char const *bl30, char const *bl31,
		char const *bl33, char const *fout);
int gi_fip_extract(char const *fip, char const *dir);

#endif
