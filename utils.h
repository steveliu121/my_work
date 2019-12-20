#ifndef __NOTEPAD_UTILS_H
#define __NOTEPAD_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif


int __get_file_size(const char *file);
int __create_cache_dir(const char *dir);
void __remove_cache_dir(const char *dir);


#ifdef __cplusplus
}
#endif

#endif
