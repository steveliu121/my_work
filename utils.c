#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int __get_file_size(const char *file)
{
	int ret = 0;
	int size = 0;
	FILE *fp = NULL;

	fp = fopen(file, "r");
	if(!fp) {
		fprintf(stderr, "open %s fail, %s\n", file, strerror(errno));
		ret = -1;
		goto out;
	}

	ret = fseek(fp, 0, SEEK_END);
	if(ret) {
		fprintf(stderr, "seek %s fail, %s\n", file, strerror(errno));
		ret = -1;
		goto out;
	}

	size = ftell(fp);

	ret = fseek(fp, 0, SEEK_SET);
	if(ret) {
		fprintf(stderr, "seek %s fail, %s\n", file, strerror(errno));
		ret = -1;
		goto out;
	}

out:
	if (fp)
		fclose(fp);

	return ret ? ret : size;

}

int __create_cache_dir(const char *dir)
{
	int ret = 0;

	if (!access(dir, F_OK)) {
		fprintf(stdout, "Cache directory already exist\n");
		return 0;
	}

	ret = mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH);
	if (ret) {
		fprintf(stderr, "Create file cache directory fail, [%s]\n",
				strerror(errno));
		ret = -1;
	}

	return ret;
}

void __remove_cache_dir(const char *dir)
{
	if (access(dir, F_OK)) {
		fprintf(stdout, "Cache directory not exist\n");
		return;
	}

	rmdir(dir);
}

