#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <poll.h>
#include <pthread.h>

#include "utils.h"

/*TODO segmentfault when quit*/
#define FILE_DIR "./notepad"
#define TMP_FILE ".tmpfile"

static int g_exit;

struct option longopts[] = {
	{"port", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};

static void sig_handle(int sig)
{
	g_exit = 1;
}

static void print_usage(void)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, "./notepad_server -p <server_port>\n");
	fprintf(stdout, "example:\n");
	fprintf(stdout, "\t./notepad_server -p 1037\nn");
}

/**获取所有文件（记事本文件）
 * 成功：返回文件的大小，失败：返回-1*/
static int __get_file_list(const char *username, const char *tmp_file)
{
	struct dirent *dir_entry = NULL;
	char path[256] = {0};
	char file_entry[128] = {0};
	int index = 0;
	DIR *dirp = NULL;
	int size = 0;
	int tmp_fd = -1;
	int ret = 0;

	snprintf(path, sizeof(path) - 1, "%s/%s", FILE_DIR, username);

	dirp = opendir(path);
	if (!dirp) {
		fprintf(stdout, "open directory %s fail, [%s]\n", path, strerror(errno));
		ret = -1;
		goto err;
	}

	tmp_fd = open(tmp_file, O_RDWR, S_IRUSR | S_IWUSR);
	if (tmp_fd == -1) {
		fprintf(stderr, "Open tmpfile %s fail, %s\n", tmp_file, strerror(errno));
		ret = -1;
		goto err;
	}
	errno = 0;
	do {
		dir_entry = readdir(dirp);
		if (dir_entry) {
			if (!strncmp(dir_entry->d_name, ".", 1) ||
				!strncmp(dir_entry->d_name, "..", 2))
				continue;
			index++;
			snprintf(file_entry, sizeof(file_entry) - 1, "%d. %s\r\n", index, dir_entry->d_name);
			size += strlen(file_entry);
			ret = write(tmp_fd, file_entry, strlen(file_entry));
			if (ret != strlen(file_entry))
				fprintf(stderr, "write tmpfile fail\n");
		} else if (errno) {
			fprintf(stderr, "read directory %s fail, [%s]\n", path, strerror(errno));
			ret = -1;
		}
	} while (dir_entry);

	close(tmp_fd);
	closedir(dirp);

	return size;

err:
	if (tmp_fd != -1)
		close(tmp_fd);
	if (dirp)
		closedir(dirp);

	return -1;
}

static int __get_ipaddr(const int sockfd)
{
	struct sockaddr_in own_addr;
	socklen_t addrlen = 0;
	char buf[INET_ADDRSTRLEN] = {0};
	int port = 0;
	int ret = 0;
	const char *ret1;

	bzero(&own_addr, sizeof(own_addr));
	addrlen = sizeof(own_addr);
	ret = getsockname(sockfd, (struct sockaddr *)&own_addr, &addrlen);
	if (ret) {
		fprintf(stderr, "%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	ret1 = inet_ntop(own_addr.sin_family, &own_addr.sin_addr, buf, INET_ADDRSTRLEN);
	if (!ret1) {
		fprintf(stderr, "%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	port = ntohs(own_addr.sin_port);

	fprintf(stdout, "######Server ipaddr:[%s], port:[%d]\n", buf, port);

out:
	if (ret)
		fprintf(stderr, "Get ipaddress fail\n");

	return ret;
}

static int __create_server_socket(const int port)
{
	struct sockaddr_in own_addr;
	int optval;
	int sockfd = -1;
	int ret = 0;

	bzero(&own_addr, sizeof(own_addr));

	/*设置服务器信息*/
	own_addr.sin_family = AF_INET;
	own_addr.sin_addr.s_addr = INADDR_ANY;
	own_addr.sin_port = htons(port);

	/*创建IPV4 TCP套接字*/
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd ==-1) {
		fprintf(stdout, "Create socket fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

	optval = 1;
	/*设置套接字选项SO_REUSERADDR,
	 * 避免server重启时绑定套接字到已经关联的端口上出现EADDRINUSE错误*/
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			&optval, sizeof(optval));
	if (ret) {
		fprintf(stdout, "warning reuse socket address fail, [%s]\n",
							strerror(errno));
		ret = -1;
		goto out;
	}

	/*绑定服务器地址信息到套接字上*/
	ret = bind(sockfd, (struct sockaddr *)&own_addr, sizeof(own_addr));
	if (ret) {
		fprintf(stderr, "Warning bind port fail, [%s]\n", strerror(errno));
		ret = -1;
	}

	/*获取服务器的ip地址*/
	__get_ipaddr(sockfd);

out:
	if (ret) {
		fprintf(stderr, "Create server socket fail\n");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/*poll查询是否有数据进来*/
static int inline __poll(const int sockfd, int timeout_ms, short events)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = sockfd;
	pfd.events = events;
	ret = poll(&pfd, 1, timeout_ms);
	if (ret == -1) {
		fprintf(stderr, "Socket poll fail, %s\n", strerror(errno));
		ret = -1;
	}
	if (ret == 0) {
		fprintf(stderr, "Socket poll timeout\n");
		return -1;
	}

	if (pfd.revents & events)
		return 0;

	fprintf(stderr, "Socket poll not the desired event\n");

	return ret;
}

static int __send_response(const int sockfd, const char *msg)
{
	int ret = 0;
	int msg_len = strlen(msg);

	ret = send(sockfd, msg, msg_len, 0);
printf("~~~~~send:%s, %d\n", msg, msg_len);
	if (ret != msg_len) {
		fprintf(stdout, "Send message fail, [%s]\n", strerror(errno));
		ret = -1;
	}

	return ret;
}

static void do_register(const int sockfd, const char *name)
{
	char path[128] = {0};
	char msg[128] = {0};
	int ret = 0;

	snprintf(path, sizeof(path) - 1, "%s/%s", FILE_DIR, name);
	if (!access(path, F_OK)) {
		strcpy(msg, "The username you entered is already in use\n");
		__send_response(sockfd, msg);
		return;
	}

	ret = __create_cache_dir(path);
	if (ret) {
		strcpy(msg, "Create account fail\n");
		__send_response(sockfd, msg);
	}
	else {
		strcpy(msg, "success");
		__send_response(sockfd, msg);
	}
}

static void do_login(const int sockfd, const char *name, char *username)
{
	char path[128] = {0};
	char msg[128] = {0};

	snprintf(path, sizeof(path) - 1, "%s/%s", FILE_DIR, name);
	if (access(path, F_OK)) {
		strcpy(msg, "The username you entered is not exist, please register one\n");
		__send_response(sockfd, msg);
	}
	else {
		/*TODO zero*/
		strncpy(username, name, sizeof(name));
		strcpy(msg, "success");
		__send_response(sockfd, msg);
	}
}

static void do_list(const int sockfd, const char *username)
{
	int tmp_fd = -1;
	char tmp_file[128] = {0};
	char msg[128] = {0};
	int size = 0;
	int ret = 0;

	/*检查用户是否已经登录*/
	if (!strncmp("null", username, strlen(username))) {
		strcpy(msg, "Please login first\n");
		__send_response(sockfd, msg);
		return;
	}

	/*获取文件列表（记事本列表）并发送给客户端*/
	/*创建一个临时文件来缓存未知大小的文件列表数据，模仿stream缓存*/
	snprintf(tmp_file, sizeof(tmp_file) - 1, "%s/%s", FILE_DIR, TMP_FILE);
	tmp_fd = open(tmp_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (tmp_fd == -1) {
		fprintf(stderr, "Create tmpfile fail, [%s]\n", strerror(errno));
		goto err;
	}
	close(tmp_fd);

	size = __get_file_list(username, tmp_file);
	if (size == -1)
		goto err;
	else if (size == 0) {
		strcpy(msg, "There's no notepad\n");
		__send_response(sockfd, msg);
		return;
	}

	tmp_fd = open(tmp_file, O_RDWR, S_IRUSR | S_IWUSR);
	if (tmp_fd == -1) {
		fprintf(stderr, "Open tmpfile %s fail, %s\n", tmp_file, strerror(errno));
		ret = -1;
		goto err;
	}
	ret = sendfile(sockfd, tmp_fd, NULL, size);
	if (ret != size) {
		fprintf(stderr, "Send file to client error, ret[%d], [%s]\n", ret, strerror(errno));
		ret = -1;
		goto err;
	}
	close(tmp_fd);

	return;
err:

	strcpy(msg, "Get notepad list fail\n");
	__send_response(sockfd, msg);
}

static void do_create(const int sockfd, const char *file, const char *username)
{
	int fd = -1;
	char path[256] = {0};
	char msg[128] = {0};
	char buf[4096] = {0};
	int success = 1;
	int size = 0;
	int first = 1;
	int ret = 0;

	/*检查用户是否已经登录*/
	if (!strncmp("null", username, strlen(username))) {
		strcpy(msg, "Please login first\n");
		__send_response(sockfd, msg);
		return;
	}

	/*检查文件是否已经存在*/
	snprintf(path, sizeof(path) - 1, "%s/%s/", FILE_DIR, username);
	strcat(path, file);
	if (!access(path, F_OK)) {
		strcpy(msg, "Notepad already exist\n");
		__send_response(sockfd, msg);
		return;
	}

	/*创建文件（记事本）*/
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "Create notepad fail, [%s]\n", strerror(errno));
		strcpy(msg, "Notepad create fail\n");
		__send_response(sockfd, msg);
		return;
	}
	close(fd);

	/*回复客户端创建文件成功*/
	strcpy(msg, "success");
	__send_response(sockfd, msg);

	/*等待客户端编辑完成后将文件发送回来*/
	fd = open(path, O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		strcpy(msg, "Could not save notepad\n");
		__send_response(sockfd, msg);
		success = 0;
		goto out;
	}
	do {
		ret = recv(sockfd, buf, sizeof(buf) - 1, 0);
		if (ret == -1) {
			strcpy(msg, "Recv notepad fail\n");
			__send_response(sockfd, msg);
			success = 0;
			goto out;
		}

		/*如果是一个空文件，则客户端会发送一个"$empty$file$"标记帧*/
		if (first == 1) {
			if (!strcmp(buf, "$empty$file$")) {
printf("~~~~~get an empty file\n");
				break;
			}
		}
		first = 0;

		size = ret;
		ret = write(fd, buf, size);
		if (ret != size)
			success = 0;

	} while (ret == (sizeof(buf) - 1));

	if (success) {
		strcpy(msg, "success");
		__send_response(sockfd, msg);
	} else {
		strcpy(msg, "Save notepad fail");
		__send_response(sockfd, msg);
	}

out:
	if (fd)
		close(fd);
}

static void do_delete(const int sockfd, const char *file, const char *username)
{
	char path[256] = {0};
	char msg[128] = {0};

	/*检查用户是否已经登录*/
	if (!strncmp("null", username, strlen(username))) {
		strcpy(msg, "Please login first\n");
		__send_response(sockfd, msg);
		return;
	}

	/*检查文件是否已经存在*/
	snprintf(path, sizeof(path) - 1, "%s/%s/", FILE_DIR, username);
	strcat(path, file);
	if (access(path, F_OK)) {
		strcpy(msg, "Notepad not exist\n");
		__send_response(sockfd, msg);
		return;
	}

	/*删除文件（记事本）*/
	remove(path);
	strcpy(msg, "success");
	__send_response(sockfd, msg);
}

static void do_edit(const int sockfd, const char *file, const char *username)
{
	char path[256] = {0};
	char buf[4096] = {0};
	char msg[128] = {0};
	int fd = -1;
	int size = 0;
	int success = 1;
	int first = 1;
	int ret = 0;

	/*1. 检查用户是否已经登录*/
	if (!strncmp("null", username, strlen(username))) {
		strcpy(msg, "Please login first\n");
		__send_response(sockfd, msg);
		return;
	}

	/*2. 检查文件是否已经存在*/
	snprintf(path, sizeof(path) - 1, "%s/%s/", FILE_DIR, username);
	strcat(path, file);
	if (access(path, F_OK)) {
		strcpy(msg, "Notepad not exist\n");
		__send_response(sockfd, msg);
		return;
	}

	/*3. 将文件发送给客户端，以供客户端编辑*/
	size = __get_file_size(path);
	fd = open(path, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		strcpy(msg, "Open notepad fail\n");
		__send_response(sockfd, msg);
		return;
	}
	strcpy(msg, "success");
	__send_response(sockfd, msg);

	/*3. 等待客户端发送开始信号*/
	bzero(msg, sizeof(msg));
	ret = recv(sockfd, msg, sizeof(msg) - 1, 0);
	if (ret == -1) {
		fprintf(stdout, "Recv message fail, [%s]\n", strerror(errno));
		return;
	}
	else if (strcmp(msg, "start")) {
		fprintf(stdout, "Recv message [%s], but not [start]\n", msg);
		return;
	}

	/*4. 将文件发送给客户端*/
	/*如果是一个空文件，则向客户端发送一个"$empty$file"标记帧*/
	if (size == 0) {
		bzero(msg, sizeof(msg));
		strcpy(msg, "$empty$file$");
		ret = send(sockfd, msg, strlen(msg), 0);
		if (ret != strlen(msg)) {
			fprintf(stdout, "Send message fail, [%s]\n", strerror(errno));
			return;
		}
	} else {
		ret = sendfile(sockfd, fd, NULL, size);
		if (ret != size)
			fprintf(stderr, "Send file to client error, [%s]\n", strerror(errno));
		close(fd);
		fd = -1;
	}

	/*5. 等待客户端编辑完成后将文件发送回来*/
	fd = open(path, O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		strcpy(msg, "Could not save notepad\n");
		__send_response(sockfd, msg);
		success = 0;
		goto out;
	}
	do {
		ret = recv(sockfd, buf, sizeof(buf) - 1, 0);
		if (ret == -1) {
			strcpy(msg, "Recv notepad fail\n");
			__send_response(sockfd, msg);
			success = 0;
			goto out;
		}

printf("~~~~~file%s\n", buf);
		/*如果是一个空文件，则客户端会发送一个"$empty$file$"标记帧*/
		if (first == 1) {
			if (!strcmp(buf, "$empty$file$")) {
printf("~~~~~get an empty file\n");
				break;
			}
		}
		first = 0;

		size = ret;
		ret = write(fd, buf, size);
		if (ret != size) {
			strcpy(msg, "Save notepad fail\n");
			__send_response(sockfd, msg);
			success = 0;
		}

	} while (ret == (sizeof(buf) - 1));

	if (success) {
		strcpy(msg, "success");
		__send_response(sockfd, msg);
	}

out:
	if (fd)
		close(fd);
}

static int do_job(const int sockfd, char *buf, const int len, char *username)
{
	char *input = buf;
	char delim[] = ":";
	char *token = NULL;
	char key[64] = {0};
	char value[64] = {0};
	int ret = 0;

	token = strsep(&input, delim);
	strncpy(key, token, sizeof(key));
	strncpy(value, input, sizeof(value));

	if (!strncmp("register", key, strlen(key)))
		do_register(sockfd, value);
	else if (!strncmp("login", key, strlen(key)))
		do_login(sockfd, value, username);
	else if (!strncmp("list", key, strlen(key)))
		do_list(sockfd, username);
	else if (!strncmp("create", key, strlen(key)))
		do_create(sockfd, value, username);
	else if (!strncmp("delete", key, strlen(key)))
		do_delete(sockfd, value, username);
	else if (!strncmp("edit", key, strlen(key)))
		do_edit(sockfd, value,username);
	else if (!strncmp("quit", key, strlen(key)))
		ret = 1;

	return ret;
}

static void *__work_thread(void *arg)
{
	int ret = 0;
	int sockfd = *((int *)arg);
	char buf[4096] = {0};
	char username[128] = "null";
	int recv_len = 0;

	free(arg);

	while (!g_exit) {
		bzero(buf, sizeof(buf));
		ret = __poll(sockfd, 20000, POLLIN);
		if (ret)
			continue;

		recv_len = recv(sockfd, buf, sizeof(buf) - 1, 0);
		if (recv_len == -1)
			fprintf(stdout, "Recv message fail, [%s]\n", strerror(errno));

printf("~~~~~~recv:%s\n", buf);

		ret = do_job(sockfd, buf, recv_len, username);
		/*接收到客户端的quit信息后，跳出循环*/
		if (ret)
			break;
	}

	close(sockfd);

	return NULL;
}

static void server_main(const int port)
{
	int ret = 0;
	int listen_sockfd = -1;
	int sub_sockfd = -1;
	int *sockfd_p = NULL;
	pthread_t tid;

	listen_sockfd = __create_server_socket(port);
	if (listen_sockfd == -1) {
		ret = -1;
		goto out;
	}

	ret = listen(listen_sockfd, SOMAXCONN);
	if (ret)
		goto out;

	while (!g_exit) {
		sub_sockfd = accept(listen_sockfd, NULL, NULL);
		if (sub_sockfd == -1)
			fprintf(stderr, "Accept an error, [%s]", strerror(errno));
		else {
			sockfd_p = (int *)calloc(1, sizeof(int));
			*sockfd_p = sub_sockfd;

			ret = pthread_create(&tid, NULL, __work_thread, sockfd_p);
			if (ret)
				fprintf(stderr, "Create work thread fail, [%s]\n", strerror(errno));
			else
				pthread_detach(tid);
		}
	}

out:
	return;
}

int main(int argc, char *argv[])
{
	int opt;
	int own_port = 0;
	int ret = 0;

	signal(SIGINT, sig_handle);
	signal(SIGTERM, sig_handle);

	if (argc != 3) {
		print_usage();
		return -1;
	}

	while ((opt = getopt_long(argc, argv,
		":p:h", longopts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			own_port = strtol(optarg, NULL, 10);
			break;
		case 'h':
			print_usage();
			return 0;
		case ':':
			fprintf(stdout, "required argument : -%c\n", optopt);
			return -1;
		case '?':
			fprintf(stdout, "invalid param: -%c\n", optopt);
			return -1;
		}
	}

	/*创建服务器文件存储目录*/
	ret = __create_cache_dir(FILE_DIR);
	if (ret)
		return -1;

	/*运行服务器主线程*/
	server_main(own_port);

	return ret;
}
