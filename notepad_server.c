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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/socket.h>
#include <poll.h>
#include <pthread.h>

#include "utils.h"

#define FILE_DIR "./notepad"

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
	fprintf(stdout, "./notepad_server <server_port>\n");
	fprintf(stdout, "example:\n");
	fprintf(stdout, "\t./notepad_client 1037\nn");
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
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP);
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

static int __send_response(const int sockfd, char *msg)
{
	int ret = 0;
	int msg_len = strlen(msg);

	ret = send(sockfd, msg, msg_len, 0);
	if (ret != msg_len) {
		fprintf(stdout, "Send message fail, [%s]\n", strerror(errno));
		ret = -1;
	}

	return ret;
}

static void do_register(const int sockfd, const char *name)
{
	char path[128] = {0};
	int ret = 0;

	snprintf(path, sizeof(path) - 1, "%s/%s", FILE_DIR, name);
	if (!access(path, F_OK))
		__send_response(sockfd, "The username you entered is already in use");

	ret = __create_cache_dir(path);
	if (ret)
		__send_response(sockfd, "Create account fail");
	else
		__send_response(sockfd, "success");
}

static void do_login(const int sockfd, const char *name, char *username)
{
	char path[128] = {0};
	int ret = 0;

	snprintf(path, sizeof(path) - 1, "%s/%s", FILE_DIR, name);
	if (access(path, F_OK))
		__send_response(sockfd, "The username you entered is not exist, please register one");
	else {
		strncpy(username, name, sizeof(username) - 1);
		__send_response(sockfd, "success");
	}
}

static void do_list(const int sockfd, const char *username)
{
	char *buf = NULL;

	if (!strncmp("null", username, strlen(username)))
		__send_response(sockfd, "Please login first\n");

	ret = __get_file_list(username, &buf);
	if (ret)
		__send_response(sockfd, "");

	__send_response(sockfd, buf);

	free(buf);
}

static void do_create(const int sockfd, const char *name, const char *username)
{
	if (!strncmp("null", username, strlen(username)))
		__send_response(sockfd, "Please login first\n");

}

static void do_delete(const int sockfd, const char *name, const char *username)
{
	if (!strncmp("null", username, strlen(username)))
		__send_response(sockfd, "Please login first\n");

}

static void do_edit(const int sockfd, const char *name, const char *username)
{
	if (!strncmp("null", username, strlen(username)))
		__send_response(sockfd, "Please login first\n");

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

	if (strncmp("register", key, strlen(key)))
		do_register(sockfd, value);
	else if (strncmp("login", key, strlen(key)))
		do_login(sockfd, value, username);
	else if (strncmp("list", key, strlen(key)))
		do_list(sockfd, username);
	else if (strncmp("create", key, strlen(key)))
		do_create(sockfd, value, username);
	else if (strncmp("delete", key, strlen(key)))
		do_delete(sockfd, value, username);
	else if (strncmp("edit", key, strlen(key)))
		do_edit(sockfd, value,username);
	else if (strncmp("quit", key, strlen(key)))
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

		ret = do_job(sockfd, buf, recv_len, username);
		/*接收到客户端的quit信息后，跳出循环*/
		if (ret)
			break;
	}

	close(sockfd);
}

static void server_main(const int port)
{
	int ret = 0;
	int listen_sockfd = -1;
	int sub_sockfd = -1;
	int *sockfd_p = NULL;
	pthread_t tid;

	listen_sockfd = __create_server_socket(port);
	if (listen_sockfd) {
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
	int sockfd = -1;
	int own_port = 0;
	int ret = 0;

	signal(SIGINT, sig_handle);
	signal(SIGTERM, sig_handle);

	if (argc != 2) {
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
