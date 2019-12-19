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

static int g_exit;

struct option longopts[] = {
	{"ipaddr", required_argument, NULL, 'i'},
	{"port", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};


enum {
	REGISTER = 1,
	LOGIN,
};

enum {
	LIST = 1,
	CREATE,
	DELETE,
	EDIT,
	UPLOAD,
};

static void sig_handle(int sig)
{
	g_exit = 1;
}

static void print_usage(void)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, "./notepad_client <server_ip> <server_port>\n");
	fprintf(stdout, "example:\n");
	fprintf(stdout, "\t./notepad_client 192.168.1.101 1037\nn");
}

/**
 * 清除屏幕内容
 * */
static void __clear_window(void)
{
	fprintf(stdout, "\033c");
}

static void __get_username(char *username)
{
	char console_input[128] = {0};

	fprintf(stdout, "Please input your user name:");
	fgets(console_input, 127, stdin);
	fprintf(stdout, "\n");

	strncpy(username, console_input, 128);
}

static void __get_notepad(char *notepad)
{
	char console_input[128] = {0};

	fprintf(stdout, "Please input your notepad name:");
	fgets(console_input, 127, stdin);
	fprintf(stdout, "\n");

	strncpy(notepad, console_input, 128);
}

/**
 * 发送并接受消息
 * */
static int __send_and_recv(const int sockfd,
				const char *send_buf,
				char *recv_buf,
				const int send_len, const int recv_size)
{
	int ret = 0;

	ret = send(sockfd, send_buf, send_len, 0);
	if (ret != send_len) {
		fprintf(stdout, "Send message fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

	ret = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
	if (ret == -1) {
		fprintf(stdout, "Recv message fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

out:
	return ret;
}

/**
 * 向服务器注册
 * */
static int user_register(const int sockfd)
{
	char username[128] = {0};
	char msg[256] = {0};
	char buf[256] = {0};
	int msg_len = 0;
	int ret = 0;

	__get_username(username);

	snprintf(msg, strlen(username), "register:%s", username);
	msg_len = strlen(msg);

	ret = __send_and_recv(sockfd, msg, buf, msg_len, sizeof(buf));
	if (ret)
		goto out;

	if (strncmp(buf, "success", strlen(buf))) {
		ret = -1;
		fprintf(stdout, "Register:%s\n", buf);
	}

out:
	if (ret)
		fprintf(stdout, "Register fail\n");

	return ret;
}

/**
 * 登录服务器
 * */
static int user_login(const int sockfd)
{
	char username[128] = {0};
	char msg[256] = {0};
	char buf[256] = {0};
	int msg_len = 0;
	int ret = 0;

	__get_username(username);

	snprintf(msg, strlen(username), "login:%s", username);
	msg_len = strlen(msg);

	ret = __send_and_recv(sockfd, msg, buf, msg_len, sizeof(buf));
	if (ret)
		goto out;

	if (strncmp(buf, "success", strlen(buf))) {
		ret = -1;
		fprintf(stdout, "Login:%s\n", buf);
	}

out:
	if (ret)
		fprintf(stdout, "Login fail\n");

	return ret;
}

/**
 * 列出当前用户的所有记事本
 * */
static int notepad_list(const int sockfd)
{
	char msg[256] = {0};
	char buf[4096] = {0};
	int msg_len = 0;
	int ret = 0;

	sprintf(msg, "list:all");
	msg_len = strlen(msg);

	ret = send(sockfd, msg, msg_len, 0);
	if (ret != msg_len) {
		fprintf(stdout, "Send message fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

	do {
		ret = recv(sockfd, buf, sizeof(buf) - 1, 0);
		if (ret == -1) {
			fprintf(stdout, "Recv message fail, [%s]\n", strerror(errno));
			ret = -1;
			goto out;
		}

		fprintf(stdout, "%s", buf);
		fflush(stdout);
	} while (ret == (sizeof(buf) - 1));

out:
	if (ret)
		fprintf(stdout, "List notepads fail\n");

	return ret;
}

/**
 * 创建，编辑并上传记事本
 * */
static int notepad_create(const int sockfd)
{
	char notepad[128] = {0};
	char msg[256] = {0};
	char buf[256] = {0};
	int msg_len = 0;
	int ret = 0;

	__get_notepad(notepad);

	snprintf(msg, strlen(notepad), "create:%s", notepad);
	msg_len = strlen(msg);

	/*TODO send filename, edit file, upload file*/

out:
	if (ret)
		fprintf(stdout, "Create notepad [%s] fail\n", notepad);

	return ret;
}

static int notepad_delete(const int sockfd)
{
	char notepad[128] = {0};
	char msg[256] = {0};
	char buf[256] = {0};
	int msg_len = 0;
	int ret = 0;

	__get_notepad(notepad);

	snprintf(msg, strlen(notepad), "delete:%s", notepad);
	msg_len = strlen(msg);

	ret = __send_and_recv(sockfd, msg, buf, msg_len, sizeof(buf));
	if (ret)
		goto out;

	if (strncmp(buf, "success", strlen(buf)))
		ret = -1;

out:
	if (ret)
		fprintf(stdout, "Delete notepad [%s] fail\n", notepad);

	return ret;
}

/*TODO*/
static int notepad_edit(const int sockfd)
{
	char notepad[128] = {0};
	char msg[256] = {0};
	char buf[256] = {0};
	int msg_len = 0;
	int ret = 0;

	__get_notepad(notepad);

	snprintf(msg, strlen(notepad), "edit:%s", notepad);
	msg_len = strlen(msg);

	ret = __send_and_recv(sockfd, msg, buf, msg_len, sizeof(buf));
	if (ret)
		goto out;

	if (strncmp(buf, "success", strlen(buf)))
		ret = -1;

out:
	if (ret)
		fprintf(stdout, "Edit notepad [%s] fail\n", notepad);

	return ret;
}

static int notepad_upload(const int sockfd)
{
	char notepad[128] = {0};

	__get_notepad(notepad);
}

/**
 * 编辑记事本
 * */
static void edit_file(const char *file_name)
{
	char vim_cmd[256] = {0};

	sprintf(vim_cmd, "vi %s", file_name);
	system(vim_cmd);
}

/**
 * 连接服务器
 * */
static int server_connect(const char *ipaddr, const int port)
{
	struct sockaddr_in peer_addr;
	int optval;
	int sockfd = -1;
	int ret = 0;

	bzero(&peer_addr, sizeof(peer_addr));

	/*设置服务器信息*/
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr.s_addr = inet_addr(ipaddr);
	peer_addr.sin_port = htons(port);

	/*创建IPV4 UDP套接字*/
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd ==-1) {
		fprintf(stdout, "Create socket fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

	optval = 1;
	/*设置套接字选项SO_REUSERADDR,这样短时间内client可以迅速连接server*/
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			&optval, sizeof(optval));
	if (ret) {
		fprintf(stdout, "warning reuse socket address fail, [%s]\n",
							strerror(errno));
		ret = -1;
		goto out;
	}

	/*连接服务器*/
	ret = connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
	if (ret) {
		fprintf(stdout, "connect to peer fail, [%s]\n", strerror(errno));
		ret = -1;
		goto out;
	}

out:
	return ret ? -1 : sockfd;
}

/**
 * 断开同服务器的连接
 * */
static void server_teardown(const int sockfd)
{
	char message[6] = "quit";
	int ret = 0;

	send(sockfd, message ,sizeof(message), 0);
	close(sockfd);
}

int main(int argc, char *argv[])
{
	int opt;
	int sockfd = -1;
	char peer_ip[16] = {0};
	int peer_port = 0;
	char file_name[128] = {0};
	char console_input[128] = {0};
	int cmd_index = -1;
	int success = 0;
	int ret = 0;

	signal(SIGINT, sig_handle);
	signal(SIGTERM, sig_handle);

	if (argc != 3) {
		print_usage();
		return 0;
	}

	while ((opt = getopt_long(argc, argv,
		":i:p:h", longopts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			strncpy(peer_ip, optarg, 16);
			break;
		case 'p':
			peer_port = strtol(optarg, NULL, 10);
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

	sockfd = server_connect(peer_ip, peer_port);
	if (ret) {
		fprintf(stderr, "Connect to notepad server fail\n");
		return -1;
	}

	while (!g_exit) {
		__clear_window();
		fprintf(stdout, "\n======Register\\Login=======\n");
		fprintf(stdout, "1. Register:\n");
		fprintf(stdout, "2. Login:\n");
		fprintf(stdout, "Type a number or 'q' to exit\n");

		fgets(console_input, 127, stdin);
		cmd_index = atoi(console_input);

		__clear_window();

		switch (cmd_index) {
			case REGISTER:
				user_register(sockfd);
				break;
			case LOGIN:
				ret = user_login(sockfd);
				success = ret ? 0 : 1;
				break;
			case 'q':
				goto exit;
			default:
				fprintf(stdout, "Unknown input message\n");
				break;
		}

		if (success) {
			success = 0;
			break;
		}

		usleep(100000);
	}


	while (!g_exit) {
		__clear_window();
		fprintf(stdout, "======Enjoy you notepad=======\n");
		fprintf(stdout, "1. List all your notepads\n");
		fprintf(stdout, "2. Create a new notepad\n");
		fprintf(stdout, "3. Delete a notepad\n");
		fprintf(stdout, "4. Edit a notepad\n");
		fprintf(stdout, "5. Upload a notepad\n");
		fprintf(stdout, "Type a number or 'q' to exit\n");

		fgets(console_input, 127, stdin);
		cmd_index = atoi(console_input);

		__clear_window();

		switch (cmd_index) {
			case LIST:
				notepad_list(sockfd);
				break;
			case CREATE:
				notepad_create(sockfd);
				break;
			case DELETE:
				notepad_delete(sockfd);
				break;
			case EDIT:
				notepad_edit(sockfd);
				break;
			case UPLOAD:
				notepad_upload(sockfd);
				break;
			case 'q':
				goto exit;
			default:
				fprintf(stdout, "Unknown input message\n");
				break;
		}

		usleep(100000);
	}

exit:
	server_teardown(sockfd);
	/*TODO*/

	return ret;
}
