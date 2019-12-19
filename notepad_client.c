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
 * 向服务器注册
 * */
static int user_register(const int sockfd)
{
	char username[128] = {0};

	__get_username(username);
	/*TODO check name valid*/
}

/**
 * 登录服务器
 * */
static int user_login(const int sockfd)
{
	char username[128] = {0};

	__get_username(username);
	/*TODO check name valid*/
}

static int notepad_list(const int sockfd)
{
}

static int notepad_create(const int sockfd)
{
	char notepad[128] = {0};

	__get_notepad(notepad);
}

static int notepad_delete(const int sockfd)
{
	char notepad[128] = {0};

	__get_notepad(notepad);
}

static int notepad_edit(const int sockfd)
{
	char notepad[128] = {0};

	__get_notepad(notepad);
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
