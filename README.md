Team Members:
- Kevin Hoganson    - kevin.hoganson42@gmail.com
- Alexander Slonim  - a.slonim412@gmail.com
- Zachary Brown     - zbrown4@students.towson.edu

Rootkit Functionality
1)	The rootkit will store itself as a kernel module and continue to function in the following ways.
2)	Keylog keyboard events and place them in a memory buffer of 10 MB in size; this buffer, when full, is either, a) forwarded to the control server, or b) placed in a clandestine file while the control server is inoperable. Next interaction from control server will cause the files to be forwarded to the control server (effectively a file transfer). 
3)	Conceal itself by first loading itself into memory, then removing itself from the mod_list kernel structure. 
4)	Listen in on incoming network traffic, particularly for TCP packets, using raw sockets.
  a.	A control server on the same subnet will be able to craft packets (using Scapy, or similar software) and broadcast them to workstations on the subnet. We craft the packets with magic “ACK” numbers that mean something to the rootkit.
  b.	The rootkit, upon receiving the TCP packet, will analyze it for the specific ACK number. If this ACK number matches, a reverse-TCP connection is established between the client and the control server.
  c.	This newly-established TCP connection will be maintained; it allows for interfacing between the rootkit and control server via a shell environment, allowing for the remote invocation of information-gathering commands: 
    i.	Listing running processes (ps),
    ii.	List all installed software (dpkg in this case),
    iii.	Retrieve user information (cat /etc/passwd, hashes from /etc/shadow, logins from /var/log/secure)
    iv.	Display open ports (netstat)
    v.	Display routing information (route), 
    vi.	Display network interface / IP (ifconfig),
    vii.	Linux operating system info (uname),
    viii.	CPU Info (cat /proc/cpuinfo),
    ix.	Listing of modules (lsmod),
    x.	Others.
  d.	Additionally, this shell environment can be used to escalate user privileges in kernel space by setting the following to 0 (or by using built-in exploits provided by the Metasploit framework):
    i.	uid, gid
    ii.	euid, egid
    iii.	suid, sgid
    iv.	fsuid, fsgid

