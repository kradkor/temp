# temp
-- helper --
sudo find . -type f -print | xargs grep -i "s" /dev/null
alias cf='f(){ find . -type f -print | xargs grep -i "$1" /dev/null; unset -f f; }; f'
# iptables
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 1.30.50.70
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 200.30.50.70

# dns
yum -y install bind
vi /etc/resolv.conf


# 1. User info

## account attr
/etc/login.defs
/etc/skel
/etc/default/useradd

## user account add
useradd ihduser: create user
useradd -u 1500 ihduser: create user uid is 1500 
## user account modify - usermod
usermod -L baduser: Temporarily prevent user from logging in
usermod -e 2017-11-20 tempuser: can login until 2017-11-20
usermod -f 7: Set grace period 7days after password expired date
usermod -u 9999 tempuser: Change UID 9999

## ownership

chown - change ownership
chgrp - change group ownership

## access auth
chmod 3770



## 1.1 account login
### passwd
how to set password 
* passwd -S centos: print user info
* passwd -l centos: limit login
* passwd -u centos: unlimit login
* cat /etc/passwd: print user info
* cat /etc/shadow: print user password

### chage
user password expire
* chage -d 18523 centos: edit last change date to 2020-09-21(18523)
* chage -l centos: print user password info
* chage -E 2022-12-31 centos: edit password expire date to 2022-12-31

### sudoer
* visudo: Edit /etc/sudoers to grant root privileges.
* format: (user) (host)=(runUser[:runGroup]) [option:](command)

[example]
* user_name ALL=(ALL) ALL | grant sudo to user
* %group_name ALL=(ALL) ALL | grant sudo to group
* user ALL=(ALL) NOPASSWD: ALL | skip type password
* user_name ALL=command1,command2,.... | grant only some commands e.g.) user_name ALL=/usr/sbin/useradd, /usr/bin/passwd
* user_name localhost=(jason:admin) /usr/bin/vi | run vi command on localhost with using jason user in admin group



# 2. Hardware

## Add/Remove hardware ##
mount : mount device
umount : umount device

## Partition settings ##
fdisk -l: Print list of partition tables
fdisk -s /dev/sda: Print size of device

## Filesystem create ##
df -h: Print filesystems.
mkfs -t ext4: Make filesystem ext4
=mkfs.ext4
=mke2fs -t ext4
* /etc/mke2fs.conf : available filesystem types
* /etc/fstab: Add your device on this file if you want to keep using settings after reboot.
6 fields exist.
1: Device Name | Device Name or path
2: Mount point | Directory path
3: Filesystem Type | nfs, NTFS, ext3, ext4, 
4: Mount option | auto, rw, nouser(can mount root only), exec, Set-UID, quota(can set quota), default
5: Dump Option | 0: cannot backup, 1: can backup
6: Integrity Check Option | 0: Do not, 1: first priority check, 2: second priority check)

## Disk quota ##
quota, edquota


edquota -t: change user's expired date (Grace period)
edquota -p [User1] [User2]
quota [user] : print users quota


# File, directory auth
* chmod
read write e)xecute

User - Group - Others 
rwx-rwx-rwx

example) u,g,o,a
chmod u=rw [FILE]
chmod g+x [FILE]
chmod go-rwx [FILE]

# Process Information
/proc/cpuinfo : Cpu
/proc/meminfo : Memory - physical, swap memory infos
/proc/mdstat : Raid
/proc/version : using kern ver
/proc/uptime: System uptime
/proc/cmdline: About running kernel options on boot time.
/proc/loadavg: Average load rate per 1, 5, 15 minutes 
/proc/{PID}: Detail information of running process. 
/proc/device: Available devices list
/proc/filesystems: Available filesystems list
/proc/modules: Loaded and running modules. (lsmod same)
/proc/swaps: Swap Filesystem info
/proc/interrupts: system interrupt configs
/proc/net/: ARP Table, TCP, UDP etc... system network info

## Print

lp -n 2 -d lp joon.txt: Print 2 sheet. Select printer name 'lp'. Print file 'joon.txt'
lpr -# 2 -P lp joon.txt: same

lp -t: Set title
lp -n 2: Set size
lp -d printer_name: Set printer

lpr -# 2: Set size
lpr -P printer_name: Set printer
lpq: Print job queue.
lpstat: Print status of printer.


# 3. Compile

/lib/modules/[kern.ver]/modules.dep - about module dependency file.
uname: system info print
uname -r: kern info print

depmod: Check dependencies and create 'modules.dep' file. /lib/modules/[kern.ver(uname -r)]/modules.dep
make clean: Make before compile. remove object files.
make mrproper: clean + remove kernel setting files
make modules: create selected module 
make modules_install: install created module

# 4. Package

rpm
* Install, Update options
-i: install new package
-h: Print install progress using '#'
-U: upgrade package. if doesn't exist then install.
--force: install package with ignoring exist package
-e: Remove package
--nodeps: Not verifying package when update, install, remove
--test: find problems without real running


* Query options
rpm -q: query option must be started with it.
rpm -i: package info, name, version, desc ..
rpm -l: package list 
rpm -qa [pack]: check system is pack installed
rpm -qf [pack/powerpath]: intsall file is in what package
rpm -ql pack: pack contained what file
rpm -qi pack: installed pack detail info 
rpm -qlp pack.rpm : what kinda files in pack 
rpm -qip pack.rpm : pack files detail info
* Other options
rpm -v: Print detail info.
rpm -V [packname]: verify package with RPM DB after installation. (integrity)
rpm --quiet: Print only error message.
rpm --rebuilddb: update RPM DB


# Process priority
low value run first
ps -el, top, mpstat: watch nice

nice -n [n] [proc name]: gen new process, add nice to before value
renice [n] [PID]: change aleady gened process's priority to n


# Scheduling
## crontab
crontab -e: edit crontab
crontab -l: print crontab list
crontab -eu centos: edit user crontab
=crontab -e -u
minute hour date month day(0:sunday)
* * * * * action 
*/10 * * * * * action : per 10 min
[example]
10 4 1 1-12/2 * /home/ihduser/work.sh

# System info
kernel info
uname -a
hostnamectl
cat /proc/version
# Kernel Parameters
sysctl -a: Print Kernel Parameters which is applied in system.
sysctl -w net.ipv4.icmp_echo_ignore_all=1 : Change kernel parameter to be ignore from ping request.

# iptables

change destination address
-t nat -A PREROUTING -i eth0 -j DNAT --to 200.100.50.10

change source address
-t nat -A POSTROUTING -o eth0 -j SNAT --to 200.100.50.10


https://itragdoll.tistory.com/5

# Linux DNS settings
## package
bind - DNS server program's name. it has 'named' Daemon
## config
* /etc/hosts - localhost only DNS config set.
<!-- vi /etc/resolv.conf -->
* /etc/rc.d/init.d/named - It makes DNS start.
* /var/named - Root domain server info, Zone file etc... storage.
* /etc/named.conf - Zone file, Reverse Zone file, etc. DNS important environment setting file. Sentences always be end with semicolon.
* Zone file - Domain name, IP address, resource mapping. It consists Resource Record.
* Reverse Zone file - Search domain info of IP adddress.

* Options sentence config items
options {
  listen-on port 53 { 127.0.0.1; }; :
  listen-on-v6 port 53 { ::1; };
  directory "/var/named"; : zone file path. REQUIRED
  dump-file "/var/named/data/cache_dump.db"; : when update info save into this file.
  statistics-file "var/named/data/named_stats.txt"; : save statistic info.
  datasize 1024M; :cache memory size 
  forward (only|first): just forward and donot response if target dead | response when forward target is dead. 
  forwarders { 123.10.22.3; }; : set forward perform servers. forward to ip. if multiple server seperate with semicolon.
  allow-transfer { 192.168.4/24; }; : Only hosts in range can copy zonefile.
  allow-query { 192.168.12/24; 192.158.2.41; }; : Only hosts in range can query.
  recursion yes; : Sub domain search yes/no
};

* Logging sentence config items
logging {
  channel default_debug {
    file "data/named.run";
    severity dynbamic;
  };
};

* Acl sentence config items (Access Control List)

acl ihd { 192.168.2.24; 192.168.4/24; }; : Set alias as 'ihd'. It can be used as 'Hosts' in allow-query, allow-transfer. So it must be defined before options sentence.

* Zone sentence config items
[!format!]
zone [DomainName] IN {
  type [master | save | hint];
  file [Zone filename];
};

* hint - Root domain
* master - Set first name server
* slave - Set second name server

[!example!]
zone "." IN {
  type hint;
  file "named.ca";
}  

zone "linux.or.kr" IN {
  type master;
  file "linux.zone";
}


# 

# 99. Log
## System log settings
/var/log - save almost all of system messages.
/var/log/dmesg - save linux boot messages. # dmesg
/var/log/secure - save remote connect logs.

/etc/rsyslog.conf

[format]
facility.priority; facility.priority; action

[type of facility]
*: all
auth: user auth (e.g. login)
authpriv: security, approve (e.g. ssh)
cron: cron daemon
daemon: daemon (ftp, httpd, telnet)
kern: kernel
user: created message from user
local0~7: system boot msg

[priority]
*: all of cases
debug: when debug
info: stats, baseinfo
notice: warning but not error
warning: warning!!!
err: error!!
crit: not hurry but cause some problems
alert: Need to take action now. 
emerge: emergency! all user.
none: do not save all of cases

[action]
file: msg to file
host: msg to host
user: msg to user screen
*: Send msg to screen of all users loginned

[example]
authpriv.* /var/log/secure

#Log all of info except mail
*.info;mail.none /var/log/messages

#all of info only
*.=info /var/log/hess

#except info
mail.*;mail.!=info /var/log/maillog


[example - send to remote server]
#set params in /etc/rsyslog.conf
$ModLoad imtcp
$InputTCPServerRun 514(port)
#send all logs to host using UDP
*.* @192.168.0.11

#send all logs to host using TCP
*.* @@192.168.0.11

## User Login Logs
last: Print last login log. This command refer /var/log/wtmp file
last -4 or last -n 4: last 4 log

lastb: Print last fail login logs(last's composite) e.g. bad login attempts. This command refer /var/log/btmp file
lastb -4 or lastb -n 4: last 4 fail log

lastlog: Print all system user's last login log. This command refer /var/log/lastlog file

logrotate: run script in cron. configfile is /etc/logrotate.conf.

[example]
* last reboot: Print system reboot log
* 
* lastlog: Print all users last login log
* lastlog -u tempuser: Print "tempuser's" last login log
* lastlog -t 3: Print login users who logged in recent 3days.

* vi /etc/logrotate
* /var/lib/logrotate.status - History of logrotate

/var/log/wtmp {
weekly # daily, weekly, monthly, yearly available
create 0600 root utmp 
rotate 4 # Performing rotate maximum 4 times. it will make logfile, logfile.1, logfile.2, logfile.3, logfile.4
}
[others]
compress - Compress logfiles
include /etc/logrotate.d - Apply path config files.
minsize - if log file's size over 1M. perform rotate
missingok - if log file doesn't exist, do not emit error and go next.





# 9. Network
## DNS  ##
pack: bind

conf_files: /etc/resolv.conf, /etc/hosts, /etc/host.conf, 
dns: /etc/named.conf

## Samba ##
/etc/samba/smb.conf


## Proxy서버 ##

pack: yum -y install squid
conf: /etc/squid/squid.conf

<example> - /etc/squid/squid.conf 
http_port [portnum] : set proxy port
acl [alias] src [iprange] : set alias to IP range
http_access allow [alias] : allow alias range
http_access deny [alias] : deny alias range

## iptables ##
iptables -L: print rules
iptables -A: add last of rules
iptables -I [chain][line num]: add rule
iptables -D [chain][line num]: remove rule
iptables -R [chain][line num]: edit rule

exam) add new rule, 192.16t8.22.12 tcp drop
iptables -A -s 192.168.22.12 -p TCP -j DROP

exam) remove Input chain 5th rule 
iptables -D INPUT 5

exam) add rule input chain 2nd rule to log
iptables -I INPUT 2 -j 
  
## mail ##
/etc/aliases
/etc/mail/virtusertable

alias
vi /etc/aliases
webmaster: user, user2
admin:include:/path
  
newaliases
  
virtuset
 
 vi /etc/mail/virtusertable
 admin@a.com  root
 ad@a.com      root
 
test@b.com root
test@c.com root
  
makemap hash /etc/mail/virtusertable < /etc/mail/virtusertable
                                                              
                                                              
                                                              
-----------------------------------------------
# Remote sync
rsync -avz root@192.168.1.22:/home /backup        

## options
* -v : Print detail info
* -r : Copy sub directories recursively
* -a : running archive mode
* -z : Support data compression(ZIP)
* -h : human readable
* -g : Keep group info

## example - write command
* !condition!
* localdir = /data
* remote ip address = 192.168.0.110, directory = /backup
* print backup progress vervose
* keep symbolic links, permission, ownership etc
[answer]
rsync -av /data 192.168.0.110:/backup

-----------------------------------------------

# NFS Server(Network File System)

## config
/etc/exports : NFS config file

## authorities
* no_root_squash: allow root access
* root_squash: not allow root access. and then map to nobody(nfsnobody)
* all_squash: All clients map to nobody
* anonuid: Grant specific user's authority

## format
* share_directory accessible_client_range(authorities)

## example - write config content
* !condition!
* /data/presales - Access, Read, Write available, in *.example.com domain range
* root user on NFS client map as root user on NFS server. and grant Access, Read, Write 

[answer]
/data/presales *.example.com(rw,no_root_squash)

-----------------------------------------------

# Mail Server
sendmail - send mail to the other mail server using SMTP protocol.

#start service
service sendmail start 
#check
netstat -anp | grep LISETN -w | grep :25

## popular command
sendmail -bp : mail queue status
sendmail -bi : update aliases info
sendmail -oQ : specific Que status
e.g.) sendmail -bp -oQ/var/spool/clientmqueue

## config 
all config files are under the /etc/mail directory.
* /etc/mail/sendmail.cf - sendmail's main config file
* Cw - set mail receive host(e.g. domain name) default: Cwlocalhost
* Fw - set mail receive host multiple(multiple Cw) default: Fw/etc/mail/local-host-names
* Ft - set Trusted user who can change mail address. 
* default: Ft /etc/mail/trusted-users
* Troot
* Tdaemon
* Tuucp
* Dj -  force set sending domain name. when mail send.
* Dn - set sendmail's returnmail's user name default: DnMAILER-DAEMON
* FR-o - Accept Relay domain. default: FR-o /etc/mail/relay-domains


* /etc/mail/sendmail.mc - sendmail's macro config file. Using m4 utility, create sendmail.cf. e.g.) m4 sendmail.mc > sendmail.cf 

* /etc/aliases - Share mails from Mail's alias or Specific Mail's received mail to the specific user
* for applying this file, type this command - sendmail -bi OR newaliases
* staff: kim, park, choi - if send mail to 'staff', 3 people can receive same mail.

* /etc/mail/local-host-names - Config sendmail's domain, host. Restart required to apply.

* /etc/mail/access - Control accessible host, domain. If you want to prevent Spam mails, use this file.
* reference - cat /etc/mail/access
* e.g.) From:spam.com DISCARD - Reject mail from domain spam.com and not reply message

* /etc/mail/virtusertable - Send Mail which is sent to virtual user to specifit user.
* for applying this file, type this command - makemap hash /etc/mail/virtusertable < /etc/mail/virtusertable
* webmaster@linux.com kim
* webmaster@windows.com park
-----------------------------------------------

# Xinet
Super Daemon - manage other daemons

## config
* /etc/xinetd.conf - default config file. man xinetd.conf
* /etc/xinetd.d/{daemon} - each daemon's config file

## primary config options
* instances - set maximum servers which run simultaneous
* log_type - set logging method. [SYSLOG, FILE] 
* log_type=SYSLOG syslog_facility [syslog_level]
* log_type=FILE file_name [limit]
* log_on_success - Log when server start, end. PID, HOST, USERID, EXIT, DURATION etc..
* log_on_failure - Log when server cannot be started or access
* cps - maxium request per sec and then set connection time when exceed limit time
* cps=25 30 - request per sec over 25 then limit 30sec connection
* only_from - set available host
* per_source - set maximum connection limit from same ip. UNLIMITED available
* includedir /etc/xinted.d


## example
* !condition!
* Log xinetd's log in /var/log/xinetd.log

[answer]
vi /etc/xinetd.conf
log_type=FILE /var/log/xinetd.log

-----------------------------------------------

# DHCP Server(Dynamic Host Configuration Protocol)

## config
* /etc/dhcp/dhcpd.conf - default config files. each config sentence must contain semicolon.

## common
* 192.168.0.0 
  
## options
range - allocating ip range to client
range dyamic-bootp - support dhcp client and bootp client
option domain-name - set domain name
option domain-name-servers - set domain name server.
option routers - set gateway address
option broadcast-address - set broadcasting address
default-lease-time - set lending request expire time per sec
max-lease-time - set maximum ip using time of client per sec
option subnet-mask - set subnet mask
fixed-address - allocate fixed IP address to system which has specific mac address.

## example
* !condition!
* When MAC Address is '08:00:07:26:c0:a5' then always allocate 192.168.1.22 
* Host name is ihd_pc
host ihd_pc {
  hardware ethernet 08:00:07:26:c0:a5;
  fixed-address 192.168.1.22;
}


-----------------------------------------------

# IP Tables
Linux's firewall setting tool. 
Rules : 1. 'Allow all and then restric specific packets' / 2. 'Reject All and then allow specific packets.
## format
iptables [-t table_name] [action] [chain_name] [match rule] [-j target]

## Chain options
-N : --new-chain. create new rule chain
-X : --delete-chain. delete empty chains. except INPUT, OUTPUT, FORWARD
-L : --list. print chains
-F : Delete selected chain's all rule
-C : Test packet
-P : set default policy of chain
-Z : set all rules of chains byte count zero

## Chain internal option
-A : --append. add new policy at last.
-I [chain] [linenumber]: --insert. add at seleted line.
-D [chain] [linenumber]: --delete.
-R [chain] [linenumber]: --replace. edit

## Match option
-s: --source. set departure address
-d: --destionation. set destionation address
-p: set protocol
-i: select input network interface
-o: select output network interface
--sport: set source port. range allowed
--dport: set target port. range allowed
--tcp-flags: select TCP flag. SYN ,ACK etc..

## Target option
ACCEPT: allow packet.
REJECT: reject packet and send response message.
DROP: just reject packet.
LOG: Log packets in syslog. file' s path is /var/log/message
RETURN: keep processing packet. in chain.

## Type of tables
filter - Base table of 'iptable'. it takes 'Packet Filtering' function.
[chains]
* INPUT - Filter coming packet which is destination is host.
* OUTPUT - Filter going out packet. departure is host
* FORWARD - Filter passing host. same as destination is not host packet.
  
[example]
* iptables -A INPUT -s 192.168.10.7 -d localhost -j DROP : in INPUT chain. Reject source address is 192.168.10.7 and destination is localhost.
* iptables -A INPUT -s 192.168.10.7 -p icmp -j REJECT: in INPUT chain. Reject source address is 192.168.10.7 and ICMP protocol. and then send response.
* iptables -A INPUT -s 192.168.10.0/24 ! -p icmp -j ACCEPT : in INPUT chain. Accept packet from 192.168.10.0/24 range if not ICMP protocol
* iptables -A OUTPUT -p tcp
  
nat - Network Address Translation. It manages and converts IP address and Port.
[chains]
* PREROUTING - Change packet's destination address
* POSTROUTING - Change packet's departure address. It's called as masquerade
* OUTPUT - Change packet's destination address which is going out from host.
* INPUT - Change packet's address which is comming into host from outside.

SNAT - Share one public IP with multiple hosts. Using internet with One Public IP. It changes source address Private to Public
[example]
* iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 222.235.10.7 : 
-t nat = nat, 
-A POSTROUTING = It changes departure(source) address using POSTROUTING action, 
-o eth0 = outing packet only through eth0, 
-j SNAT = target is SNAT,
--to 222.235.10.7 = Change source address as 222.235.10.7

* iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 222.235.10.7-222.234.10.25 : It allows range too
* iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to MASQUERADE : MASQUERADE is dynamic adderess. It can be changed.
  
DNAT - Multiple server connect using one public IP. Servers can be receive request using one public IP. It distinguishes request with --dport. It changes destination address Public to Private(using port).
[example]
* iptables -t nat -A PREROUTING -p tcp -d 222.235.10.7 --dport 80 -j DNAT --to 192.168.10.7:80
-t nat = using nat table,
-p tcp = this rule only target tcp protocol,
-d 222.235.10.7 = check if destination address is 222.235.10.7,
--dport 80 = check if destination port is 80,
-j DNAT = Set as DNAT,
--to 192.168.10.7:80 = change destination address as 192.168.10.7:80 from 222.235.10.7:80

* iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080

mangle - For improving performance like TOS(Type of Service). It applies special rules which manipulate packet data.
raw - Connection tracking



-----------------------------------------------

# TCP Wrapper
daemon is tcpd.
man hosts.allow
*
 /etc/hosts.allow - Write allow hosts
* /etc/hosts.deny - Write deny hosts
  

## config
applying order : allow -> deny .
one line. one rule. if over two line needed use \.
[format]
[daemon_list]:[client_list]:[shell_command]
daemon_list : service run daemon name. define multiple daemon using comma.
ALL

client_list: access control target host. define multiple client using comma. [user@host] format allowed

shell_command:
%a: client ip
%A: server ip
%c: 
%d: service name
%h: client name

[example]
[hosts.allow]
ALL : 192.168.9.0/255.255.255.0 : Allow all 192.168.9.0 range clients.

-----------------------------------------------

# Squid Server
Proxy server
## config
* /etc/squid/squid.conf

* cache_dir: 
cache_dir ufs [path] [cache_size] [first dir count] [second dir count]
* http_port [port_num]: set using port
http_port 3128
* acl [alias] src [ip_range]: set first acl and then define access control
* acl [alias] dst [ip_range]
* acl [alias] port [port_num]
* acl [alias] srcdomain [domain_name]
* acl [alias] srcdomain [domain_name]
acl local src 192.168.10.0/255.255.255.0
http_access allow local
http_access dney all

acl Safe_ports port 80
acl Safe_ports port 21
http_access deny !Safe_ports

* cache_mem [size]: set cache size
cache_mem 2048 MB
* cache_log [log_path]: set logfile

-----------------------------------------------

# Samba
* smbd: using TCP, 445
* nmbd: using UDP 137, 139

## start samba
* service smb start : start SMB. /etc/rc.d/init.d/smb start => OK same
* service nmb start : start NMB. /etc/rc.d/init.d/nmb start => OK same

## chkconfig
* chkconfig smb on
* chkconfig nmb on
  
## config
/etc/samba/smb.conf

## add user
make linux account who uses samba
* adduser smbuser
* passwd smbuser

## mapping user
* vi /etc/samba/smbusers
root = administrator admin: root is mapped with administrator and admin
nobody = guest pcguest smbguest: noboy is mapped with gust, pcguest, smb-guest

## set samba account and password
smbpasswd
-a : add smb user and set password. user must be added in linux
-x : remove smb user
-d : unactivate smb user
-e : activate smb user
-n : remove password. can login without password. (need to foloowing option in smb.conf => null passwords = yes)
[example]
smbpasswd -a smbuser
## others
pbedit: smb user list and print detail infos
-L : list of smb users
-v : detail users
-u : select user
-a : add smb user and set password
-r : modify smb user
-x : delete smb user

smbstatus: Print current connection
testparm: Print Smb's config info
nmblookup: lookup IPaddress with NETBIOS
smbcontrol: message to smb daemon

[example]
pbedit -L
pbedit -v -u smbuser

## smbclient
connect to smb server!
[format]
smbclient [option] [host_name] 
[options]
-L : Print smb share directory
-M : send message with Ctrl+d
-U [user_name] : select username
-p [TCP_port] : select server tcp port

[example]
* smbclient -L 172.30.1.12 -U smbuser
* smbclient //172.30.1.12/smbuser/ -U smbuser
* smbclient //172.30.1.12/smbuser/ -U smbuser%pass1234 : set with password(pass1234)

## mount smb dir
look order
* mkdir /smbuser
* mount -t cifs //172.30.1.12/smbuser /smbuser -o user=smbuser,password=pass1234
* df
* ls -l /smbuser/


-----------------------------------------------
# history
clean
history -c

# make cls command
$ sudo vi /usr/local/bin/cls

#!/bin/bash
clear
printf '\033[3J'

sudo chmod a+x /usr/local/bin/cls
  

  /etc/samba/smb.conf
  
  [www]
  comment=description
  path=share file path
  valid users=user1 user2
  write list=user1 user2
  
# apache webserver
  DocumentRoot "path"
  UserDir www
  DirectoryIndex index.htm index.html
  Listen 8080
  ServerName www.jjj.com:8080

