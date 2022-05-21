# temp

# iptables
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 1.30.50.70
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 200.30.50.70

# dns
yum -y install bind
vi /etc/resolv.conf


# 1. User info

## create account
useradd ihduser: create user
useradd -u 1500 ihduser: create user uid is 1500 

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
* visudo: /etc/sudoers 

# file, directory auth
* chmod
read write e)xecute

User - Group - Others 
rwx-rwx-rwx

example) u,g,o,a
chmod u=rw [FILE]
chmod g+x [FILE]
chmod go-rwx [FILE]


# 2. Hardware

## add hardware ##
명령어:mount, umount

## partition settings ##
Fdisk -l
Fdisk /dev/sdb

## filesystem create ##
mkfs -t ext4

## disk quota ##
quota, edquota


edquota -t: change user's expired date (Grace period)
edquota -p [User1] [User2]
quota [user] : print users quota

# proc
/proc/cpuinfo : cpu
/proc/meminfo : memory
/proc/mdstat : raid
/proc/version : using kern ver

# 3. Compile

/lib/modules/[kern.ver]/modules.dep - about module dependency file.
uname: system info print
uname -r: kern info print

make mrproper: kern setting info clear
depmod: create modules.dep 
make modules: create selected module 
make modules_install: install created module

# 4. Package

rpm
rpm -qa [pack]: check system is pack installed
rpm -qf [pack/powerpath]: intsall file is in what package
rpm -ql pack: pack contained what file
rpm -qi pack: installed pack detail info 
rpm -qlp pack.rpm : what kinda files in pack 
rpm -qip pack.rpm : pack files detail info


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
minute hour date month day(0:sun)
* * * * * action 
*/10 * * * * * action : per 10 min

# Log
last: last login log
last -4 or last -n 4: last 4 log
lastb: last fail login logs(last's composite)
lastb -4 or lastb -n 4: last 4 fail log
lastlog: all system accounts last login log


# System info
kernel info
uname -a
hostnamectl
cat /proc/version


# iptables

change destination address
-t nat -A PREROUTING -i eth0 -j DNAT --to 200.100.50.10

change source address
-t nat -A POSTROUTING -o eth0 -j SNAT --to 200.100.50.10


https://itragdoll.tistory.com/5

# Linux DNS settings

vi /etc/resolv.conf

vi /etc/named.conf
options {
directory "/var/named"; : zone file path
datasize 1024M; :cache memory size 
forward (only|first): just forward | response when forward target is dead
forwarders { 123.10.22.3; }; : forward to ip
allow-transfer { 192.168.4/24; }; : copy zone to ip only range
allow-query { 192.168.12/24; 192.158.2.41; }; :allow query only
}

# 

# System log settings
/var/log - save almost all of system messages.
/var/log/dmesg - save linux boot messages. # dmesg
/var/log/secure - save remote connect logs.

/etc/rsyslog.conf

[format]
facility.priority; facility.priority; action

[type of facility]
*: all
auth: user auth (eg login)
authpriv: security, approve
cron: cron daemon
daemon: deamon (ftp, telnet)
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
alert: now adjust
emerge: emergency! all user.
none: do not save all of cases

[action]
file: msg to file
host: msg to host
user: msg to user screen
*: msg to all user logginned

[example]
authpriv.* /var/log/secure

#Log all of info except mail
*.info;mail.none /var/log/messages

#all of info only
*.=info /var/log/hess

#except info
mail.*;mail.!=info /var/log/maillog


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
iptables -I INPUT 2 -j LOG

# history
clean
history -c

# make cls command
$ sudo vi /usr/local/bin/cls

#!/bin/bash
clear
printf '\033[3J'

sudo chmod a+x /usr/local/bin/cls
  
# samba
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
