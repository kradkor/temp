# temp

# iptables
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 1.30.50.70
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 200.30.50.70

# dns
yum -y install bind
vi /etc/resolv.conf


# 1. User info

## create account
useradd ihduser: 계정 생성
useradd -u 1500 ihduser: uid가 1500인 계정 생성

## 1.1 account login
### passwd
사용자 패스워드 설정
* passwd -S centos: 사용자 정보 확인
* passwd -l centos: 로그인 일시 제한
* passwd -u centos: 로그인 제한 해제    
* cat /etc/passwd: 사용자 정보 확인
* cat /etc/shadow: 사용자 비밀번호 확인

### chage
사용자 패스워드 만료 정보 변경과 관련된 명령어
* chage -d 18523 centos: 마지막 변경일을 2020-09-21(18523)로 수정
* chage -l centos: 사용자의 패스워드 관련정보 출력
* chage -E 2022-12-31 centos: 사용자의 패스워드 만료일을 2022-12-31로 수정

### sudoer
* visudo: /etc/sudoers 파일을 편집

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
rpm -qip pack.rpm : pack files detail info패키지 파일의 상세 정보


# Process priority
low value run first
ps -el, top, mpstat: watch nice

nice -n [n] [proc name]: gen new process, add nice to before value
renice [n] [PID]: change aleady gened process's priority to n


# 스케쥴링
## crontab
crontab -e: 크론탭 수정
crontab -l: 크론탭 목록 출력
crontab -eu centos: 사용자의 크론탭 수정
minute hour date month day(0:sun)
* * * * * action 
*/10 * * * * * action : per 10 min

# 로그 작성
last: 최근 로그인 기록
last -4 or last -n 4: 최근 기록 4개
lastb: 최근 실패한 로그인 기록(last의 반대)
lastb -4 or lastb -n 4: 최근 기록 4개
lastlog: 모든계정의 가장 최근 로그인(계정 당 최근1개 + 시스템계정도 나온다는게 차이점)


# 시스템정보 확인
커널정보 확인
uname -a
hostnamectl
cat /proc/version


# iptables

목적지 주소를 바꿀 때
-t nat -A PREROUTING -i eth0 -j DNAT --to 200.100.50.10

소스 주소를 바꿀 때
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
http-access allow [alias] : allow alias range
http-access deny [alias] : deny alias range

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
