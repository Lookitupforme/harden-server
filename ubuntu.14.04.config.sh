#!/bin/bash
# konstruktoid.net
#
# Documentation:
# Red Hat 6 STIG - Version 1 Release 4
# Guide to the Secure Configuration of Red Hat Enterprise Linux 5
# CIS Ubuntu 12.04 LTS Server Benchmark v1.0.0
# https://wiki.ubuntu.com/Security/Features
# https://help.ubuntu.com/community/StricterDefaults
# Works fine on 14.04 LTS

SYSCTL_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/misc/sysctl.conf"
AUDITD_RULES="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/misc/audit.rules"
VERBOSE="N"

clear

if [[ $VERBOSE == "Y" ]];
  then
    APTFLAGS="--assume-yes"
  else
    APTFLAGS="--quiet=2 --assume-yes"
fi

APT="aptitude $APTFLAGS"

if ! [[ `lsb_release -i |grep 'Ubuntu'` ]];
  then
    echo "Ubuntu only. Exiting."
    echo
    exit
fi

i="0"

echo "[$i] Updating the package index files from their sources."
 $APT update
((i++))

echo "[$i] Upgrading installed packages."
 $APT upgrade
((i++))

echo "[$i] /etc/hosts.*"
 bash -c "echo sshd : ALL : ALLOW$'\n'ALL: LOCAL, 127.0.0.1 > /etc/hosts.allow"
 bash -c "echo ALL: PARANOID > /etc/hosts.deny"
((i++))

echo "[$i] /etc/login.defs"
 sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' /etc/login.defs
 sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
 sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
 sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' /etc/login.defs
((i++))

echo "[$i] /etc/sysctl.conf"
 bash -c "curl -s $SYSCTL_CONF > /etc/sysctl.conf"
 service procps start
((i++))

echo "[$i] /etc/security/limits.conf"
 sed -i 's/^# End of file*//' /etc/security/limits.conf
 bash -c "echo * hard maxlogins 10 >> /etc/security/limits.conf"
 bash -c "echo * hard core 0$'\n'* soft nproc 100$'\n'* hard nproc 150$'\n\n'# End of file >> /etc/security/limits.conf"
((i++))

echo "[$i] Adduser / Useradd"
 sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf
 sed -i 's/SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd
 sed -i 's/^# INACTIVE=.*/INACTIVE=35/' /etc/default/useradd
((i++))

echo "[$i] Root access"
 sed -i 's/^#+ : root : 127.0.0.1/+ : root : 127.0.0.1/' /etc/security/access.conf
 bash -c "echo console > /etc/securetty"
((i++))

echo "[$i] Installing base packages."

 bash -c "echo postfix postfix/main_mailer_type select Internet Site | debconf-set-selections"
 bash -c "echo postfix postfix/mailname string `hostname -f` | debconf-set-selections"

 $APT install aide-common apparmor-profiles auditd haveged libpam-cracklib libpam-tmpdir ntp openssh-server postfix $VM

echo "[$i] /etc/ssh/sshd_config"
# bash -c "echo $'\n'## Groups allowed to connect$'\n'AllowGroups $SSH_GRPS >> /etc/ssh/sshd_config"
 sed -i 's/^LoginGraceTime 120/LoginGraceTime 20/' /etc/ssh/sshd_config
 sed -i 's/^PermitRootLogin without-password/PermitRootLogin no/' /etc/ssh/sshd_config
 bash -c "echo ClientAliveInterval 900 >> /etc/ssh/sshd_config"
 bash -c "echo ClientAliveCountMax 0 >> /etc/ssh/sshd_config"
 bash -c "echo PermitUserEnvironment no >> /etc/ssh/sshd_config"
 bash -c "echo Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc >> /etc/ssh/sshd_config"
 bash -c "echo UseDNS no >> /etc/ssh/sshd_config"
 /etc/init.d/ssh restart
((i++))

echo "[$i] Passwords and authentication"
 sed -i 's/^password[\t].*.pam_cracklib.*/password\trequired\t\t\tpam_cracklib.so retry=3 maxrepeat=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4/' /etc/pam.d/common-password
 sed -i 's/try_first_pass sha512.*/try_first_pass sha512 remember=24/' /etc/pam.d/common-password
 sed -i 's/nullok_secure//' /etc/pam.d/common-auth
((i++))

echo "[$i] Cron and at"
 bash -c "echo root > /etc/cron.allow"
 bash -c "echo root > /etc/at.allow"
((i++))

echo "[$i] Ctrl-alt-delete"
 sed -i 's/^exec.*/exec \/usr\/bin\/logger -p security.info \"Ctrl-Alt-Delete pressed\"/' /etc/init/control-alt-delete.conf
((i++))

echo "[$i] Blacklisting kernel modules"
 bash -c "echo >> /etc/modprobe.d/blacklist.conf"
for mod in dccp sctp rds tipc net-pf-31 bluetooth usb-storage;
do
   bash -c "echo install $mod /bin/false >> /etc/modprobe.d/blacklist.conf"
done
((i++))

echo "[$i] Auditd"
 sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
 bash -c "curl -s $AUDITD_RULES > /etc/audit/audit.rules"
 sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
 bash -c "curl -s $AUDITD_RULES > /etc/audit/audit.rules"
 update-grub 2> /dev/null
((i++))

echo "[$i] Aide"
 sed -i 's/^Checksums =.*/Checksums = sha512/' /etc/aide/aide.conf
((i++))

echo "[$i] .rhosts"
for dir in `cat /etc/passwd | awk -F ":" '{print $6}'`;
do
        find $dir -name "hosts.equiv" -o -name ".rhosts" -exec rm -f {} \; 2> /dev/null
        if [[ -f /etc/hosts.equiv ]];
                then
                rm /etc/hosts.equiv
        fi
done
((i++))

echo "[$i] Remove users"
for users in games gnats irc news uucp;
do
  sudo userdel -r $users 2> /dev/null
done

echo "[$i] Remove suid bits"
for p in /bin/fusermount /bin/mount /bin/ping /bin/ping6 /bin/su /bin/umount /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/pkexec /usr/bin/traceroute6.iputils /usr/bin/wall /usr/sbin/pppd;
do
  oct=`stat -c "%a" $p |sed 's/^4/0/'`
  ug=`stat -c "%U %G" $p`
   dpkg-statoverride --remove $p 2> /dev/null
   dpkg-statoverride --add $ug $oct $p 2> /dev/null
   chmod -s $p
done

for SHELL in `cat /etc/shells`; do
  if [ -x $SHELL ]; then
     chmod -s $SHELL
  fi
done

((i++))

echo "[$i] Cleaning."
 $APT clean
 $APT autoclean
 apt-get -qq autoremove
((i++))

echo
echo "[$i] Running Aide, this will take a while"
 aideinit --yes
 cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
((i++))

echo
