#!/usr/bin/bash
bool = true
#Updates
apt-get update
apt-get upgrade
#Installing and cofiguring UFW
apt-get install ufw
ufw enable
ufw status
#empty passwords
sudo awk -F: '!$2 {print $1}' /etc/shadow 
#denying empty passwords
grep nullok /etc/pam.d/common-password
#ensuring only users who need access to security functions are part of sudo group
grep sudo /etc/group  
sudo:x:27:<username> 
#disable ctrl-alt-delete
gsettings get org.gnome.settings-daemon.plugins.media-keys logout 
@as []
#disabling the ctrl-alt-delete sequence
systemctl status ctrl-alt-del.target 
ctrl-alt-del.target 
Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.) 
Active: inactive (dead) 
#not allow unattended or automatic login via SSH. 
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))' 
/etc/ssh/sshd_config:PermitEmptyPasswords no 
/etc/ssh/sshd_config:PermitUserEnvironment no
#requiring the change of at least eight characters when passwords are changed.
grep -i difok /etc/security/pwquality.conf 
     difok = 8  
#minimum pass policy
grep -i minlen /etc/security/pwquality.conf 
     minlen = 15 
#complex pass policy
grep -i ocredit /etc/security/pwquality.conf 
     ocredit = -1  
#requiring a numeric character for passwords
grep -i dcredit /etc/security/pwquality.conf 
     dcredit = -1  
#enforcing password complexity by requiring at least one lowercase character be used.
grep -i lcredit /etc/security/pwquality.conf 
     lcredit = -1 
 #enforcing password complexity by requiring at least one uppercase character 
 grep -i ucredit /etc/security/pwquality.conf 
     ucredit = -1  
#enforcing reauthentication for privilege escalaltion
sudo grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*
#enforce a 60-day maximum password lifetime restriction.
grep -i pass_max_days /etc/login.defs 
     PASS_MAX_DAYS    60  
#24 hours/one day minimum password lifetime restriction
grep -i pass_min_days /etc/login.defs 
     PASS_MIN_DAYS    1 



#password policies
#audit policies
#services
#users
names=()
cat /etc/passwd
while [bool = true]
do
     echo What user would you like to delete? Type "done" if done.
     read input
     if [ "input" == "done" ]; then
          bool = false
     else
          names+=("input")
     fi
done
for i in $($names)
do
     userdel -f $names
done
#user groups
names=()
getent group
while [bool = true]
do
     echo Enter 1 to add a user to a group, 2 to create a group, 3 to delete a user from a group, 4 to delete a group, or done to continue the script.
     read input
     if [ "input" == "done" ]; then
          bool = false
     else if ["input" == "1"]; then
          names+=("input")
     else if
          names+=("input")
     else if
          names+=("input")
     else if
          names+=("input")
     fi
done
for i in $($names)
do
     userdel -f $names
done
#ports
#updates
apt-get update
apt-get upgrade
