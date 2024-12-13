#!/usr/bin/bash 
#password policies

#audit policies
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


#audit policies

#generates audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access
sudo auditctl -l | grep sudo.log  
     -w /var/log/sudo.log -p wa -k maintenance 

#prevents all software from executing at higher privilege levels than users executing the software
sudo auditctl -l | grep execve 
     -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv 

#generates audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur
  sudo auditctl -l | grep sudoers  
     -w /etc/sudoers -p wa -k privilege_modification  

 #generates audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
 sudo auditctl -l | grep sudoers.d  
     -w /etc/sudoers.d -p wa -k privilege_modification 

#must generate audit records for the use and modification of the lastlog file
 sudo auditctl -l | grep lastlog  
     -w /var/log/lastlog -p wa -k logins    

#must generate audit records for the use and modification of faillog file
sudo auditctl -l | grep faillog  
     -w /var/log/faillog -p wa -k logins  

#must generate audit records for the /var/run/utmp file 
sudo auditctl -l | grep '/var/run/utmp'  
     -w /var/run/utmp -p wa -k logins  

#must generate audit records for the /var/log/wtmp file 
sudo auditctl -l | grep '/var/log/wtmp'  
     -w /var/log/wtmp -p wa -k logins

#must generate audit records for the /var/log/btmp file
sudo auditctl -l | grep '/var/log/btmp'  
     -w /var/log/btmp -p wa -k logins  

#generate audit records for all events that affect the systemd journal files
sudo auditctl -l | grep journal  
     -w /var/log/journal -p wa -k systemd_journal  

# generates audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls
sudo auditctl -l | grep 'unlink\|rename\|rmdir'  
     -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete  
     -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete  


# generates audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls
sudo auditctl -l | grep xattr  
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod  
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod   
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod  
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod 

#generates audit records for successful/unsuccessful uses of the init_module and finit_module system calls
sudo auditctl -l | grep init_module  
     -a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng  
     -a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng  


# generates audit records for successful/unsuccessful uses of the delete_module system call
sudo auditctl -l | grep -w delete_module  
     -a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng  
     -a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng  



sudo auditctl -l | grep 'open\|truncate\|creat'  
     -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access    


#generates audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls
sudo auditctl -l | grep chown  
     -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  
     -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  


#generates audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls
sudo auditctl -l | grep chown  
     -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  
     -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  


#generates audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls
 sudo auditctl -l | grep chmod 
     -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng  
     -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng  

#generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow
sudo auditctl -l | grep shadow 
     -w /etc/shadow -p wa -k usergroup_modification 


#generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd
sudo auditctl -l | grep passwd 
     -w /etc/passwd -p wa -k usergroup_modification 
 
#generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd
sudo auditctl -l | grep opasswd 
     -w /etc/security/opasswd -p wa -k usergroup_modification 
 
#generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
sudo auditctl -l | grep gshadow 
     -w /etc/gshadow -p wa -k usergroup_modification 

#generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
sudo auditctl -l | grep group 
     -w /etc/group -p wa -k usergroup_modification

#generates audit records for successful/unsuccessful uses of the usermod command
sudo auditctl -l | grep -w usermod 
     -a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod 

#generates audit records for successful/unsuccessful uses of the unix_update command
sudo auditctl -l | grep -w unix_update 
     -a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update  
     
#generates audit records for successful/unsuccessful uses of the umount command.
sudo auditctl -l | grep /usr/bin/umount 
     -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount 

#generates audit records for successful/unsuccessful uses of the sudoedit command.
sudo auditctl -l | grep /usr/bin/sudoedit 
     -a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd




#services

#users

#add or delete users
cat /etc/passwd
while [bool = true]
do
     echo Enter 1 to create a user, 2 to delete a user, or done to continiue the script.
     read userInput
     if [ "userInput" == "done" ]; then
          bool = false
     else if ["input" == "1"]; then
          echo What is the name of the user that will be created?
          read user
          useradd -aG $user
     else if ["input" == "2"]; then
          echo What is the name of the user that will be deleted?
          read group
          userdel -f $user
     fi
done

#groups
getent group
while [bool = true]
do
     echo Enter 1 to add a user to a group, 2 to create a group, 3 to delete a user from a group, 4 to delete a group, or done to continue the script.
     read userInput
     if [ "userInput" == "done" ]; then
          bool = false
     else if ["input" == "1"]; then
          echo What group shall the user join?
          read group
          echo What user should be added to the group?
          read user
          usermod -aG $group $user
     else if ["input" == "2"]; then
          echo What is the name of the new group?
          read group
          groupadd $group
     else if ["input" == "3"]; then
          echo What group would you like to delete a user from?
          read group
          echo What user would you like to delete from the group?
          read user
          gpasswd -d -f $user $group
     else if ["input" == "4"]; then
          echo What is the name of the group that will be deleted?
          read group
          groupdel -f $group
     fi
done
#ports
echo Check out the ports of the VM for any insecure one (open or they use insecure protocols

