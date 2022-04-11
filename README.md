# set-profilelist-acls
This script fixes the privileges of user home directories privileges and NTUSER.dat regedits in home directory privileges.

## General Fix Usage
- Opens a powershell with admin authority.
- Permission to run script on open session is given with the following command
```
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```
- Script file is run
```
.\set_home_folder_permissions.ps1
```