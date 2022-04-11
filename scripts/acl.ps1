$Username = "leyla"
$Domain = "DUYGU"
$IdRef = [System.Security.Principal.NTAccount]($Domain+"\"+$Username)
$HomePath = "C:\Users\leyla"

# New-PSDrive HKU Registry HKEY_USERS
$BrokenRegedit = 'Broken'


# create a "drive" for HKEY_CLASSES_ROOT
new-psdrive -name ACL -psprovider Registry -root HKEY_USERS

# change the current location
set-location ACL:\
reg load "HKU\$BrokenRegedit" $HomePath\NTUSER.DAT

$acl = Get-Acl "ACL:\$BrokenRegedit"
$acl.Access

Get-Item ACL:\$BrokenRegedit `
    | foreach { $_ ; $_ | Get-ChildItem -Force -Recurse } `
    | foreach { 
        $acl = Get-Acl $_
        $acl.Access
        
        $regRights = [System.Security.AccessControl.RegistryRights]::FullControl
        $inhFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        # $inhFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $prFlags = [System.Security.AccessControl.PropagationFlags]::None
        $acType = [System.Security.AccessControl.AccessControlType]::Allow
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
        
        $acl.AddAccessRule($rule)
        $acl.SetAccessRule($rule)
        $acl | Set-Acl -Path $_
    }



[gc]::Collect()
(Get-Acl "ACL:\$BrokenRegedit").Access

reg unload HKU\Broken
cd C:\
Remove-PSDrive -Name ACL

