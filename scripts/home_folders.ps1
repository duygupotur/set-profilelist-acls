$Username = "leyla"
$Domain = "DUYGU"
$IdRef = [System.Security.Principal.NTAccount]($Domain+"\"+$Username)

$HomePath = "C:\Users\leyla"
$HomeFolder = Get-Item $HomePath
$HomeFolder

$HomeFolderAcl = $HomeFolder.GetAccessControl()

## Permissions
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($IdRef, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
$HomeFolderAcl.AddAccessRule($AccessRule)
