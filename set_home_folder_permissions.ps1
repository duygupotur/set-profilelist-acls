# C:\users\test\Documents\set_home_folder_permissions.ps1
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

function set-regedit-acls {
    param( $User, $HomePath)
    $UsernamePrefix, $Username= ($User -split '\\')
    $username
    $use
    # create ntaccount
    $IdRef = [System.Security.Principal.NTAccount]($User)
    
    # New-PSDrive HKU Registry HKEY_USERS
    $BrokenRegedit = "$Username"

    # create a "drive" for HKEY_CLASSES_ROOT
    new-psdrive -name ACL -psprovider Registry -root HKEY_USERS

    # change the current location
    set-location ACL:\

    # load hiv
    reg load "HKU\$BrokenRegedit" $HomePath\NTUSER.DAT

    # add permission to regedit
    Get-Item ACL:\$BrokenRegedit `
        | foreach { $_ ; $_ | Get-ChildItem -Force -Recurse } `
        | foreach { 
            # get current acl
            $acl = Get-Acl $_
            # $acl.Access
        
            # set acl rule
            $regRights = [System.Security.AccessControl.RegistryRights]::FullControl
            $inhFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
            $prFlags = [System.Security.AccessControl.PropagationFlags]::None
            $acType = [System.Security.AccessControl.AccessControlType]::Allow
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
        
            # add acl rule 
            $acl.AddAccessRule($rule)
            $acl.SetAccessRule($rule)
            $acl | Set-Acl -Path $_
        }
    
    # write changes
    [gc]::Collect()
    sleep 2

    # unload hiv
    
    cd C:\
    reg unload HKU\$BrokenRegedit
    Remove-PSDrive -Name ACL
}

function set-home-folder-acls {
    param( $User, $HomePath)
    $UsernamePrefix, $Username= ($User -split '\\')

    # create ntaccount
    $IdRef = [System.Security.Principal.NTAccount]($User)

    # create home folder object
    $HomeFolder = Get-Item $HomePath

    # get folder's current acls
    $HomeFolderAcl = $HomeFolder.GetAccessControl()

    ## create rule permissions
    $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($IdRef, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
    $HomeFolderAcl.AddAccessRule($AccessRule)

    ## Set Acl
    Set-Acl -AclObject $HomeFolderAcl -ea Stop -Path $HomeFolder
    dir -r $HomeFolder | Set-Acl -AclObject $HomeFolderAcl -ea Stop

}

Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {   
    if ( $_.GetValue('FullProfile')) {
        $ProfilePath = $_.GetValue('ProfileImagePath') 
        $UserSid = $_.GetValue('Sid') 
        $SidString = (New-Object System.Security.Principal.SecurityIdentifier($UserSid, 0))
        Try{
            $User = $SidString.Translate([System.Security.Principal.NTAccount])
            echo "$ProfilePath $User"
            echo "Set acl $ProfilePath for $User"
            set-regedit-acls -User $User -HomePath $ProfilePath
            set-home-folder-acls -User $User -HomePath $ProfilePath
        }
        Catch{
          Write-Host ("Failed to update " + $SidString) -ForegroundColor Red
        }
    }
}