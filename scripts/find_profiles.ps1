# C:\users\test\Documents\test.ps1
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') }
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {   
    if ( $_.GetValue('FullProfile')) {
        $ProfilePath = $_.GetValue('ProfileImagePath') 
        $UserSid = $_.GetValue('Sid') 
        $SidString = (New-Object System.Security.Principal.SecurityIdentifier($UserSid, 0))
        Try{
          $User = $SidString.Translate([System.Security.Principal.NTAccount])
          $user
        }
        Catch{
          Write-Host ("Failed to update " + $SidString) -ForegroundColor Red
          $SidString = ""
        }
    }
}