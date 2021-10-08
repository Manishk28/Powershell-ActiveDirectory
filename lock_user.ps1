#Requires -Version 3.0
#Requires -Modules ActiveDirectory, GroupPolicy
$user = Get-ADUser -Identity "test.user"
write-host $user
    $Password = ConvertTo-SecureString 'NotMyPassword' -AsPlainText -Force
 
    Get-ADUser -Identity $user -Properties SamAccountName, UserPrincipalName, LockedOut |
        ForEach-Object {
 
            Do {
 
                Invoke-Command -ComputerName <DOMAIN CONTROLLER NAME> {Get-Process
                } -Credential (New-Object System.Management.Automation.PSCredential ($($_.UserPrincipalName), $Password)) -ErrorAction SilentlyContinue
 
            }
            Until ((Get-ADUser -Identity $_.SamAccountName -Properties LockedOut).LockedOut)
 
            Write-Output "$($_.SamAccountName) has been locked out"
        } 
