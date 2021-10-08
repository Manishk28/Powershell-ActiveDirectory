# Powershell-ActiveDirectory
A collection of Active Directory scripts

# List of useful commands 
View all Active Directory commands
get-command -Module ActiveDirectory

Display Basic Domain Information
Get-ADDomain

Get all Domain Controllers by Hostname and Operating
Get-ADDomainController -filter * | select hostname, operatingsystem

Get all Fine Grained Password Policies
Get-ADFineGrainedPasswordPolicy -filter *

Get Domain Default Password Policy
Gets the password policy from the logged in domain
Get-ADDefaultDomainPasswordPolicy

Backup Active Directory System State Remotely
This will back up the domain controllers system state data. Change DC-Name to your server name and change the Backup-Path. The backup path can be a local disk or a UNC path
invoke-command -ComputerName DC-Name -scriptblock {wbadmin start systemstateback up -backupTarget:"Backup-Path" -quiet}

AD User PowerShell Commands
This section is all Active Directory user commands
Get User and List All Properties (attributes)
Change username to the samAccountName of the account
Get-ADUser username -Properties *

Get User and List Specific Properties
Just add whatever you want to display after select
Get-ADUser username -Properties * | Select name, department, title

Get All Active Directory Users in Domain
Get-ADUser -Filter *

Get All Users From a Specific  OU
OU = the distinguished path of the OU
Get-ADUser -SearchBase “OU=ADPRO Users,dc=ad,dc=activedirectorypro.com” -Filter *

Get AD Users by Name
This command will find all users that have the word robert in the name. Just change robert to the word you want to search for.
get-Aduser -Filter {name -like "*robert*"}
Get All Disable User Accounts
Search-ADAccount -AccountDisabled | select name

Disable User Account
Disable-ADAccount -Identity rallen

Enable User Account
Enable-ADAccount -Identity rallen

Get All Accounts with Password Set to Never Expire
get-aduser -filter * -properties Name, PasswordNeverExpires | where {$_.passwordNeverExpires -eq "true" } | Select-Object DistinguishedName,Name,Enabled

Find All Locked User Accounts
Search-ADAccount -LockedOut

Unlock User Account
Unlock-ADAccount –Identity john.smith

List all Disabled User Accounts
Search-ADAccount -AccountDisabled

Force Password Change at Next Login
Set-ADUser -Identity username -ChangePasswordAtLogon $true

Move a Single User to a New OU
You will need the distinguishedName of the user and the target OU
Move-ADObject -Identity "CN=Test User (0001),OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" -TargetPath "OU=HR,OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com"

Move Users to an OU from a CSV
Setup a csv with a name field and a list of the users sAmAccountNames. Then just change the target OU path.
# Specify target OU. $TargetOU = "OU=HR,OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" # Read user sAMAccountNames from csv file (field labeled "Name"). Import-Csv -Path Users.csv | ForEach-Object { # Retrieve DN of User. $UserDN = (Get-ADUser -Identity $_.Name).distinguishedName # Move user to target OU. Move-ADObject -Identity $UserDN -TargetPath $TargetOU }

AD Group Commands
Get All members Of A Security group
Get-ADGroupMember -identity “HR Full”
Get All Security Groups
This will list all security groups in a domain
Get-ADGroup -filter *

Add User to Group
Change group-name to the AD group you want to add users to
Add-ADGroupMember -Identity group-name -Members Sser1, user2

Export Users From a Group
This will export group members to a CSV, change group-name to the group you want to export.
Get-ADGroupMember -identity “Group-name” | select name | Export-csv -path C:OutputGroupmembers.csv -NoTypeInformation

Get Group by keyword
Find a group by keyword. Helpful if you are not sure of the name, change group-name.
get-adgroup -filter * | Where-Object {$_.name -like "*group-name*"}

Import a List of Users to a Group
$members = Import-CSV c:itadd-to-group.csv | Select-Object -ExpandProperty samaccountname Add-ADGroupMember -Identity hr-n-drive-rw -Members $members

AD Computer Commands

Get All Computers
This will list all computers in the domain
Get-AdComputer -filter *
Get All Computers by Name

This will list all the computers in the domain and only display the hostname
Get-ADComputer -filter * | select name

Get All Computers from an OU
Get-ADComputer -SearchBase "OU=DN" -Filter *

Get a Count of All Computers in Domain
Get-ADComputer -filter * | measure

Get all Windows 10 Computers
Change Windows 10 to any OS you want to search for
Get-ADComputer -filter {OperatingSystem -Like '*Windows 10*'} -property * | select name, operatingsystem

Get a Count of All computers by Operating System
This will provide a count of all computers and group them by the operating system. A great command to give you a quick inventory of computers in AD.
Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count

Delete a single Computer
Remove-ADComputer -Identity "USER04-SRV4"

Delete a List of Computer Accounts
Add the hostnames to a text file and run the command below.
Get-Content -Path C:ComputerList.txt | Remove-ADComputer

Delete Computers From an OU
Get-ADComputer -SearchBase "OU=DN" -Filter * | Remote-ADComputer

Collecting Disabled User Accounts Information
Search-ADAccount –AccountDisabled –UsersOnly –ResultPageSize 2000 –ResultSetSize $null | Select-Object SamAccountName, DistinguishedName

Collecting Inactive User Accounts
Search-ADAccount –AccountInActive –TimeSpan 90:00:00:00 –ResultPageSize 2000 –ResultSetSize $null | ?{$_.Enabled –eq $True} | Select-Object Name, SamAccountName, DistinguishedName

Collecting Disabled Computer Accounts Information
Get-ADComputer -Filter {(Enabled -eq $False)} -ResultPageSize 2000 -ResultSetSize $null -Server <AnyDomainController> -Properties Name, OperatingSystem
