$users = "Testuser"
$groups = 'Domain Admins'

foreach ($user in $users) {
    foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group -Recursive | Select -ExpandProperty SamAccountName
        write-output $members > "C:\Users\manish.kothari\Desktop\1.log" #create a file on desktop with list of users which are member of group.
        If ($members -contains $user) {
            Write-Host "$user is a member of $group"
        } Else {
            Write-Host "$user is not a member of $group"
        }
    }
} 
