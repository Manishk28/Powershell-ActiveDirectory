$username="Testuser_"
$count=1..100
foreach ($i in $count)
{
New-AdUser -Name $username$i -Enabled $True -AccountPassword (ConvertTo-SecureString "Password12345" -AsPlainText -force) -ChangePasswordAtLogon $true -passThru 
#Add-ADGroupMember -Identity 'TestGroup' -Members $username$i
#Remove-AdUser -Identity $username$i -Confirm $true 
} 
