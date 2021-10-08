$FuncRoot = New-Object System.DirectoryServices.DirectoryEntry LDAP://<IP ADDRESS>:389
$FuncQuery = New-Object System.DirectoryServices.DirectorySearcher
$FuncQuery.SearchRoot = $FuncRoot
$FuncQuery.filter = "(distinguishedname=<GUID=0a030557-0fad-0d00-bcf0-0b00a0a00d00>)"
$FuncResult = $FuncQuery.FindOne()
	if ($FuncResult -eq $Null) {
		Write-Host "User not found"
	}	
	else {
		Write-Host "User found"
	} 
