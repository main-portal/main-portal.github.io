Write-Host "
##############################################################################
[+] DOMAIN ENUMERATION BASIC
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print current domain
[+] Command --> Get-NetDomain
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetDomain
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print current domain SID
[+] Command --> Get-DomainSID
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-DomainSID
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print domain controllers for the current domain
[+] Command --> Get-NetDomainController
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetDomainController
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] DOMAIN ADMINISTRATOR ENUMERATION 
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print Members of the Domain Admins group
[+] Command --> Get-NetGroupMember -GroupName 'Domain Admins'
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGroupMember -GroupName "Domain Admins"
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print Attributes of the Domain Admins Group
[+] Command --> Get-NetGroup -GroupName 'Domain Admins' -FullData
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGroup -GroupName "Domain Admins" -FullData
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] ENTERPRISE ADMINS ENUMERATION 
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host " FIX THIS CODE 
##############################################################################
[+] Print Members of the Enterprise Admins Group
[+] Command --> Get-NetGroupMember -GroupName 'Enterprise Admins' -Domain moneycorp.local
##############################################################################
 -ForegroundColor Yellow -BackgroundColor Black
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain moneycorp.local
" -ForegroundColor red -BackgroundColor white

Write-Host "
##############################################################################
[+] DOMAIN USERS ENUMERATION 
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print list of users in the current domain
[+] Command --> Get-NetUser
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetUser
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print list of all properties for users in the current domain
[+] Command --> Get-UserProperty | ft
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-UserProperty | ft
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print all the SPN accounts
[+] Command --> Get-NetUser -SPN
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetUser -SPN
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] SENSITIVE FILES AND SHARES 
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print interesting shares
[+] Command --> Invoke-ShareFinder -Exclude Standard -ExcludePrint -ExcludeIPC -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-ShareFinder -Exclude Standard -ExcludePrint -ExcludeIPC -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print sensitive files on computers in the domain
[+] Command --> Invoke-FileFinder -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-FileFinder -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] READ NOTES FOR MORE ENUMERATION SNIPPETS
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] GPO AND OU ENUMERATION
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print Restricted Groups from GPO
[+] Command --> Get-NetGPOGroup -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGPOGroup -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print for membership of the group 'RDPUsers'
[+] Command --> Get-NetGroupMember -GroupName RDPUsers
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGroupMember -GroupName RDPUsers
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print all the OUs
[+] Command --> Get-NetOU -FullData
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetOU -FullData
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print the GPOs
[+] Note the adspath
[+] Command --> Get-NetGPO
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGPO
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] READ NOTES FOR MORE ENUMERATION SNIPPETS
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] ACL ENUMERATION
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print ACL for the Domain Admins group
[+] Command --> Get-ObjectAcl -SamAccountName 'Domain Admins' -ResolveGUIDs -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print ACLs for all of the GPOs
[+] Command --> Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print all interesting ALC's
[+] Command --> Invoke-ACLScanner -ResolveGUIDs
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-ACLScanner -ResolveGUIDs
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print All Modify rights/perms for the RDPUsers group
[+] Command --> Invoke-ACLScanner -ResolveGUIs | ?{$_.IdentityReference -match 'RDPUsers'}
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-ACLScanner -ResolveGUIs | ?{$_.IdentityReference -match "RDPUsers"}
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] READ NOTES FOR MORE ENUMERATION SNIPPETS
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] TRUSTS ENUMERATION
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print all domains in the root forest
[+] Keep note of the name parameter
[+] Command --> Get-NetForestDomain -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetForestDomain -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print Mapped trusts for the complete Domain
[+] Command --> Get-NetForestDomain | Get-NetDomainTrust -NET
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Get-NetForestDomain | Get-NetDomainTrust -NET
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Extract info from the external forest
[+] Command below
[+] Get-NetForestDomain -Forest external-forest-name-here -Verbose | Get-NetDomainTrust -NET
##############################################################################
" -ForegroundColor red -BackgroundColor White

Write-Host "
##############################################################################
[+] User Hunting
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
[+] Print all machines on the current domain where the current user has local admin access
[+] Command --> Find-LocalAdminAccess -Verbose
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Find-LocalAdminAccess -Verbose
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Print computers where a domain admin (or specified user/group) has sessions
[+] More example : Invoke-UserHunter -GroupName 'RDPUsers'
[+] Command --> Invoke-UserHunter
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-UserHunter
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] Confirm Access Check to Local Admin Accounts
[+] Command --> Invoke-UserHunter -CheckAccess
##############################################################################
" -ForegroundColor Yellow -BackgroundColor Black
try{
Invoke-UserHunter -CheckAccess
}
catch{
Write-Host "NO RESULT" -ForegroundColor Green -BackgroundColor RED
}

Write-Host "
##############################################################################
[+] READ NOTES FOR MORE ENUMERATION SNIPPETS
##############################################################################
" -ForegroundColor red -BackgroundColor Black

Write-Host "
##############################################################################
SCAN ENDED
##############################################################################
" -ForegroundColor Magenta -BackgroundColor black