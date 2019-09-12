#
# SetAdminIUPN.ps1
#

Get-ADUser ($env:UserName) | Set-ADUser -UserPrincipalName (($env:UserName)+"@"+((Get-ADDomain | select forest).forest))