#
# SQL_PS_Extension.ps1
#

# Actions:
# - Add the Domain Admins Groups to the SysAdmins Group in SQL Server

# Setting variables
$AdminUser = $args[0]
$adminPassword = $args[1]
$netbiosADDS = $args[2]
$ADDSServer = $args[3]
$FQDN = $args[4]
$SCCMServiceAccountPassword = ConvertTo-SecureString -String $args[5] -AsPlainText -Force
$SQLServiceAccountPassword = ConvertTo-SecureString -String $args[6] -AsPlainText -Force
$sccmHostName = $args[7]

#Capture Script Location (because Extension versions may vary)
$CurrentScriptLocation = (Get-Location).path

#Let the server settle down before config
Start-Sleep -s 180

#Configure logging
function log
{
   param([string]$message)
   "`n`n$(get-date -f o)  $message" 
}

#Disable Defender RealTime Scanning
Set-MpPreference -DisableRealtimeMonitoring $true

#Start SQL Server
net start MSSQLSERVER

#Enable CredSSP to allow Multiple HOP Remote PowerShell
log "Configuring WSMAN"
Enable-WSManCredSSP -Role Server -Force
Enable-WSManCredSSP -Role Client -DelegateComputer ("*."+$FQDN) -Force
Enable-PSRemoting -force
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force

#Set policy "Allow delegating fresh credentials with NTLM-only server authentication" 
log "Configuring CREDSSP"
$allowed = @('WSMAN/*.'+ $FQDN)
$key = 'hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
if (!(Test-Path $key)) {
    md $key
}  
New-ItemProperty -Path $key -Name AllowFreshCredentialsWhenNTLMOnly  -Value 1 -PropertyType Dword -Force    
$key = Join-Path $key 'AllowFreshCredentialsWhenNTLMOnly'
if (!(Test-Path $key)) {
    md $key
}
$i = 1
$allowed |% {
    # Script does not take into account existing entries in this key
    New-ItemProperty -Path $key -Name $i -Value $_ -PropertyType String -Force
    $i++
}

#Create Credentials
$mycreds = New-Object System.Management.Automation.PSCredential ($AdminUser, (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

# This creates the SCCM Service accounts pages 61 through 65 FB
$ScriptBlockServiceAccounts= {
	param ($fqdn, $SCCMServiceAccountPassword,$SQLServiceAccountPassword)

    function log
    {
       param([string]$message)
       "`n`n$(get-date -f o)  $message" 
    }
	
	#Set UPN for admin account
	Get-ADUser ($env:UserName) | Set-ADUser -UserPrincipalName (($env:UserName)+"@"+((Get-ADDomain | select forest).forest))

	#Configure the CN for the Service account users
	$CN = "CN=Managed Service Accounts,DC=" + $FQDN.Split('.')[0] + ",DC=" + $FQDN.Split(".")[1]

	#Create the SCCM Netaccess account
	log "Create the SCCM Netaccess account"
	$SCCMServiceAccountName = "SCCM Netaccess"
	New-ADUser -Name $SCCMServiceAccountName  -SamAccountName $SCCMServiceAccountName -UserPrincipalName ($SCCMServiceAccountName+"@"+$FQDN) -Path $CN -AccountPassword $SCCMServiceAccountPassword -Enabled $true -PasswordNeverExpires $true

	#Create the SQL Service account
	log "Create the SQL Service account"
	$SQLServiceAccountName = "SQL.service"
	New-ADUser -Name $SQLServiceAccountName  -SamAccountName $SQLServiceAccountName -UserPrincipalName ($SQLServiceAccountName+"@"+$FQDN) -Path $CN -AccountPassword $SQLServiceAccountPassword -Enabled $true -PasswordNeverExpires $true
}

$session = New-PSSession -cn ($ADDSServer+"."+$FQDN) -Credential $mycreds -Authentication Credssp
Invoke-Command -Session $session -ScriptBlock $ScriptBlockServiceAccounts -ArgumentList $fqdn, $SCCMServiceAccountPassword, $SQLServiceAccountPassword
Remove-PSSession -VMName ($ADDSServer+"."+$FQDN)

#Wait for creation of service accounts and start SQL
Start-Sleep -s 30
net start MSSQLSERVER

#Set SQL Permissions for admins
log "Set SQL Permissions for admins"
if ($netbiosADDS -ne "contoso")
{
	$filePath = $CurrentScriptLocation+'\'+'AddDomainAdminsToSysAdmins.sql'
	$tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
	$find = 'contoso'
	$replace = $netbiosADDS
	(Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
	Remove-Item -Path $filePath
	Move-Item -Path $tempFilePath -Destination $filePath
	}
if ($sccmHostName -ne "sccm-01")
	{
		$filePath = $CurrentScriptLocation+'\'+'AddDomainAdminsToSysAdmins.sql'
		$tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
		$find = 'sccm-01'
		$replace = $sccmHostName
		(Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
		Remove-Item -Path $filePath
		Move-Item -Path $tempFilePath -Destination $filePath
		}	
cd "\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn"
& sqlcmd -S ($env:computername) -U $AdminUser -P $adminPassword -i $CurrentScriptLocation'\AddDomainAdminsToSysAdmins.sql'


#Log Change SQL Server Service account
log "Change SQL Server Service account"
$ServiceAccountobject = $netbiosADDS+"\sql.service"
& sc.exe config "MSSQLSERVER" obj= $ServiceAccountobject password= $args[5]
net stop MSSQLSERVER
net start MSSQLSERVER

#Change SQL Server Collation
net stop MSSQLSERVER
CD "\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Binn"
.\sqlservr -m -T4022 -T3659 -s"SQLEXP2014" -q"SQL_Latin1_General_CP1_CI_AS"
net start MSSQLSERVER

#Open File and Printer Sharing for the SCCM Installation
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

#Add the SCCM Computer Account to the Local Admins Group on SQL
Add-LocalGroupMember -Group "Administrators" -Member ($sccmHostName+"$")