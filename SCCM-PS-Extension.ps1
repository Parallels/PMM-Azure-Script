#
# SCCM_PS_Extension.ps1
#


# Actions:
# - Install WDS (2. Install WDS Role.ps1)
# - Install SCCM Pre-req (4. Install SCCM prerequisites.ps1)
# - Install WSUS (5. InstallWSUS-ReportViewer2008.ps1)

# Setting variables
$FQDN = $args[0]
$NetBiosDomainName = $args[1]
$SecurePassword = ConvertTo-SecureString -String $args[2] -AsPlainText -Force
$SCCMServer = $args[3]
$ADDSServer = $args[4]
$adminPassword = ConvertTo-SecureString -String $args[5] -AsPlainText -Force
$AdminUser =  $args[6]
$sqlHostName = $Args[7]

#Construct variables
$adHostName = get-content env:computername

#Capture Script Location (because Extension versions may vary)
$CurrentScriptLocation = (Get-Location).path

#Configure logging
function log
{
   param([string]$message)
   "`n`n$(get-date -f o)  $message" 
}

#Disable Defender RealTime Scanning
Set-MpPreference -DisableRealtimeMonitoring $true

#GetSCCMISO
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://pmmazurelabfiles.blob.core.windows.net/pmmaurelabfilescontainer/mu_system_center_configuration_manager_current_branch_version_1802_x86_x64_dvd_12064903.iso" -OutFile "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.9.5\Downloads\0\mu_system_center_configuration_manager_current_branch_version_1802_x86_x64_dvd_12064903.iso"

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
$mycreds = New-Object System.Management.Automation.PSCredential ($AdminUser, $adminPassword)

#Impersonate User
log "Impersonate user '$AdminUser'"
.\New-ImpersonateUser.ps1 -Credential $mycreds

# This configures DHCP according to pages 31 through 45
$ScriptBlockDHCP= {
	param ($NetBiosDomainName, $adIpAddress, $FQDN)

    function log
    {
       param([string]$message)
       "`n`n$(get-date -f o)  $message" 
    }
	
	#Construct variables
	$DHCPScopeFriendlyName = "SCCM LAN"
	$DHCPScopeStartIP = "10.0.66.51"
	$DHCPScopeEndIP = "10.0.66.99"
	$adHostName = get-content env:computername

	#Install the DHCP Feature including the Management Tools
	log "Install the DHCP Feature including the Management Tools"
	Install-WindowsFeature -Name DHCP -IncludeManagementTools

    #Restart the DHCO Service
    net stop DHCPServer | net start DHCPServer

	#Notify Server Manager that Authorization is complete
	log "Notify Server Manager that Authorization is complete"
	Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2

	#Get Current DHCP Bindings
	log "Get Current DHCP Bindings"
	Get-DhcpServerv4Binding

	#Set the Binding state
	log "Set the Binding state"
	Set-DhcpServerv4Binding -BindingState $true -InterfaceAlias "Ethernet"

	#Configure the AD Domain the in DHCP Scope
	log "Configure the AD Domain the in DHCP Scope"
	Add-DhcpServerInDC -DnsName $NetBiosDomainName -IPAddress ((Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin manual).IPAddress)

	#Add DHCP Scope
	log "Add DHCP Scope"
	Add-DhcpServerv4Scope -Name $DHCPScopeFriendlyName -StartRange $DHCPScopeStartIP -EndRange $DHCPScopeEndIP  -SubnetMask 255.255.255.0 
	$ScopeID = Get-DhcpServerv4Scope -ComputerName $adHostName | select Scopeid

	#Set Lease Duration to 7 days
	log "Set Lease Duration to 7 days"
	Set-DhcpServerv4Scope -ComputerName $adHostName -ScopeId $ScopeID[0].ScopeId.IPAddressToString -LeaseDuration 7.00:00:00

	#Configure Dynamic IP Address Assignment type to Both
	log "Configure Dynamic IP Address Assignment type to Both"
	Set-DhcpServerv4Scope -ComputerName $adHostName -ScopeId $ScopeID[0].ScopeId.IPAddressToString -Type both

	#Enable Dynamic DNS Update, and also for client who do not request (older clients)
	log "Enable Dynamic DNS Update, and also for client who do not request (older clients)"
	Set-DhcpServerv4DnsSetting -ComputerName $adHostName -DynamicUpdates Always -UpdateDnsRRForOlderClients $true
}

$session = New-PSSession -cn ($ADDSServer+"."+$FQDN) -Credential $mycreds -Authentication Credssp
Invoke-Command -Session $session -ScriptBlock $ScriptBlockDHCP -ArgumentList $NetBiosDomainName,$adIpAddress,$FQDN
Remove-PSSession -VMName ($ADDSServer+"."+$FQDN)



# This creates AD Extension for SCCM pages 107 through 108 
$ScriptBlockADExtension= {
    function log
    {
       param([string]$message)
       "`n`n$(get-date -f o)  $message" 
    }

	$ImageISOName = "mu_system_center_configuration_manager_current_branch_version_1802_x86_x64_dvd_12064903.iso"

	#Mount disk image SCCM ISO and get the driveletter
	log "Mount disk image SCCM ISO and get the driveletter"
    $InstallPath = "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.9.5\Downloads\0"
	$mountResult = Mount-DiskImage -ImagePath ($InstallPath+'\'+$ImageISOName) -PassThru
	$ISODriveLetter = ($mountResult | Get-Volume).DriveLetter

	#Run the extension
	log "Run the AD extension EXTADSCH.exe"
	$ExtensionExe = $ISODriveLetter+":\SMSSETUP\BIN\X64\extadsch.exe"
	& $ExtensionExe

	#Log the results from the schema extension
	log "Log the results from the schema extension"
	get-content "C:\ExtADSch.log"
}

$session = New-PSSession -cn ($ADDSServer+"."+$FQDN) -Credential $mycreds -Authentication Credssp
Invoke-Command -Session $session -ScriptBlock $ScriptBlockADExtension
Remove-PSSession -VMName ($ADDSServer+"."+$FQDN)



# This creates System Management Contains and sets the necesary permissions and membership pages 108 hrough 117
$ScriptBlockSCCMContainer= {
	param ($SCCMServer)

    function log
    {
       param([string]$message)
       "`n`n$(get-date -f o)  $message" 
    }

	#Import AD Module
	log "Import AD Module"
	Import-Module ActiveDirectory

	#Get Root Domain CN
	$root = (Get-ADRootDSE).defaultNamingContext

	# Create the System Management container
	log "Create the System Management container"
	$ou = New-ADObject -Type Container -name "System Management" -Path "CN=System,$root" -Passthru 

	# Get the current ACL for the OU
	$acl = get-acl "ad:CN=System Management,CN=System,$root"

	# Create a new access control entry to allow access to the OU
	log "Create a new access control entry to allow access to the OU"
	$identity = [System.Security.Principal.IdentityReference] [System.Security.Principal.SecurityIdentifier] (get-adcomputer $env:ComputerName).SID
	$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
	$type = [System.Security.AccessControl.AccessControlType] "Allow"
	$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
	$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType

	# Add the ACE to the ACL, then set the ACL to save the changes
	log "Add the ACE to the ACL, then set the ACL to save the changes"
	$acl.AddAccessRule($ace) 
	Set-acl -aclobject $acl "ad:CN=System Management,CN=System,$root"

	#Add SCCM Server to Administrators group
	log "Add SCCM Server to Administrators group"
	Add-ADGroupMember -Identity "Administrators" -Members ($SCCMServer+"$")
}

$session = New-PSSession -cn ($ADDSServer+"."+$FQDN) -Credential $mycreds -Authentication Credssp
Invoke-Command -Session $session -ScriptBlock $ScriptBlockSCCMContainer -ArgumentList $SCCMServer
Remove-PSSession -VMName ($ADDSServer+"."+$FQDN)



# This Installs and configures WDS according to pages 45 through 59

#Install the WDS Feature including the Management Tools
log "Install WVD"
Install-WindowsFeature wds-deployment -includemanagementtools

#Configure to WDS Service to delay start
log "Configure to WDS Service to delay start"
sc.exe config WDSServer start= delayed-auto

#Wait for the WDS initialization to complete
Start-Sleep -s 90

#Start the WDS Service
log "Start the WDS Service"
net start WDSServer

#Set the Remote Installation Path to C:\RemoteInstall
log "Set the Remote Installation Path to C:\RemoteInstall"
wdsutil /initialize-server /remInst:"C:\RemoteInstall"

#Configure WDS to respond to all Client Computers
log "Configure WDS to respond to all Client Computers"
wdsutil /set-server /AnswerClients:All

#Configure Respone Delay to 1 second
log "Configure Respone Delay to 1 second"
wdsutil /set-server /Responsedelay:1



# This creates the IIS Roles, Features, configurations incl BITS pages 65 through 81

#Install the IIS role including management tools
log "Install the IIS role including management tools"
Install-WindowsFeature -name Web-Server -IncludeManagementTools

log "Enable various IIS Features..."
#Enable Web Server Features
Log "Installing IIS-HttpRedirect"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
Log "Installing IIS-WebDav"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebDav

#Enable application development Features
Log "Installing IIS-ApplicationDevelopment"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
Log "Installing IIS-ASPNET"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET -All
Log "Installing IIS-ASP"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASP -All
Log "Installing Web-Asp-Net45"
Add-WindowsFeature Web-Asp-Net45
Log "Installing Web-Net-Ext45"
Add-WindowsFeature Web-Net-Ext45
Log "Installing IIS-ISAPIExtensions"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
Log "Installing IIS-ISAPIFILTER"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFILTER

#Enable Haalth and Diagnostics Features
Log "Installing IIS-HTTPlogging"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HTTPlogging
Log "Installing IIS-LoggingLibraries"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
Log "Installing IIS-RequestMonitor"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
Log "Installing IIS-HttpTracing"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing

#Enable Security Features
Log "Installing IIS-BasicAuthentication"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
Log "Installing IIS-WindowsAuthentication"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
Log "Installing IIS-URLAuthorization"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-URLAuthorization
Log "Installing IIS-RequestFiltering"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
Log "Installing IIS-IPSecurity"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-IPSecurity

#Enable Managent tools Features
Log "Installing IIS-IIS6ManagementCompatibility"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
Log "Installing IIS-LegacyScripts"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-LegacyScripts -all
Log "Installing IIS-WMICompatibility"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WMICompatibility -all
Log "Installing IIS-ManagementService"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementService
Log "Installing IIS-ManagementScriptingTools"
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools
Log "Installing Web-Lgcy-Mgmt-Console"
Add-WindowsFeature Web-Lgcy-Mgmt-Console

#Enable WebDav Authoring
log "Enable WebDav Authoring"
Set-WebConfigurationProperty -Filter system.webServer/webdav/authoring -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site" -Name Enabled -Value True

#Add new WebDav Authoring rule
log "Add new WebDav Authoring rule"
$newRule = @{
    users="*"
    path="*"
    access="Read"
}
Add-WebConfiguration -Filter system.webServer/webdav/authoringRules -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site" -Value $newRule

#Set Allow Anonymous Property Queries to true
log "Set Allow Anonymous Property Queries to true"
C:\Windows\System32\InetSrv\AppCmd set config "Default Web Site/" /section:system.webServer/webdav/authoring /properties.allowAnonymousPropfind:true /commit:apphost

#Set Allow Custom Propertiess to false
log "Set Allow Custom Propertiess to false"
C:\Windows\System32\InetSrv\AppCmd set config "Default Web Site/" /section:system.webServer/webdav/authoring /properties.allowCustomProperties:false /commit:apphost

#Set Allow Property Queries with Infinite Depth to true
log "Set Allow Property Queries with Infinite Depth to true"
C:\Windows\System32\InetSrv\AppCmd set config "Default Web Site/" /section:system.webServer/webdav/authoring /properties.allowInfinitePropfindDepth:true /commit:apphost

#Enable Windows Authentication on Default Web Site
log "Enable Windows Authentication on Default Web Site"
Set-WebConfigurationProperty -filter "/system.webServer/security/authentication/windowsAuthentication" -name enabled -value true -PSPath "IIS:\" -location "Default Web Site"

#Install Remote Differential Compression feature including management tools
log "Install Remote Differential Compression feature including management tools"
Install-WindowsFeature -name RDC -IncludeManagementTools

#Install BITS feature including management tools
log "Install BITS feature including management tools"
Install-WindowsFeature -name BITS -IncludeManagementTools

#Allow all fileExtensions to be used
log "Allow all fileExtensions to be used"
Start-Sleep -s 30
((Get-Content -path C:\Windows\System32\inetsrv\config\applicationHost.config -Raw) -replace ' allowed="false" />',' allowed="true" />') | Set-Content -Path C:\Windows\System32\inetsrv\config\applicationHost.config




# This Installs and WSUS and ReportViewer 2008 - from PMM-HowtoInstallSCCM2012-051118-1513-16.pdf - pages 92-106

# Variables
$WSUSContentPath = "C:\WSUS"
$TestWSUSContentPath = Test-Path $WSUSContentPath
$WSUSToolsPath = "C:\Program Files\Update Services\Tools\"
$WSUSBPAReport = "WSUS-BPA-Report.txt"

# Log start of WSUS install
log "Begin WSUS install." 

# Make WSUS Directory for storing Content
If($TestWSUSContentPath -eq $true) { 
log "WSUS content path already exists, moving forward" 
} 
Else { 
log "Creating WSUS content directory..." 
New-Item -Path "C:\" -Name WSUS -ItemType Directory 
}

# Install WSUS with Management Tools
log "Install WSUS with Management Tools"
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools

# Define WSUS content directory
cd $WSUSToolsPath
log  "Setting WSUS content path to C:\WSUS." 
.\wsusutil.exe postinstall CONTENT_DIR=C:\WSUS\Content


# Invoke Best Practices Analyzer
log "Invoke Best Practices Analyzer"
Invoke-BpaModel -ModelId Microsoft/Windows/UpdateServices

# Get BPA Report and save to log
log "Get BPA Report and save to log"
Get-BpaResult -ModelId Microsoft/Windows/UpdateServices |  Select Title,Severity,Compliance | Format-List  | Out-file -FilePath $Store$WSUSBPAReport
log  "WSUS is installed." 

# Intall ReportViewer 2008 silently
log "Downloading ReportViewer 2008"
Invoke-WebRequest -Uri "https://download.microsoft.com/download/2/d/8/2d889b35-c4db-49c6-ae19-e5a0c7c2b24d/ReportViewer.exe" -OutFile "C:\Packages\Plugins\ReportViewer.exe"
sleep -Seconds 3
log "Installing ReportViewer 2008"
Start-Process -file msiexec -arg "/i C:\packages\plugins\ReportViewer.exe /q" | Wait-process

#Install ADK
log "Downloading ADK"
Invoke-WebRequest -Uri "http://download.microsoft.com/download/B/E/6/BE63E3A5-5D1C-43E7-9875-DFA2B301EC70/adk/adksetup.exe" -OutFile "C:\Packages\Plugins\adksetup.exe"
sleep -Seconds 3
log "Installing ADK"
$SetupSwitches = "/Features OptionId.DeploymentTools OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off"
Start-Process -FilePath C:\Packages\Plugins\adksetup.exe -ArgumentList $SetupSwitches -NoNewWindow -Wait

#Install WINPE
log "Downloading WINPE"
Invoke-WebRequest -Uri "http://download.microsoft.com/download/D/7/E/D7E22261-D0B3-4ED6-8151-5E002C7F823D/adkwinpeaddons/adkwinpesetup.exe" -OutFile "C:\Packages\Plugins\adkwinpesetup.exe"
sleep -Seconds 3
log "Installing WINPE"
$SetupSwitches = "/Features OptionId.WindowsPreinstallationEnvironment /norestart /quiet /ceip off"
Start-Process -FilePath C:\Packages\Plugins\adkwinpesetup.exe -ArgumentList $SetupSwitches -NoNewWindow -Wait

#Install SCCM
Start-Sleep -s 300
$SCCMSetupScript = "ConfigMgrSetup.ini"
$InstallPath = "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.9.5\Downloads\0"
$ImageISOName = "mu_system_center_configuration_manager_current_branch_version_1802_x86_x64_dvd_12064903.iso"

#Create the necesary SCCM Downloads folder
New-Item -Path C:\Downloads -ItemType Directory

#Mount disk image SCCM ISO and get the driveletter
$mountResult = Mount-DiskImage -ImagePath ($InstallPath+"\"+$ImageISOName) -PassThru
log $mountResult
$ISODriveLetter = ($mountResult | Get-Volume).DriveLetter
log "ISODriveLetter:'$ISODriveLetter'"

#Wait for the mount to complete
log "wait 30 sec to allow ISO mount to complete"
Start-Sleep -s 30

#Update the values inside the .ini file
if ($sqlHostName -ne "sql-01")
{
	$filePath = $CurrentScriptLocation+'\'+'ConfigMgrSetup.ini'
	$tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
	$find = 'sql-01'
	$replace = $sqlHostName
	(Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
	Remove-Item -Path $filePath
	Move-Item -Path $tempFilePath -Destination $filePath
}

if ($SCCMServer -ne "sccm-01")
{
	$filePath = $CurrentScriptLocation+'\'+'ConfigMgrSetup.ini'
	$tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
	$find = 'sccm-01'
	$replace = $SCCMServer
	(Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
	Remove-Item -Path $filePath
	Move-Item -Path $tempFilePath -Destination $filePath
}

if ($FQDN -ne "contoso.com")
{
	$filePath = $CurrentScriptLocation+'\'+'ConfigMgrSetup.ini'
	$tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
	$find = 'contoso.com'
	$replace = $FQDN
	(Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
	Remove-Item -Path $filePath
	Move-Item -Path $tempFilePath -Destination $filePath
}

$SCCMSetupScriptFullPath = $InstallPath + "\" + $SCCMSetupScript
$SCCMInstall = $ISODriveLetter+":\SMSSETUP\BIN\X64\setup.exe"
#Start-Process cmd.exe -ArgumentList "/C $SCCMInstall /script c:\RDSG\SCCMSetupScript.ini"
log "SCCM Install:'$SCCMInstall'"
log "SCCM Scriptpath: '$SCCMSetupScriptFullPath'"
& $SCCMInstall /script $SCCMSetupScriptFullPath

#Wait 1 minute to make sure SCCM Setup created a logfile
Start-Sleep -s 60
$LogFileToCheck = "C:\ConfigMgrSetup.log"
$StringToCheck = "Exiting ConfigMgr Setup Bootstrapper"
$NumberOfLinesToCheck = 5
$Sleeptime = 2
$CheckCount = 0
$Match = 0

log "SCCM-PS-Extension COMPLETED, please wait for SCCM Install to complete ~30 min..."
Do 
    {
    $Selection = Get-Content -Path $LogFileToCheck | Select-Object -Last $NumberOfLinesToCheck 

    If($Find = select-string -pattern $StringToCheck -InputObject $Selection)
    {
        $Match = 1
        log "String '$StringToCheck' was found in $LogFileToCheck, exiting..."
    }     
    else
    {
        $CheckCount++
        log "Now checked $CheckCount times."
        log "String '$StringToCheck' is still not found, seeping for $Sleeptime seconds and then rechecking."
        Start-Sleep -s $Sleeptime # this is where powershell waits for however long we want and then rechecks
  
    }
} While ($Match -ne 1)

#Set Domain Admins and Admin user to role Full Administrators
Remove-ImpersonateUser
$AdminUserUPN = $NetBiosDomainName+"\"+$AdminUser
$DomainAdminsUPN =  $NetBiosDomainName+"\domain admins"
$SCCMServerUPN = $SCCMServer+"."+$FQDN
set-location "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin"
Import-Module .\ConfigurationManager.psd1
New-PSDrive -Name "TST" -PSProvider "AdminUI.PS.Provider\CMSite" -Root $SCCMServerUPN -Description "SCCM TST Site"
CD TST:
New-CMAdministrativeUser -Name $AdminUserUPN -RoleName "Full Administrator"
New-CMAdministrativeUser -Name $DomainAdminsUPN  -RoleName "Full Administrator"
Get-CMAdministrativeUser
