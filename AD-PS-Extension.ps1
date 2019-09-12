#
# AD_PS_Extension.ps1
#

# Actions:
# - Install ADDS & DNS (buildad.ps1)
# - Install DHCP (1. Install DHCP Role.ps1)
# - Create Service Accounts (3. Create SCCM Service accounts.ps1)
# - Create the SCCM AD Schema Extension (6 AD Schema Extension for SCCM. .ps1)
# - SCCM Container & Site Server Groups (7. SCCM prerequisites(container and  Site Server to Group).ps1)

# Setting variables
$FQDN = $args[0]
$NetBiosDomainName = $args[1]
$SecurePassword = ConvertTo-SecureString -String $args[2] -AsPlainText -Force

#Capture Script Location (because Extension versions may vary)
$CurrentScriptLocation = (Get-Location).path

#Configure logging
function log
{
   param([string]$message)
   "`n`n$(get-date -f o)  $message" 
}

Function SwitchDHCPToStatic{
    $CurrentIP = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp
	$adIpAddress = $CurrentIP.IPAddress
    $adIpAddress = $CurrentIP.IPAddress
    $CurrentGateway = (Get-NetIPConfiguration -InterfaceIndex $CurrentIP.InterfaceIndex).IPv4DefaultGateway.NextHop
    $CurrentDNS = ((Get-NetIPConfiguration -InterfaceIndex $CurrentIP.InterfaceIndex).DNSServer |
            Where-Object AddressFamily -eq 2).ServerAddresses
    Set-NetIPInterface -InterfaceIndex $CurrentIP.InterfaceIndex -Dhcp Disabled
    $Params = @{
        IPAddress      = $CurrentIP.IPAddress
        InterfaceAlias = $CurrentIP.InterfaceAlias
        Type           = $CurrentIP.Type
        PrefixLength   = $CurrentIP.PrefixLength
    }
    New-NetIPAddress @Params
    $Params = @{
        InterfaceIndex    = $CurrentIP.InterfaceIndex
        DestinationPrefix = '0.0.0.0/0'
        AddressFamily     = 'IPv4'
        NextHop           = $CurrentGateway
    }
    New-NetRoute @Params
    Set-DnsClientServerAddress -InterfaceIndex $CurrentIP.InterfaceIndex -ServerAddresses $CurrentDNS
}

#Disable Defender RealTime Scanning
Set-MpPreference -DisableRealtimeMonitoring $true

#Change the current DHCP IP address to Fixed IP Address
log "Change the current DHCP IP address to Fixed IP Address"
SwitchDHCPToStatic

# Configure Active Directory and DNS
log "Configure Active Directory and DNS"
Install-WindowsFeature AD-Domain-Services
Install-WindowsFeature RSAT-AD-AdminCenter
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DomainMode "7" `
-DomainName $FQDN `
-DomainNetbiosName $NetBiosDomainName `
-ForestMode "7" `
-InstallDns:$true `
-SafeModeAdministratorPassword $SecurePassword `
-NoRebootOnCompletion:$true `
-Force:$true

#Enable CredSSP to allow Multiple HOP Remote PowerShell
log "Configuring WSMAN"
Enable-WSManCredSSP -Role Server -Force
Enable-WSManCredSSP -Role Client -DelegateComputer ("*."+$FQDN) -Force
Enable-PSRemoting -force
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force

#Set policy "Allow delegating fresh credentials with NTLM-only server authentication" 
$allowed = @('WSMAN/*.'+$FQDN)
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

# Done
log "Restart in 10 sec!!"
sleep -Seconds 10
Restart-Computer

log "ADDS-PS-Extension COMPLETED"


