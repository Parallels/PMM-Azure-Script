<#
.SYNOPSIS
Impersonates another user on a local machine or Active Directory.

.DESCRIPTION
New-ImpersonateUser uses the LogonUser method from the advapi32.dll to get a token that can then be used to call the WindowsIdentity.Impersonate method in order to impersonate another user without logging off from the current session.  You can pass it either a PSCredential or each field separately. Once impersonation is done, it is highly recommended that Remove-ImpersonateUser (a function added to the global scope at runtime) be called to revert back to the original user. 

.PARAMETER Credential
The PS Credential to be used, eg. from Get-Credential

.PARAMETER Username
The username of the user to impersonate.

.PARAMETER Domain
The domain of the user to impersonate.  If the user is local, use the name of the local computer stored in $env:COMPUTERNAME

.PARAMETER Password
The password of the user to impersonate.  This is in cleartext which is why sending a PSCredential is recommended.

.PARAMETER Quiet
Using the Quiet parameter will force New-ImpersonateUser to have no outputs.

.INPUTS
None.  You cannot pipe objects to New-ImpersonateUser

.OUTPUTS
System.String
By default New-ImpersonateUser will output strings confirming Impersonation and a reminder to revert back.

None
The Quiet parameter will force New-ImpersonateUser to have no outputs.

.EXAMPLE
PS C:\> New-ImpersonateUser -Credential (Get-Credential)

This command will impersonate the user supplied to the Get-Credential cmdlet.
.EXAMPLE
PS C:\> New-ImpersonateUser -Username "user" -Domain "domain" -Password "password"

This command will impersonate the user "domain\user" with the password "password."
.EXAMPLE
PS C:\> New-ImpersonateUser -Credential (Get-Credential) -Quiet

This command will impersonate the user supplied to the Get-Credential cmdlet, but it will not produce any outputs.
.NOTES
It is recommended that you read some of the documentation on MSDN or Technet regarding impersonation and its potential complications, limitations, and implications.
Author:  Chris Carter
Version: 1.0

.LINK
http://msdn.microsoft.com/en-us/library/chf6fbt4(v=vs.110).aspx (Impersonate Method)
http://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx (LogonUser function)
Add-Type

#>

#Requires -Version 2.0
#Add common parameters
[CmdletBinding(DefaultParameterSetName="Credential")]

Param(
    [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Username,
    [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Domain,
    [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Password,
    [Parameter(ParameterSetName="Credential", Mandatory=$true, Position=0)][PSCredential]$Credential,
    [Parameter()][Switch]$Quiet
)

#Import the LogonUser Function from advapi32.dll and the CloseHandle Function from kernel32.dll
Add-Type -Namespace Import -Name Win32 -MemberDefinition @'
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
'@

#Set Global variable to hold the Impersonation after it is created so it may be ended after script run
$Global:ImpersonatedUser = @{}
#Initialize handle variable so that it exists to be referenced in the LogonUser method
$tokenHandle = 0

#Pass the PSCredentials to the variables to be sent to the LogonUser method
if ($Credential) {
    Get-Variable Username, Domain, Password | ForEach-Object {
        Set-Variable $_.Name -Value $Credential.GetNetworkCredential().$($_.Name)}
}

#Call LogonUser and store its success.  [ref]$tokenHandle is used to store the token "out IntPtr token" from LogonUser.
$returnValue = [Import.Win32]::LogonUser($Username, $Domain, $Password, 2, 0, [ref]$tokenHandle)

#If it fails, throw the verbose with the error code
if (!$returnValue) {
    $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    Write-Host "Impersonate-User failed a call to LogonUser with error code: $errCode"
    throw [System.ComponentModel.Win32Exception]$errCode
}
#Successful token stored in $tokenHandle
else {
    #Call the Impersonate method with the returned token. An ImpersonationContext is returned and stored in the
    #Global variable so that it may be used after script run.
    $Global:ImpersonatedUser.ImpersonationContext = [System.Security.Principal.WindowsIdentity]::Impersonate($tokenHandle)
    
    #Close the handle to the token. Voided to mask the Boolean return value.
    [void][Import.Win32]::CloseHandle($tokenHandle)

    #Write the current user to ensure Impersonation worked and to remind user to revert back when finished.
    if (!$Quiet) {
        Write-Host "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        Write-Host "It is very important that you call Remove-ImpersonateUser when finished to revert back to your user." `
            -ForegroundColor DarkYellow -BackgroundColor Black
    }
}

#Clean up sensitive variables
$Username = $Domain = $Password = $Credential = $null

#Function put in the Global scope to be used when Impersonation is finished.
Function Global:Remove-ImpersonateUser {
    <#
    .SYNOPSIS
    Used to revert back to the orginal user after New-ImpersonateUser is called. You can only call this function once; it is deleted after it runs.

    .INPUTS
    None.  You cannot pipe objects to Remove-ImpersonateUser

    .OUTPUTS
    None.  Remove-ImpersonateUser does not generate any output.
    #>

    #Calling the Undo method reverts back to the original user.
    $ImpersonatedUser.ImpersonationContext.Undo()

    #Clean up the Global variable and the function itself.
    Remove-Variable ImpersonatedUser -Scope Global
    Remove-Item Function:\Remove-ImpersonateUser
}
