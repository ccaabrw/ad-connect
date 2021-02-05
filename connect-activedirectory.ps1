# connect-activedirectory.ps1
#
# Open a new PowerShell window and connect to active directory

[cmdletbinding()]
param (
    [parameter(position = 0)]
    [string] $user = "ISDccaabrw",
    [parameter(position = 1)]
    [string] $dom = "ad"
)
# todo: add -debug flag

# Needed for SendKeys
add-type -AssemblyName System.Windows.Forms

#$myinvocation | fl

# Self-elevate the script
# http://www.expta.com/2017/03/how-to-self-elevate-powershell-script.html
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + "-user $user -dom $dom"
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

function Decrypt-SecureString {

    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
        [System.Security.SecureString]
        $sstr
    )

    $marshal = [System.Runtime.InteropServices.Marshal]
    $ptr = $marshal::SecureStringToBSTR( $sstr )
    $str = $marshal::PtrToStringBSTR( $ptr )
    $marshal::ZeroFreeBSTR( $ptr )
    $str

    # This can also be done in one line:
    # [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($securestring))
}

####################

Set-Variable d1 "ad.ucl.ac.uk" -option ReadOnly
Set-Variable d2 "adtest.bcc.ac.uk" -option ReadOnly
Set-Variable d3 "addev.ucl.ac.uk" -option ReadOnly


$conn = New-Object -TypeName psobject -Property @{
    user = $user
    domain = switch ($dom) {
        "ad" { $d1 }
        "adtest" { $d2 }
        "addev" { $d3 }
    }
    title = "$dom\$user"
    pw = ""
}

# TODO: Put these encrypted passwords in a separate module
if ($conn.user -match "isdccaabrw") {
    switch ($conn.domain) {
        $d1 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000ef49e31c3e7c3b44" `
            + "90528f350253418e0000000002000000000010660000000100002000000066f8" `
            + "13199bd9baa639065ce5ca7adc563cbd13f20bc3f448d9d1b9d6ea3fe51a0000" `
            + "00000e8000000002000020000000d8f8fa77eb0523c02b779cb505a1093981f0" `
            + "3f2122241ad1ae50c285b53968892000000090c83a43aa9f4690e03e26d2b81e" `
            + "45f41710187cb3b0f58ace3f946c822aa04840000000504f184276b1ac7d8318" `
            + "47af62e7e016581d9132141bc92d4d059f03168804b7f38d96dff7f5b5019d19" `
            + "1f2a9ed456af749f85b4782d261885e16c0738f9c724" | ConvertTo-SecureString
        }
        $d2 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002061d82f9fcba04a" `
            + "96c6346db52b8d9700000000020000000000106600000001000020000000c495" `
            + "6e5b0c995948dd55b8ef77e45f9d9b596af0655cbe2d62ed32fb9a1ab28e0000" `
            + "00000e8000000002000020000000b789953cedebfbc60a16e0f65c6fcdfb026b" `
            + "b634db1d25999cdf09e5b46495ec200000002050a1d9e8461b0673dda8618a2c" `
            + "0123c8fa496892ac1d5335c471cf9510f42b40000000241bcd526bd41ade9fd7" `
            + "18a32bf450e22a94efb23c2ac466efd15771e268d316b6ef89d5eaba504bfcb2" `
            + "12546d0f2a384c694126ef031d9bfbb2cdcb1e2d37ce" | ConvertTo-SecureString
        }
        $d3 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002061d82f9fcba04a" `
            + "96c6346db52b8d9700000000020000000000106600000001000020000000784b" `
            + "73dff892899c66dd61894f293e548bf05d492dc420584c2a6603f84197bb0000" `
            + "00000e8000000002000020000000fa142ee730d1246dcb4d5b28e97bc95de5c7" `
            + "29a13dca863d68db8a04b18560b22000000072c700c003dd50df60a408f837c0" `
            + "9320414b0fe442fde1f0f623cfbdf2a34b0940000000003d8e2c425336cc4b0b" `
            + "5a8b0882a6575575cef80cc82a42e2a8f842e7145f5f12c2a9f758e61107ff43" `
            + "9bcc2b5b8568f872f4eef40af615ab0916cb42361820" | ConvertTo-SecureString
        }
        Default {}
    }
} elseif ($conn.user -match "ccaabrw") {
    switch ($conn.domain) {
        $d1 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002061d82f9fcba04a" `
            + "96c6346db52b8d9700000000020000000000106600000001000020000000721f" `
            + "4e7d8ce14d130ed7d71111de86a254ccdaff4031698a0adee6dcb91210aa0000" `
            + "00000e800000000200002000000051835a1dc5e7980a326ccd424aeb680a86bd" `
            + "1b68a36511dd2ed8a9d0e32222e72000000002e24c003e6ae1bf686b8858d7bd" `
            + "5eb22dd56decc53ef86c1052f3f66b96c48340000000792d6c4ade746be47853" `
            + "a04b43a2861dfe809f84ea91774ef10bb8b1addfafa106e56af9c122dddf9093" `
            + "621dd4b612a18fc18b10b5149a08e9455db75c12d4a5" | ConvertTo-SecureString
        }
        Default {}
    }
}

# todo: call a fixed script and give it the right parameters to setup functions and other setup for the session
# (this script should also work on other domain connected systems)
# this will also contain predefined GUI commands with the correct settings (examples below)
# print the connection information at the start of the window ("Connected to ad.ucl.ac.uk")
# detect whether gitpromptsettings needs tweaking (?)
# the functions performed by this script are all chosen using parameters
# OR perhaps this needs to be a module and then we set a parameter variable once loaded?
# OR a script and a module? [https://powershell.org/forums/topic/declaring-module-parameters/#post-23352]

<#

mmc dsa.msc /domain=ad.ucl.ac.uk
mmc dhcpmgmt.msc /computername ucldhcp01.ad.ucl.ac.uk   [how to find list of authorised servers?]
mmc domain.msc /server=ad.ucl.ac.uk
mmc dssite.msc /domain=ad.ucl.ac.uk
mmc dnsmgmt.msc /computername ad.ucl.ac.uk

function test-credential
function get-passwordexpiry
function code-password
check-admins

#>

$command = '$PSDefaultParameterValues.Add("*-AD*:Server", "' + $conn.domain + '"); ' + `
    '$PSDefaultParameterValues.Add("*-DnsServer*:ComputerName", "' + $conn.domain + '"); ' + `
    '$Host.UI.RawUI.WindowTitle = "' + $conn.title + '"; ' + `
    'cd ' + $env:HOMEDRIVE + $env:HOMEPATH + '\Documents; '

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [System.Convert]::ToBase64String($bytes)

$u = $conn.user + '@' + $conn.domain
#$p = (Decrypt-SecureString $conn.pw) + "`r"
# todo: check for sendkeys escape chars in password and put in braces
# - put this in the code that generates encoded securestring

# https://docs.microsoft.com/en-gb/dotnet/api/system.windows.forms.sendkeys

# for testing purposes:
$conn.user
$conn.domain
$conn.title
$command
""
""
$nothing = Read-Host -prompt "Ready to go"
""
""

#start-process as the specified user and run some commands to setup the session
#also set window title and colours?

# NB: Because this uses SendKeys, this script should be started manually.
# To avoid other windows appearing while we are starting and receiving the input by mistake.

Start-Process -FilePath "runas.exe" -ArgumentList "/noprofile /netonly /user:$u `"powershell -noexit -encodedcommand $encoded`""
Start-Sleep -Milliseconds 500
[System.Windows.Forms.SendKeys]::SendWait((Decrypt-SecureString $conn.pw) + "`r")


# links:
# https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mmc
# http://www.primemsp.com/content/msc_Shortcuts.aspx
# https://ss64.com/nt/syntax-mmc.html

# todo: sport through this list to find useful ones

<#

AD Domains and Trusts
 domain.msc
 
Active Directory Management
 admgmt.msc
 
AD Sites and Serrvices
 dssite.msc
 
AD Users and COmputers
 dsa.msc
 
ADSI Edit
 adsiedit.msc
 
Authorization manager
 azman.msc
 
Certification Authority Management
 certsrv.msc
 
Certificate Templates
 certtmpl.msc
 
Cluster Administrator
 cluadmin.exe
 
Computer Management
 compmgmt.msc
 
Component Services
 comexp.msc
 
Configure Your Server
 cys.exe
  
Device Manager
 devmgmt.msc
 
DHCP Managment
 dhcpmgmt.msc
 
Disk Defragmenter
 dfrg.msc
 
Disk Manager
 diskmgmt.msc
 
Distributed File System
 dfsgui.msc
 
DNS Managment
 dnsmgmt.msc
  
Event Viewer
 eventvwr.msc
  
Indexing Service Management
 ciadv.msc
 
IP Address Manage
 ipaddrmgmt.msc
  
Licensing Manager
 llsmgr.exe
 
Local Certificates Management
 certmgr.msc
 
Local Group Policy Editor
 gpedit.msc
 
Local Security Settings Manager
 secpol.msc
 
Local Users and Groups Manager
 lusrmgr.msc
 
Network Load balancing
 nlbmgr.exe
  
Performance Montior
 perfmon.msc
 
PKI Viewer
 pkiview.msc
 
Public Key Managment
 pkmgmt.msc
  
QoS Control Management
 acssnap.msc
  
Remote Desktops
 tsmmc.msc
 
Remote Storage Administration
 rsadmin.msc
 
Removable Storage 
 ntmsmgr.msc
 
Removalbe Storage Operator Requests
 ntmsoprq.msc
 
Routing and Remote Access Manager
 rrasmgmt.msc
 
Resultant Set of Policy
 rsop.msc
  
Schema management
 schmmgmt.msc
 
Services Management
 services.msc
 
Shared Folders
 fsmgmt.msc
 
SID Security Migration
 sidwalk.msc
  
Telephony Management
 tapimgmt.msc
  
Terminal Server Configuration
 tscc.msc
 
Terminal Server Licensing 
 licmgr.exe
 
Terminal Server Manager
 tsadmin.exe
  
UDDI Services Managment
 uddi.msc
  
Windows Mangement Instumentation
 wmimgmt.msc
  
WINS Server manager
 winsmgmt.msc

#>
