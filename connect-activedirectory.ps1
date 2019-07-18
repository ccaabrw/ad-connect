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
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002061d82f9fcba04a" `
            + "96c6346db52b8d97000000000200000000001066000000010000200000008b7d" `
            + "a2926a9a9a096613238af3987dccc727df575f452584858240bfc0ec5d380000" `
            + "00000e8000000002000020000000022d50df5e04781dcfc5dbc2b01b92323640" `
            + "7728c86b3593f5edb4c84cb1ed15200000009755637748fc55786dc53365f746" `
            + "2a7989150262b7ba10885aa0b3bd9a3928e74000000076c62130a1ac78375dd3" `
            + "cd6c31731d70f6a16d32182f918048802dd4e53e52049bae709ce6683def1f87" `
            + "b80fc8549b57922dcd677a0d0e7abad6eb35b242cd77" | ConvertTo-SecureString
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
            + "96c6346db52b8d97000000000200000000001066000000010000200000001c98" `
            + "3892715cb20d5c5e00b8d0114ee77364de530f93d6075ecfaf79a46519250000" `
            + "00000e8000000002000020000000e78cac9050b30490b34c58e551dda44543ec" `
            + "76db9a1fedd8fb01a5b0d5fb79ca20000000815a0952abfcb2575f7c8bc6a000" `
            + "07e0fa1ab161887712fa0fb47fb2aad859cb40000000dc18f7da2199dbc2fad2" `
            + "8a568e3f85a62b064ca4a8f222b1bd51c22ffc58c5962daece28f601aea8a964" `
            + "948bd5a4c3d0feaad214aae630c3ce3df64aa5986f32" | ConvertTo-SecureString
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
