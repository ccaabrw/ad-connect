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
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002d3b54d9c8a96142" `
            + "9e175fce79b715b30000000002000000000010660000000100002000000081b2" `
            + "f3493cb5e463227c06a3429dcd8a692ebd52ffbefbc1abc4e8c6f8d459360000" `
            + "00000e8000000002000020000000fdcf872282aaf7ded20d1decbbe13cee11f2" `
            + "9d5070152c72b61c9d462d8ef169200000006be5e5332f39198dba78f2a78069" `
            + "0ff9e03c7a843f0be3198cb56413154a6cd0400000006f2f08fdf371ee5100b5" `
            + "78d8093f572fed9eb23a220c9d03640f9c668e08d06fc198f0ff2e8911844a90" `
            + "4ac97736d05e62db90994df637bde85c10d943be2dc3" | ConvertTo-SecureString
        }
        $d2 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002d3b54d9c8a96142" `
            + "9e175fce79b715b300000000020000000000106600000001000020000000113b" `
            + "c596cae558fecab21c7919e94699c7f18fc85169feebd44895e7228fe3a60000" `
            + "00000e8000000002000020000000bb713f17406e6e93d84ff2981cdc0d759493" `
            + "2d7b943e3fef19176a0d246f271a20000000a009f5a8622245609d407f7dc787" `
            + "32989142efb6722ead5c56163e2cfe0dedaa400000008e7214f3784e481ad304" `
            + "b639aec47bc1d6fd19f8bd4f5706900e0f64b8aa6724251934de02f3bdda8579" `
            + "68ad3a32aad320f739a6abc38cd6417e9a9502979d24" | ConvertTo-SecureString
        }
        $d3 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002d3b54d9c8a96142" `
            + "9e175fce79b715b30000000002000000000010660000000100002000000074a4" `
            + "8e4f9ab1d823be1413b695172450968553af492b47c9f167aaa94b8b02d40000" `
            + "00000e8000000002000020000000f87a340ac295b88d23c503ad2e9ec8009375" `
            + "a4b64f91eecfba78438a4ae5d5ad20000000f0770b72f8d2c10582f2af4c0183" `
            + "acaac8291ba560d19f6ffa66b6aee66c989840000000ce86860c1c4436e2e64b" `
            + "9518262920d89063c0f0ddc653ad59a5d6bfa7b44114882e14c0562b5167db82" `
            + "e97862dfb73dc4d6885d31639df666715508f969cef6" | ConvertTo-SecureString
        }
        Default {}
    }
} elseif ($conn.user -match "ccaabrw") {
    switch ($conn.domain) {
        $d1 { $conn.pw = `
            "01000000d08c9ddf0115d1118c7a00c04fc297eb010000002d3b54d9c8a96142" `
            + "9e175fce79b715b300000000020000000000106600000001000020000000c899" `
            + "1d849b39ca81c9e07c64b93578105de2809c69c4d22c281aceded33781320000" `
            + "00000e8000000002000020000000d4bb5c634a35954e0a0513251acde93b26d3" `
            + "d165c9782f1eba652e738c28a9862000000001b1e075c3b6ce9405e43515416a" `
            + "a7db256366f34a0f5423f0dd1ad852c3538d400000008e4f62253dd2fa1fe4c8" `
            + "8ffd01d0490d31527a7260e4f5e837c918e935c9aeaee5a3831e7eea17274398" `
            + "80d50ea400b133b456dc05fd051102295b95dca02c1d" | ConvertTo-SecureString
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
