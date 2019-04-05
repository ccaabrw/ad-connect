connect-activedirectory.ps1
===========================

Use to connect to AD services using PowerShell.
Opens an appropriate PS window with specified credentials.

Predefined credentials are stored in the script (as securestring).

TODO:
Move creds to a separate module which users can then populate with their own.

Block user input while automating password entry:
https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/blocking-user-input

Authenticate using an SSH key?


List the GUI tools and their arguments (populate a number of variables from within a script that is run for the session)


EXAMPLE USAGE (current implementation):

Open elevated powershell
cd \users\ccaabrw\documents\gitdcs\ad-connect
.\connect-activedirectory.ps1
.\connect-activedirectory.ps1 -dom adtest
.\connect-activedirectory.ps1 -dom addev

From each window:
. .\ad-function.ps1
