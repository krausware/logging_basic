#Most common avenues of attack as seen by: Mitre ATTACK framework
#1 Process injection
#2 Powershell
#3 Credential Dumping
#4 Maquerading
#5 Command-Line iterface
#6 Scipting
#7 Scheduled Task
#8 REgistry Run Keys / Startup FOlder
#9 System information Discovery
#10 Disabling Secuirty tools

#set the flag to alert that we have big problems 
$critical = 0

$today = (Get-Date).ToString("yyyMMdd") + '.txt'
New-Item -Name $today -Path C:\temp

$logloc = C:\temp\$today

#1

#2
#looks for event 4014 for a process being loaded
#Microsoft-Windows-PowerShell/OperationalMicrosoft-Windows-PowerShell/Operational
#Turn on Powershell Script Block Logging
#administrative Templates > windows COmponents > windows Powershell
#detection:
#    selection:
#        EventID: 4104
#    keyword1:
#        - '*kernel32.dll*'
#    keyword2:
#        - '*LoadLibraryA*'
#    keyword3:
#        - '*GetProcAddress*'
#    keyword4:
#        - '*VirtualAlloc*'
#    condition: All of them
Get-EventLog -LogName 'Windows Powershell' -After (Get-Date).Adddays(-1) | foreach{ if($_.InstanceId -eq 4104){ 
Add-Content -Value $_.Message -Path $logloc
$critical = 1}}

#3 etc


#alert
#group policy logon script will parse and warn user
if ($critical -eq 1){Add-Content -Value "DANGERDANGER" -Path $logloc}

$auditbox = '\netman\c$\audit', '\netman2\c$\audit', '\unc-aud\c$\audit'

$auditbox | foreach{Copy-Item $logloc -Destination $_} 

