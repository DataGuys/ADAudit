# ADAudit

Run AD Audit OneLiner
Run from elevated CMD
# Stable Version

```cmd
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/DataGuys/ADAudit/refs/heads/main/ADAuditComprehensiveV4.ps1 | iex'"
```
# Beta Version 
```cmd
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/DataGuys/ADAudit/refs/heads/main/ADAuditComprehensiveV5.ps1 | iex'"
```
## Most of the CSV exports will end up in a folder off the root C:\ADHealthCheck
