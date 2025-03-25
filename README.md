# ADAudit

Run AD Audit OneLiner
Run from elevated CMD or PowerShell Terminal
# Stable Version

```cmd
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/DataGuys/ADAudit/refs/heads/main/ADAuditComprehensiveV4.ps1 | iex'"
```
# Beta Version 
```cmd
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/DataGuys/ADAudit/refs/heads/main/ADAuditComprehensiveV5.ps1 | iex'"
```
## Most of the CSV exports will end up in a folder off the root C:\ADHealthCheck

| Source | Recommendation | FGPP Example | Rationale |
|--------|----------------|-------------|-----------|
| Microsoft Learn (Max password age) | 30–90 days | Default Domain Policy = 42 days | Balances risk of compromise vs. user friction; aligns with most compliance frameworks |
| Lepide FGPP Best Practices | Privileged accounts get shorter lifespans | Domain Admins = 30 days<br>Enterprise Admins = 15 days | Limits exposure window for high‑value targets |
| NIST SP 800‑63B | Do **not** require periodic expiration; change only on evidence of compromise | N/A | Frequent resets encourage weak, predictable passwords; event‑driven rotation is more secure |
| SpecOps Password Guidelines | If expiration is used, consider long intervals (365+ days) when paired with MFA and breach‑list checks | N/A | Reduces “password fatigue” while still limiting exposure if a breach occurs |

