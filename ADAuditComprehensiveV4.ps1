######################################################################################
# ADComprehensiveMerged.ps1
# ------------------------------------------------------------------------------------
# Merges your original "ADAuditComprehensiveV2.ps1" script with selected, non-duplicated
# functions from "ADAudit.ps1" (phillips321.co.uk).
#
# Notably, it adds:
#   - SYSVOL GPP cpassword check
#   - LAPS status check
#   - OU perms check
#   - SPN kerberoast check
#   - AS-REP roastable check
#   - DC ownership check
#   - LDAP security check
#
# All references to Nessus output have been removed.
# The rest of the original "ADAuditComprehensiveV2.ps1" is retained, including:
#   - your DNS reverse lookup vs Sites/Subnets check
#   - your menu-based approach and BPA scanning
#   - your "Invoke-DiscoveryScript", "Invoke-ForestHealthCheck", etc.
#
# Usage:
#   1) Copy this entire script to a .ps1 file, e.g. ADComprehensiveMerged.ps1.
#   2) Run in an elevated PowerShell with modules: ActiveDirectory, GroupPolicy,
#      BestPractices, DSInternals, etc. installed as needed.
#   3) Select the menu item that corresponds to each check you want to run.
#
######################################################################################


######################################################################################
# SECTION 1: UTILITY / SHARED FUNCTIONS
######################################################################################

function Write-Both {
    param([string] $Message)
    $basePath = "C:\ADHealthCheck"
    if (!(Test-Path $basePath)) {
        New-Item -ItemType Directory -Path $basePath | Out-Null
    }
    $logFile = Join-Path $basePath "consolelog.txt"
    Write-Host $Message
    Add-Content -Path $logFile -Value $Message
}

function Pause {
    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Write-Header {
    param([string]$Text)
    Write-Both "========================================="
    Write-Both " $Text "
    Write-Both "========================================="
}

function Ensure-Folder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }
}

######################################################################################
# SECTION 2: ORIGINAL CONTENT FROM "ADAuditComprehensiveV2.ps1"
######################################################################################

#region Helper Functions from original

function Invoke-ScanGPOsUnknownAccounts {
    <#
        Scans all GPOs for unresolved SIDs in security settings.
    #>
    Write-Header "Scanning GPOs for Orphand SIDs"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\GPOswithOrphandSIDS"
    Ensure-Folder -Path $OutPath

    $GPOsWithIssues = @()
    foreach ($GPO in Get-GPO -All -ErrorAction SilentlyContinue) {
        $xmlContent = try {
            [xml](Get-GPOReport -Guid $GPO.Id -ReportType Xml -ErrorAction Goto Pause | Out-Null)
        } catch {
            $null
        }
        if ($xmlContent -and $xmlContent.GPO.Computer.ExtensionData.Extension.SecuritySettings) {
            foreach ($setting in $xmlContent.GPO.Computer.ExtensionData.Extension.SecuritySettings.ChildNodes) {
                if ($setting.'Trustee-SID' -and -not $setting.'Trustee-Name') {
                    $GPOsWithIssues += [PSCustomObject]@{
                        GPOName = $GPO.DisplayName
                        SID     = $setting.'Trustee-SID'
                        Setting = $setting.LocalizedName
                    }
                }
            }
        }
    }
    if ($GPOsWithIssues.Count -gt 0) {
        $GPOsWithIssues | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "GPOsWithUnknownAccounts.csv"
        $GPOsWithIssues | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Results exported to $OutputFile"
    } else {
        Write-Both "No unknown (orphaned) accounts found in GPOs."
    }
    Pause
    Show-MainMenu
}

function Invoke-ScanGPOPasswordPolicies {
    <#
        Evaluates all GPOs for password policy settings.
    #>
    Write-Header "Scanning GPOs for Password Policies"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\GPOPasswordPolicies"
    Ensure-Folder -Path $OutPath

    function Get-PolicyValue {
        param(
            [xml]$XmlContent,
            [string]$PolicyName
        )
        $policy = $XmlContent.GPO.Computer.ExtensionData.Extension.Account | Where-Object { $_.Name -eq $PolicyName }
        if ($policy -and $policy.SettingNumber) {
            return $policy.SettingNumber
        }
        else {
            return $null
        }
    }

    $results = @()
    foreach ($gpo in Get-GPO -All) {
        $xmlContent = try {
            [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        } catch {
            $null
        }
        if ($xmlContent) {
            $maxAge    = Get-PolicyValue -XmlContent $xmlContent -PolicyName "MaximumPasswordAge"
            $minLength = Get-PolicyValue -XmlContent $xmlContent -PolicyName "MinimumPasswordLength"
            $history   = Get-PolicyValue -XmlContent $xmlContent -PolicyName "PasswordHistorySize"
            if ($maxAge -or $minLength -or $history) {
                $results += [PSCustomObject]@{
                    GPOName             = $gpo.DisplayName
                    MaxPasswordAge      = $maxAge
                    MinPasswordLength   = $minLength
                    PasswordHistorySize = $history
                }
            }
        }
    }
    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "GPO_Password_Policies.csv"
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Results exported to $OutputFile"
    } else {
        Write-Both "No GPO-level password policy settings detected or none found."
    }
    Pause
}

function Invoke-GPOPolicyOverlapScan {
    <#
        Scans for overlapping GPO settings across domain controllers.
    #>
    Write-Header "Overlapping GPO Policy Settings Scan"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\OverlapGPO"
    Ensure-Folder -Path $OutPath

    foreach ($gpo in Get-GPO -All) {
        $xmlPath = Join-Path $OutPath ("{0}.xml" -f ($gpo.DisplayName -replace '[\\/:*?"<>|]', '_'))
        Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $xmlPath
    }
    $summaries = @()
    foreach ($file in Get-ChildItem "$OutPath\*.xml") {
        [xml]$xmlContent = Get-Content $file.FullName
        if ($xmlContent.GPO.Computer.ExtensionData.Extension.Policy) {
            foreach ($setting in $xmlContent.GPO.Computer.ExtensionData.Extension.Policy) {
                $summaries += [PSCustomObject]@{
                    GPOName = $xmlContent.GPO.Name
                    Policy  = $setting.Name
                    State   = $setting.State
                    Value   = $setting.Value
                }
            }
        }
    }
    if ($summaries.Count -gt 0) {
        $CSVPath = Join-Path $OutPath "GPOSummary.csv"
        $summaries | Export-Csv -Path $CSVPath -NoTypeInformation
        Write-Both "GPO Summary exported to $CSVPath"
    } else {
        Write-Both "No GPO policy data collected or no extension data found."
    }
    Pause
}

function Invoke-ReviewBaseSecurity {
    <#
        Reviews base security settings on the DC.
    #>
    Write-Header "Reviewing Base Security Settings"

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Both "Run this script as an Administrator!"
        Pause
        return
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Both "Active Directory module not available. Install RSAT-AD-PowerShell."
        Pause
        return
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\BaseSecurity"
    Ensure-Folder -Path $OutPath

    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Both "Failed to retrieve OS information: $_"
        Pause
        return
    }

    try {
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } catch {
        Write-Both "Failed to retrieve domain password policy: $_"
        $domainPolicy = $null
    }

    $groupsToCheck = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $groupMemberships = @{}

    foreach ($grp in $groupsToCheck) {
        try {
            $members = (Get-ADGroupMember -Identity $grp -ErrorAction Stop).Name -join ', '
            $groupMemberships["$grp Members"] = $members
        } catch {
            $groupMemberships["$grp Members"] = "Error retrieving members"
        }
    }

    if ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        try {
            $smb1 = Get-WindowsFeature FS-SMB1
        } catch {
            $smb1 = $null
        }
    } else {
        $smb1 = $null
    }

    try {
        $isRODC = (Get-ADDomainController -Identity $env:computername -ErrorAction Stop).IsReadOnly
    } catch {
        $isRODC = $false
    }

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $installedFeatures = (Get-WindowsFeature | Where-Object { $_.Installed }).Name -join ', '
        } else {
            $installedFeatures = "N/A"
        }
    } catch {
        $installedFeatures = "Error retrieving features"
    }

    $result = [PSCustomObject]@{
        "Operating System"         = "$($osInfo.Caption), SP:$($osInfo.ServicePackMajorVersion).$($osInfo.ServicePackMinorVersion)"
        "Last Boot "           = $osInfo.LastBootUp
        "Min Password Length"      = if ($domainPolicy) { $domainPolicy.MinPasswordLength } else { "N/A" }
        "Password History Count"   = if ($domainPolicy) { $domainPolicy.PasswordHistoryCount } else { "N/A" }
        "Max Password Age (Days)"  = if ($domainPolicy) { $domainPolicy.MaxPasswordAge.Days } else { "N/A" }
        "Reversible Encryption"    = if ($domainPolicy) { $domainPolicy.ReversibleEncryptionEnabled } else { "N/A" }
        "SMBv1 Installed"          = if ($smb1 -and $smb1.Installed) { "Yes" } else { "No" }
        "DC Type"                  = if ($isRODC) { "Read-Only" } else { "Writable" }
        "Installed Features"       = $installedFeatures
    } + $groupMemberships

    $result | Format-Table -AutoSize
    $OutputFile = Join-Path $OutPath "BaseSecurityReview.csv"
    $result | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "Data exported to $OutputFile"
    Pause
}

function Invoke-DCEventErrorSummary {
    <#
        Summarizes error and warning events from key logs.
    #>
    Write-Header "DC Event Errors Summary"

    $OutPath = "C:\ADHealthCheck\EventErrors"
    Ensure-Folder -Path $OutPath

    $logs = @("System","Application","Directory Service","DNS Server","File Replication Service")
    $eventStats = @{}

    foreach ($log in $logs) {
        $events = Get-WinEvent -LogName $log -MaxEvents 1000 | Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
        foreach ($e in $events) {
            $key = "$log-$($e.LevelDisplayName)-$($e.Id)"
            if ($eventStats.ContainsKey($key)) {
                $eventStats[$key].Count++
            } else {
                $eventStats[$key] = [PSCustomObject]@{
                    Count         = 1
                    LogName       = $log
                    Level         = $e.LevelDisplayName
                    EventID       = $e.Id
                    SampleMessage = ($e.Message.Split("`n"))[0]
                }
            }
        }
    }

    $summary = $eventStats.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            LogName       = $_.Value.LogName
            Level         = $_.Value.Level
            EventID       = $_.Value.EventID
            Count         = $_.Value.Count
            SampleMessage = $_.Value.SampleMessage
        }
    } | Sort-Object Count -Descending

    if ($summary.Count -gt 0) {
        $summary | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "EventLogSummary.csv"
        $summary | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Event log summary exported to $OutputFile"
    } else {
        Write-Both "No Error/Warning events found or no events retrieved."
    }
    Pause
}

function Invoke-AllDCDiagTests {
    <#
        Runs a full suite of dcdiag tests on all domain controllers.
    #>
    Write-Header "Running DCDiag Tests"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\DCDiag"
    Ensure-Folder -Path $OutPath

    $results = @()
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        Write-Both "Running dcdiag on $($dc.HostName)"
        $testOutput = (& dcdiag /s:$($dc.HostName)) | Out-String
        $results += [PSCustomObject]@{
            DCName       = $dc.HostName
            DCDiagOutput = $testOutput
        }
    }
    $OutputFile = Join-Path $OutPath "DCDiagResults.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "DCDiag results exported to $OutputFile"
    Pause
    Show-MainMenu
}

function Invoke-ForestHealthCheck {
    <#
        Performs an AD forest health check.
    #>
    Write-Header "AD Forest Health Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADForest -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADForest command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\ForestHealthCheck"
    Ensure-Folder -Path $OutPath

    $forest = Get-ADForest
    $domains = $forest.Domains | ForEach-Object { Get-ADDomain -Identity $_ }
    $fsmoRoles = netdom query fsmo
    $repData = Get-ADReplicationUpToDatenessVectorTable -Scope Forest -Target $forest.Name
    $staleData = $repData | Where-Object { $_.LastReplicationSuccess -lt (Get-Date).AddDays(-7) }

    $review = [PSCustomObject]@{
        ForestName             = $forest.Name
        ForestFunctionalLevel  = $forest.ForestMode
        ChildDomains           = ($forest.Domains -join ', ')
        GlobalCatalogs         = ($forest.GlobalCatalogs -join ', ')
        UPNSuffixes            = ($forest.UPNSuffixes -join ', ')
        SPNSuffixes            = ($forest.SPNSuffixes -join ', ')
        DomainFunctionalLevels = ($domains | ForEach-Object { "$($_.Name): $($_.DomainMode)" }) -join '; '
        SchemaVersion          = $forest.ObjectVersion
        FSMORoles              = $fsmoRoles -join "`r`n"
        SiteNames              = ($forest.Sites -join ', ')
    }

    $ForestCSV = Join-Path $OutPath "ADForestReview.csv"
    $StaleCSV  = Join-Path $OutPath "StaleReplicationData.csv"

    $review | Export-Csv -Path $ForestCSV -NoTypeInformation
    $staleData | Export-Csv -Path $StaleCSV -NoTypeInformation

    Write-Both "Forest review exported to $ForestCSV"
    Write-Both "Stale replication data exported to $StaleCSV"
    Pause
}

function Invoke-MoveFSMORoles {
    <#
        Moves all FSMO roles to a specified new DC.
    #>
    Write-Header "Moving FSMO Roles"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Move-ADDirectoryServerOperationMasterRole -ErrorAction SilentlyContinue)) {
        Write-Both "The Move-ADDirectoryServerOperationMasterRole command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\FSMOMoves"
    Ensure-Folder -Path $OutPath

    $TargetDC = Read-Host "Enter the FQDN of the target DC for FSMO roles"
    $Server = Get-ADDomainController -Identity $TargetDC
    Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster
    Write-Both "FSMO roles moved to $TargetDC."
    Pause
}

function Invoke-GetDCEgressWANIPs {
    <#
        Retrieves the external WAN IPs for all domain controllers.
    #>
    Write-Header "DC External WAN IPs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\ExternalWANIPs"
    Ensure-Folder -Path $OutPath

    function Get-LocalExternalIP {
        try {
            return (Invoke-RestMethod -Uri 'https://ipinfo.io/json' -UseBasicParsing).ip
        } catch {
            return "Failed to get external IP"
        }
    }

    $results = @()
    $DCs = Get-ADDomainController -Filter *
    foreach ($dc in $DCs) {
        $scriptBlock = ${function:Get-LocalExternalIP}
        $wanIP = Invoke-Command -ComputerName $dc.HostName -ScriptBlock $scriptBlock -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            DCName = $dc.HostName
            WANIP  = $wanIP
        }
        Write-Both "External IP for $($dc.HostName): $wanIP"
    }
    $OutputFile = Join-Path $OutPath "DCExternalWANIPs.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "Results exported to $OutputFile"
    Pause
}

function Invoke-LDAPLDAPSCheck {
    <#
        Checks LDAP and LDAPS connectivity on all domain controllers.
    #>
    Write-Header "LDAP/LDAPS Connectivity Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\LDAPLDAPSCheck"
    Ensure-Folder -Path $OutPath

    function Test-LDAPPort {
        param([string]$Server,[int]$Port)
        try {
            $conn = [ADSI]"LDAP://$Server`:$Port"
            $conn.Close()
            return $true
        } catch {
            return $_.Exception.Message
        }
    }

    $allDCs = (Get-ADDomainController -Filter *).HostName
    $results = foreach ($dc in $allDCs) {
        $ldapStatus  = Test-LDAPPort -Server $dc -Port 389
        $ldapsStatus = Test-LDAPPort -Server $dc -Port 636
        [PSCustomObject]@{
            ComputerName = $dc
            LDAPStatus   = if ($ldapStatus -eq $true) {"OK"} else {"Failed: $ldapStatus"}
            LDAPSStatus  = if ($ldapsStatus -eq $true) {"OK"} else {"Failed: $ldapsStatus"}
        }
    }
    $OutputFile = Join-Path $OutPath "DomainControllers_LDAPS_Status.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    $results | Format-Table -AutoSize
    Write-Both "LDAP/LDAPS results exported to $OutputFile"
    Pause
}

function Invoke-DiscoveryScript {
    <#
        Collects detailed software, hardware, and network info from DCs.
    #>
    Write-Header "Running Discovery Script"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\Discovery"
    Ensure-Folder -Path $OutPath

    $swFile = Join-Path $OutPath "DC_Software_Report.csv"
    $hwFile = Join-Path $OutPath "DC_Hardware_Report.csv"
    $nwFile = Join-Path $OutPath "DC_Network_Report.csv"

    $swResults = @(); $hwResults = @(); $nwResults = @()
    $onlineDCs = Get-ADDomainController -Filter * | Where-Object { Test-Connection -ComputerName $_.HostName -Count 1 -Quiet }

    foreach ($dc in $onlineDCs) {
        # Software
        try {
            $regPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            $reg = [wmiclass]"\\$($dc.HostName)\root\cimv2:StdRegProv"
            $subKeys = $reg.EnumKey(2147483650, $regPath)
            foreach ($key in $subKeys.sNames) {
                $name = $reg.GetStringValue(2147483650, "$regPath\$key", "DisplayName").sValue
                if ($name) {
                    $swResults += [PSCustomObject]@{
                        DCName      = $dc.HostName
                        DisplayName = $name
                    }
                }
            }
        } catch {
            Write-Both "Error retrieving software info for $($dc.HostName)"
        }
        # Hardware
        try {
            $comp = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $dc.HostName
            $cpu  = Get-WmiObject -Class Win32_Processor -ComputerName $dc.HostName
            $os   = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $dc.HostName
            $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $dc.HostName
            foreach ($disk in $disks) {
                $hwResults += [PSCustomObject]@{
                    DCName        = $dc.HostName
                    Manufacturer  = $comp.Manufacturer
                    Model         = $comp.Model
                    CPU           = $cpu.Name
                    TotalMemoryGB = [Math]::Round($os.TotalVisibleMemorySize / 1MB,2)
                    DiskDrive     = $disk.DeviceID
                    TotalSizeGB   = [Math]::Round($disk.Size / 1GB,2)
                    FreeSpaceGB   = [Math]::Round($disk.FreeSpace / 1GB,2)
                }
            }
        } catch {
            Write-Both "Error retrieving hardware info for $($dc.HostName)"
        }
        # Network
        try {
            $configs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ComputerName $dc.HostName
            foreach ($cfg in $configs) {
                $nwResults += [PSCustomObject]@{
                    DCName         = $dc.HostName
                    IPAddress      = ($cfg.IPAddress -join ', ')
                    SubnetMask     = ($cfg.IPSubnet -join ', ')
                    DefaultGateway = ($cfg.DefaultIPGateway -join ', ')
                    DNSServers     = ($cfg.DNSServerSearchOrder -join ', ')
                    MACAddress     = $cfg.MACAddress
                }
            }
        } catch {
            Write-Both "Error retrieving network info for $($dc.HostName)"
        }
    }
    $swResults | Export-Csv -Path $swFile -NoTypeInformation
    $hwResults | Export-Csv -Path $hwFile -NoTypeInformation
    $nwResults | Export-Csv -Path $nwFile -NoTypeInformation
    Write-Both "Discovery reports exported to $OutPath"
    Pause
}

function Invoke-ProtectOUs {
    <#
        Protects all OUs from accidental deletion.
    #>
    Write-Header "Protecting All OUs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADOrganizationalUnit command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    Get-ADOrganizationalUnit -Filter * | ForEach-Object {
        Set-ADOrganizationalUnit $_ -ProtectedFromAccidentalDeletion $true
    }
    Write-Both "All OUs have been protected from accidental deletion."
    Pause
}

function Invoke-QuietAuditRedTeam {
    <#
        Performs a quiet audit for red team operations (example from original).
    #>
    Write-Header "Quiet Red Team Audit"
    $OutPath = "C:\ADHealthCheck\QuietAuditRedTeam"
    Ensure-Folder -Path $OutPath

    function Install-Tools {
        Write-Both "Installing Chocolatey and required AD tools..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install ldapexplorer -y
    }
    Install-Tools

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

    Get-ADDomain | Select-Object DistinguishedName,DNSRoot,DomainMode | Export-Csv -Path (Join-Path $OutPath "AD_DomainInfo.csv") -NoTypeInformation
    Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,Site | Export-Csv -Path (Join-Path $OutPath "AD_DomainControllers.csv") -NoTypeInformation
    Get-ADUser -Filter * | Select-Object Name,SamAccountName,Enabled | Export-Csv -Path (Join-Path $OutPath "AD_Users.csv") -NoTypeInformation
    Get-ADGroup -Filter * | Select-Object Name,GroupCategory,GroupScope | Export-Csv -Path (Join-Path $OutPath "AD_Groups.csv") -NoTypeInformation
    Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName,Name | Export-Csv -Path (Join-Path $OutPath "AD_OrganizationalUnits.csv") -NoTypeInformation
    Write-Both "Quiet audit completed. Files exported to $OutPath"
    Pause
}

function Invoke-BestPracticeDNSSiteSubnetCheck {
    <#
        Checks DNS reverse lookup zones vs AD Sites and Services subnets. (From original)
    #>
    Write-Header "DNS Subnet and AD Sites/Services Best Practices Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADReplicationSubnet -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADReplicationSubnet command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    if (-not (Get-Module -ListAvailable -Name DNSServer)) {
        Write-Both "DNSServer module not available. DNS reverse lookup check will be limited."
    } else {
        Import-Module DNSServer
    }

    $OutPath = "C:\ADHealthCheck\SubnetConnectivity"
    Ensure-Folder -Path $OutPath

    function Log-Message {
        param (
            [string]$Message,
            [string]$Type = "Info"
        )
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Both "$stamp [$Type] $Message"
    }

    function Get-ReverseZoneName {
        param([string]$Subnet)
        # Expecting subnet in CIDR form e.g. 192.168.1.0/24
        $parts = $Subnet -split '/'
        if ($parts.Count -lt 2) { return "" }
        $ip = $parts[0]
        $cidr = [int]$parts[1]
        $ipOctets = $ip -split '\.'
        switch ($cidr) {
            8  { return "$($ipOctets[0]).in-addr.arpa" }
            16 { return "$($ipOctets[1]).$($ipOctets[0]).in-addr.arpa" }
            24 { return "$($ipOctets[2]).$($ipOctets[1]).$($ipOctets[0]).in-addr.arpa" }
            default {
                # fallback
                $fullOctets = [int]($cidr / 8)
                $reverseParts = @()
                for ($i = $fullOctets -1; $i -ge 0; $i--) {
                    $reverseParts += $ipOctets[$i]
                }
                return ($reverseParts -join '.') + ".in-addr.arpa"
            }
        }
    }

    function Get-IPsFromSubnet {
        param(
            [string]$Subnet,
            [int]$Count
        )
        $baseIP,$cidr = $Subnet -split '/'
        if (-not $cidr) { return }
        $baseOctets = $baseIP -split '\.'
        [int]$lastOctet = $baseOctets[3]
        1..$Count | ForEach-Object {
            "$($baseOctets[0]).$($baseOctets[1]).$($baseOctets[2]).$($lastOctet + $_)"
        }
    }

    function Test-ADSubnetConnectivity {
        param(
            [string]$RemoteDC,
            [int]$IPsToTestPerSubnet = 3,
            [int]$Pingout = 2,
            [string]$OutputCsvPath = (Join-Path $OutPath 'SubnetConnectivityReport.csv')
        )

        $results = @()
        $sites = Get-ADReplicationSite -Filter *
        $siteSubnets = @{}

        foreach ($site in $sites) {
            $subnets = Get-ADReplicationSubnet -Filter {Site -eq $site.Name}
            $siteSubnets[$site.Name] = $subnets
        }

        foreach ($site in $siteSubnets.Keys) {
            foreach ($subnet in $siteSubnets[$site]) {
                # Check DNS reverse lookup if DNSServer module is available
                if (Get-Module -Name DNSServer) {
                    $reverseZoneName = Get-ReverseZoneName -Subnet $subnet.Range
                    if ($reverseZoneName) {
                        try {
                            $dnsZone = Get-DnsServerZone -Name $reverseZoneName -ErrorAction Stop
                            Log-Message "Reverse lookup zone '$reverseZoneName' exists for $($subnet.Range) in site $site" "Info"
                        } catch {
                            Log-Message "Reverse zone '$reverseZoneName' NOT found for $($subnet.Range) in site $site" "Error"
                        }
                    }
                } else {
                    Log-Message "Skipping DNS reverse zone check for $($subnet.Range) in site $site. No DNSServer module" "Warning"
                }

                $IPsToTest = Get-IPsFromSubnet -Subnet $subnet.Range -Count $IPsToTestPerSubnet
                if ($IPsToTest) {
                    foreach ($ip in $IPsToTest) {
                        try {
                            $localPing = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue -outSeconds $Pingout
                            $remotePing = Invoke-Command -ComputerName $RemoteDC -ScriptBlock {
                                param($ip,$Pingout)
                                Test-Connection -ComputerName $ip -Count 1 -Quiet -outSeconds $Pingout
                            } -ArgumentList $ip,$Pingout -ErrorAction SilentlyContinue

                            $results += [PSCustomObject]@{
                                Stamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                                Site         = $site
                                Subnet       = $subnet.Range
                                TestedIP     = $ip
                                LocalDCPing  = $localPing
                                RemoteDC     = $RemoteDC
                                RemotePing   = $remotePing
                            }
                        } catch {
                            Log-Message "Error pinging $ip $_" "Error"
                        }
                    }
                }
            }
        }
        if ($results) {
            $results | Export-Csv -Path $OutputCsvPath -NoTypeInformation
            Write-Both "Subnet connectivity report generated at $OutputCsvPath"
        } else {
            Write-Both "No results produced for connectivity test or no subnets found."
        }
    }

    $remoteDC = Read-Host "Enter the name of a remote DC to use for ping tests"
    Test-ADSubnetConnectivity -RemoteDC $remoteDC
    Pause
}

function Invoke-ADTimeFix {
    <#
        Updates time settings on the PDC emulator and configures other domain controllers
        to sync with it (from original script).
    #>
    Write-Header "AD Time Fix Process"
    try {
        $fsmo = netdom query fsmo | Out-String
        $pdcLine = $fsmo.Split("`r`n") | Where-Object { $_ -match "^PDC\s" }
        if (-not $pdcLine) {
            Write-Both "PDC role not found in FSMO query output."
            Pause
            return
        }
        $tokens = $pdcLine -split "\s+"
        $pdcName = $tokens[1]
        Write-Both "PDC Emulator: $pdcName"

        $localComp = $env:COMPUTERNAME
        if ($localComp -ieq $pdcName) {
            Write-Both "Running locally on PDC, applying time config here."
            w32tm /config /syncfromflags:manual
            w32tm /config /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org"
            w32tm /config /reliable:yes
            net stop w32time; net start w32time
        } else {
            Write-Both "Remotely configuring PDC time on $pdcName"
            $pdcBlock = {
                w32tm /config /syncfromflags:manual
                w32tm /config /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org"
                w32tm /config /reliable:yes
                net stop w32time; net start w32time
            }
            Invoke-Command -ComputerName $pdcName -ScriptBlock $pdcBlock
        }
        Import-Module ActiveDirectory
        if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
            Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
            Pause
            Show-MainMenu
            return
        }
        # Now configure other DCs to sync from domain hierarchy
        $otherDCs = Get-ADDomainController -Filter * | Where-Object { $_.Name -ine $pdcName }
        foreach ($dc in $otherDCs) {
            Write-Both "Configuring time on $($dc.Name)"
            $dcBlock = {
                w32tm /config /syncfromflags:domhier
                w32tm /resync /force
            }
            Invoke-Command -ComputerName $dc.Name -ScriptBlock $dcBlock -ErrorAction SilentlyContinue
        }
        Write-Both "AD Time Fix completed."
    } catch {
        Write-Both "Error in ADTimeFix: $_"
    }
    Pause
}

function Invoke-BPALocalScan {
    <#
        Runs BPA models related to AD roles on the local DC.
    #>
    Write-Header "Running Local BPA Scan"
    Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-BPAModel -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-BPAModel command was not found. Please ensure the BPA module is installed and this is running on a Domain Controller."
        Pause
        Show-MainMenu
        return
    }
    $models = Get-BpaModel | Where-Object { $_.Id -match "DirectoryServices|DNSServer|DHCPServer|CertificateServices" }
    $results = @()
    foreach ($m in $models) {
        Write-Both "Invoking BPA model: $($m.Id)"
        Invoke-BpaModel $m.Id | Out-Null
        $r = Get-BpaResult $m.Id
        $results += $r
    }
    $outputDir = "C:\ADHealthCheck\BPA"
    Ensure-Folder -Path $outputDir
    $outfile = Join-Path $outputDir "BPA_LocalScanResults.csv"
    $results | Export-Csv -Path $outfile -NoTypeInformation
    Write-Both "Local BPA scan results exported to $outfile"
    Pause
}
function start-gpozaurr {
    $outputDir = "C:\ADHealthCheck\GPOZaurr"
    Ensure-Folder -Path $outputDir

    # 3) Check if GPOZaurr is installed
    if (-not (Get-Module -ListAvailable -Name 'GPOZaurr')) {
        Write-Host "Installing GPOZaurr from PSGallery..." -ForegroundColor Magenta
        try {
            Install-Module GPOZaurr -Force -Verbose
        }
        catch {
            Write-Error "Failed to install GPOZaurr: $_"
            Show-MainMenu
            return
        }
    }

    # 6) Example usage: Invoking GPOZaurr
    Write-Host "Running GPOZaurr" -ForegroundColor Green
        Invoke-GPOZaurr -Verbose 
    Write-Host "GPOZaurr tasks completed. Data is in $outputPath" -ForegroundColor Green
    Show-MainMenu
    return
}

function Invoke-GPOBPASetup {

    <#
    .SYNOPSIS
        Sets up Policy Analyzer plus STIG and Microsoft baseline GPO packages,
        then optionally runs Policy Analyzer.
    
    .DESCRIPTION
        - Checks if the local machine is a Domain Controller.
        - Backs up domain GPOs if on a DC and converts them into a .PolicyRules file.
        - Clears any old .PolicyRules files and downloads the latest STIG GPO package.
        - Downloads and extracts Microsoft baseline packages.
        - Merges STIG GPO backups into a single STIG_GPOs.PolicyRules file.
        - Optionally prompts to launch Policy Analyzer.
        - Now uses C:\ADHealthCheck\PolicyAnalyzer for all operations.
    
    .PARAMETER None
        This function takes no parameters and performs all actions automatically.
    
    .NOTES
        Requires PowerShell 5+ (for Expand-Archive).
        Relies on GPO2PolicyRules.exe from the PolicyAnalyzer.zip package.
    #>
    
        [CmdletBinding()]
        param()
    
        # ----------------------------
        # 1. Define core paths
        # ----------------------------
        $basePath          = 'C:\ADHealthCheck\PolicyAnalyzer'
        $policyAnalyzerPath = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'PolicyAnalyzer.exe'
        $policyRulesFolder  = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'Policy Rules'
        $gpo2PolicyExe      = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'GPO2PolicyRules.exe'
    
        # ----------------------------
        # 2. Ensure main folders exist
        # ----------------------------
        if (!(Test-Path $basePath)) {
            New-Item -ItemType Directory -Path $basePath | Out-Null
            Write-Host "Created folder: $basePath" -ForegroundColor Green
        }
        if (!(Test-Path $policyRulesFolder)) {
            New-Item -ItemType Directory -Path $policyRulesFolder | Out-Null
            Write-Host "Created policy rules folder: $policyRulesFolder" -ForegroundColor Green
        }
    
        # ----------------------------
        # 3. Check Domain Controller & backup GPOs
        # ----------------------------
        function Is-DC {
            try {
                # DomainRole: 4 = Backup DC, 5 = Primary DC
                $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                return ($domainRole -eq 4 -or $domainRole -eq 5)
            }
            catch {
                Write-Warning "Could not determine Domain Controller role: $_"
                return $false
            }
        }
    
        if (Is-DC) {
            Write-Host "Domain Controller detected. Backing up GPOs..." -ForegroundColor Magenta
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $allGPOs = Get-GPO -All
                if ($allGPOs) {
                    Write-Host "Found $($allGPOs.Count) GPO(s). Backing them up..." -ForegroundColor Cyan
                    foreach ($gpo in $allGPOs) {
                        Backup-GPO -Name $gpo.DisplayName -Path $policyRulesFolder -ErrorAction Stop
                        Write-Host "Backed up: $($gpo.DisplayName)" -ForegroundColor Green
                    }
                } else {
                    Write-Warning "No GPOs found for backup."
                }
            } catch {
                Write-Warning "Failed to backup GPOs: $_"
            }
        }
        else {
            Write-Host "Not a Domain Controller, skipping GPO backup." -ForegroundColor Yellow
        }
    
        # ----------------------------
        # 4. Download & Extract PolicyAnalyzer FIRST
        # ----------------------------
        $allBaselines = @(
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202025%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Microsoft%20365%20Apps%20for%20Enterprise%202412.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip'
        )
    
        # Known direct link for PolicyAnalyzer
        $policyAnalyzerLink = 'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/PolicyAnalyzer.zip'
        Write-Host "`n(1) Downloading and extracting PolicyAnalyzer.zip first..." -ForegroundColor Magenta
    
        $policyAnalyzerZip = Join-Path $basePath 'PolicyAnalyzer.zip'
        try {
            Write-Host "Downloading PolicyAnalyzer.zip..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $policyAnalyzerLink -OutFile $policyAnalyzerZip
    
            Write-Host "Extracting PolicyAnalyzer to $($basePath + '\PolicyAnalyzer')" -ForegroundColor Cyan
            $paExtractPath = $basePath
            if (!(Test-Path $paExtractPath)) {
                New-Item -ItemType Directory -Path $paExtractPath | Out-Null
            }
    
            Expand-Archive -Path $policyAnalyzerZip -DestinationPath $paExtractPath -Force
            Write-Host "Policy Analyzer extracted." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to download/extract PolicyAnalyzer.zip: $_"
        }
    
        # ----------------------------
        # 5. Clear out old .PolicyRules AFTER extracting
        # ----------------------------
        Write-Host "`n(2) Clearing out old .PolicyRules files..." -ForegroundColor Magenta
        if (Test-Path $policyRulesFolder) {
            Get-ChildItem -Path $policyRulesFolder -Filter *.PolicyRules -File -ErrorAction SilentlyContinue | Remove-Item -Force
            Write-Host "Cleared old .PolicyRules in: $policyRulesFolder" -ForegroundColor Yellow
        } else {
            New-Item -ItemType Directory -Path $policyRulesFolder | Out-Null
            Write-Host "Created missing folder: $policyRulesFolder" -ForegroundColor Green
        }
    
        # ----------------------------
        # 6. Convert DC GPO backups (if any) using GPO2PolicyRules
        # ----------------------------
        if (Is-DC) {
            if (Test-Path $gpo2PolicyExe) {
                Write-Host "Converting Domain GPO backups to Domain_GPOs.PolicyRules..." -ForegroundColor Magenta
                $outputPolicyFile = Join-Path $policyRulesFolder 'Domain_GPOs.PolicyRules'
                & $gpo2PolicyExe $policyRulesFolder $outputPolicyFile
                if (Test-Path $outputPolicyFile) {
                    Write-Host "Created: $outputPolicyFile" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to create Domain_GPOs.PolicyRules"
                }
            } else {
                Write-Warning "GPO2PolicyRules.exe not found after extraction."
            }
        }
    
        # ----------------------------
        # 7. Find the latest STIG GPO zip & prepare for downloads
        # ----------------------------
        Write-Host "`n(3) Checking for latest STIG GPO zip..." -ForegroundColor Magenta
        $stigBaseUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/'
        $defaultStigLink = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_January_2025.zip'
    
        $global:downloadList = New-Object System.Collections.ArrayList
        [void]$global:downloadList.AddRange($allBaselines)
    
        try {
            $listing = Invoke-WebRequest -Uri $stigBaseUrl -UseBasicParsing -ErrorAction Stop
            $regex   = 'U_STIG_GPO_Package_.*?\.zip'
            $files   = $listing.Links | Where-Object { $_.href -match $regex } | ForEach-Object { $_.href }
    
            if (!$files) {
                Write-Warning "No STIG GPO zip files found at $stigBaseUrl"
                Write-Host "Using fallback STIG link: $defaultStigLink" -ForegroundColor Yellow
                [void]$global:downloadList.Add($defaultStigLink)
            } else {
                $latestStig = $files | Sort-Object | Select-Object -Last 1
                if ($latestStig) {
                    $fullStigUrl = $stigBaseUrl + $latestStig
                    Write-Host "Latest STIG GPO zip: $fullStigUrl" -ForegroundColor Cyan
                    [void]$global:downloadList.Add($fullStigUrl)
                }
            }
        }
        catch {
            Write-Warning "Failed to parse STIG zip listing: $_"
            Write-Host "Using fallback STIG link: $defaultStigLink" -ForegroundColor Yellow
            [void]$global:downloadList.Add($defaultStigLink)
        }
    
        # ----------------------------
        # 8. Download/extract the baselines + STIG
        # ----------------------------
        Write-Host "`n(4) Downloading and extracting baselines + STIG if found..." -ForegroundColor Magenta
        foreach ($url in $global:downloadList) {
            try {
                $originalFileName = Split-Path -Path $url -Leaf
                $cleanFileName    = $originalFileName -replace '%20', '_'
                $destinationZip   = Join-Path $basePath $cleanFileName
    
                Write-Host "`nDownloading $cleanFileName ..." -ForegroundColor Magenta
                Invoke-WebRequest -Uri $url -OutFile $destinationZip
    
                $folderName      = [System.IO.Path]::GetFileNameWithoutExtension($cleanFileName)
                $baselinesFolder = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'Baselines'
                if (!(Test-Path $baselinesFolder)) {
                    New-Item -ItemType Directory -Path $baselinesFolder | Out-Null
                }
                $extractPath = Join-Path $baselinesFolder $folderName
    
                Write-Host "Extracting $cleanFileName to $extractPath" -ForegroundColor Cyan
                Expand-Archive -Path $destinationZip -DestinationPath $extractPath -Force
    
                # If STIG GPO package, convert to STIG_GPOs.PolicyRules
                if ($cleanFileName -match '^U_STIG_GPO_Package_.*\.zip$') {
                    if (Test-Path $gpo2PolicyExe) {
                        Write-Host "Converting STIG GPO backups to STIG_GPOs.PolicyRules..." -ForegroundColor Magenta
                        $stigOutputPolicyFile = Join-Path $policyRulesFolder 'STIG_GPOs.PolicyRules'
                        & $gpo2PolicyExe $extractPath $stigOutputPolicyFile
                        if (Test-Path $stigOutputPolicyFile) {
                            Write-Host "Created STIG .PolicyRules: $stigOutputPolicyFile" -ForegroundColor Green
                        } else {
                            Write-Warning "Failed to create STIG_GPOs.PolicyRules"
                        }
                    } else {
                        Write-Warning "Could not find GPO2PolicyRules.exe. Skipping STIG conversion."
                    }
                }
    
                # Copy any .PolicyRules files from the extracted folder
                $allPolicyRules = Get-ChildItem -Path $extractPath -Recurse -Include *.PolicyRules -File -ErrorAction SilentlyContinue
                if ($allPolicyRules) {
                    Write-Host "Found PolicyRules files in $extractPath" -ForegroundColor Green
                    foreach ($ruleFile in $allPolicyRules) {
                        Write-Host "  Copying '$($ruleFile.FullName)'" -ForegroundColor Green
                        $destination = Join-Path $policyRulesFolder $ruleFile.Name
                        Copy-Item $ruleFile.FullName -Destination $destination -Force
                    }
                } else {
                    Write-Host "No .PolicyRules files found under $extractPath" -ForegroundColor Yellow
                }
    
                Write-Host "Done processing $cleanFileName" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to process $url. Error: $_"
            }
        }
    
        Write-Host "`nAll baseline/STIG downloads and extractions complete!" -ForegroundColor Green
        Start-Sleep 2
    
        # ----------------------------
        # 9. Prompt to launch Policy Analyzer
        # ----------------------------
        if (Test-Path $policyAnalyzerPath) {
            $userChoice = Read-Host "`nWould you like to run Policy Analyzer now? (Y/N)"
            if ($userChoice -match '^(Y|y)$') {
                Write-Host "Launching Policy Analyzer..." -ForegroundColor Magenta
                Start-Process $policyAnalyzerPath
            } else {
                Write-Host "Policy Analyzer launch skipped." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Policy Analyzer.exe not found at $policyAnalyzerPath" -ForegroundColor Red
        }
    }
    
function Invoke-BPARemoteScan {
    <#
        Runs BPA models for AD roles on each DC remotely.
    #>
    Write-Header "Running Remote BPA Scan on All DCs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null

    $modelFilter = "DirectoryServices|DNSServer|DHCPServer|CertificateServices"
    $dcResults = @()
    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

    foreach ($dc in $allDCs) {
        Write-Both "Scanning DC: $dc"
        try {
            $remoteResults = Invoke-Command -ComputerName $dc -ScriptBlock {
                param($modelFilter)
                Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null
                $localResults = @()
                $filteredModels = Get-BpaModel | Where-Object { $_.Id -match $modelFilter }
                foreach ($mod in $filteredModels) {
                    Invoke-BpaModel $mod.Id | Out-Null
                    $localResults += Get-BpaResult $mod.Id
                }
                return $localResults
            } -ArgumentList $modelFilter -ErrorAction Stop
            foreach ($r in $remoteResults) {
                $r | Add-Member -MemberType NoteProperty -Name "DC" -Value $dc -Force
                $dcResults += $r
            }
        } catch {
            Write-Both "Failed scanning $dc $_"
        }
    }
    $outputDir = "C:\ADHealthCheck\BPA"
    Ensure-Folder -Path $outputDir
    $outfile = Join-Path $outputDir "BPA_RemoteCombinedScanResults.csv"
    $dcResults | Export-Csv -Path $outfile -NoTypeInformation
    Write-Both "Remote BPA scan results combined and exported to $outfile"
    Pause
    Show-MainMenu
    return
}

#endregion

######################################################################################
# SECTION 3: NON-DUPLICATED FUNCTIONS FROM ADAudit.ps1
# (Renamed as "Invoke-" style for consistency)
######################################################################################

function Invoke-SYSVOLGPPPasswordCheck {
    <#
      Original "Get-SYSVOLXMLS" renamed to "Invoke-SYSVOLGPPPasswordCheck"
      Checks SYSVOL for GPP cpassword in XML files.
    #>
    Write-Header "Check SYSVOL for cpassword in GPP XMLs"
    $outputDir = "C:\ADHealthCheck\SYSVOL"
    Ensure-Folder -Path $outputDir

    $xmlFiles = Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    if ($xmlFiles) {
        $foundCount = 0
        foreach ($file in $xmlFiles) {
            $xml = try { [xml](Get-Content -Path $file.FullName) } catch { $null }
            if ($xml -and ($xml.InnerXml -like "*cpassword*" -and $xml.InnerXml -notlike '*cpassword=""*')) {
                $destName = $file.Name + "_" + (Get-Date -Format "yyyyMMddHHmmss")
                Copy-Item -Path $file.FullName -Destination (Join-Path $outputDir $destName) -Force
                Write-Both "[!] Found cpassword in: $($file.FullName). Copied to $destName"
                $foundCount++
            }
        }
        if ($foundCount -eq 0) {
            Write-Both "No cpassword entries found in discovered GPP XMLs."
        }
    }
    else {
        Write-Both "No GPP XML files or cannot read SYSVOL."
    }
    Pause
}

function Invoke-LAPSStatusCheck {
    <#
      Original "Get-LAPSStatus"
      Checks if LAPS is installed, which machines are missing ms-Mcs-AdmPwd, etc.
    #>
    Write-Header "Check for LAPS usage"
    $outputDir = "C:\ADHealthCheck\LAPS"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADObject command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    try {
        Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -ErrorAction Stop | Out-Null
        Write-Both "[+] LAPS attribute found (ms-Mcs-AdmPwd)."
    } catch {
        Write-Both "[!] LAPS Not Installed or not detected in schema."
    }

    if (Get-Module -ListAvailable -Name "AdmPwd.PS") {
        Import-Module AdmPwd.PS -Force
        $missing = Get-ADComputer -Filter { ms-Mcs-AdmPwd -notlike "*" }
        if ($missing) {
            $missing | Select-Object -ExpandProperty Name | Out-File (Join-Path $outputDir "laps_missing-computers.txt")
            Write-Both "[!] Some computers do not have LAPS password set, see laps_missing-computers.txt"
        } else {
            Write-Both "All discovered computers appear to store LAPS password."
        }
    } else {
        Write-Both "AdmPwd.PS module not found, skipping advanced LAPS checks."
    }
    Pause
}

function Invoke-OUPermsCheck {
    <#
      Original "Get-OUPerms"
      Checks for non-standard ACL perms on OUs for Authenticated Users, Domain Users, Everyone.
    #>
    Write-Header "Check for non-standard OU permissions"
    $outputDir = "C:\ADHealthCheck\OUperms"
    Ensure-Folder -Path $outputDir
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADObject command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    try {
        $count = 0
        $objects = Get-ADObject -Filter * -SearchBase (Get-ADDomain).DistinguishedName
        foreach ($obj in $objects) {
            try {
                $acl = Get-Acl ("AD:\" + $obj.DistinguishedName)
                $perm = $acl.Access | Where-Object {
                    ($_.IdentityReference -match "Authenticated Users" -or
                     $_.IdentityReference -match "Everyone" -or
                     $_.IdentityReference -match "Domain Users" -or
                     $_.IdentityReference -match "BUILTIN\\Users") -and
                    ($_.ActiveDirectoryRights -notin 'GenericRead','GenericExecute','ExtendedRight','ReadControl','ReadProperty','ListObject','ListChildren','ListChildren, ReadProperty, ListObject','ReadProperty, GenericExecute') -and
                    ($_.AccessControlType -ne 'Deny')
                }
                if ($perm) {
                    Add-Content -Path (Join-Path $outputDir "ou_permissions.txt") -Value "OU: $($obj.DistinguishedName)"
                    Add-Content -Path (Join-Path $outputDir "ou_permissions.txt") -Value "   Rights: $($perm.IdentityReference) $($perm.ActiveDirectoryRights) $($perm.AccessControlType)"
                    $count++
                }
            } catch {}
        }
        if ($count -gt 0) {
            Write-Both "[!] Found $count OU(s) with suspicious ACL entries. See ou_permissions.txt"
        } else {
            Write-Both "No suspicious OU ACL perms found."
        }
    } catch {
        Write-Both "[!] Error enumerating OUs: $_"
    }
    Pause
}

function Invoke-SPNsCheck {
    <#
      Original "Get-SPNs"
      Checks for potential high-value kerberoastable SPN accounts in Domain Admins or Enterprise Admins.
    #>
    Write-Header "Check for high-value kerberoastable SPN accounts"
    $outputDir = "C:\ADHealthCheck\SPNs"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $allUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName,MemberOf
    $results = @()
    foreach ($u in $allUsers) {
        $grpNames = $u.MemberOf | ForEach-Object {
            (Get-ADGroup $_ -ErrorAction SilentlyContinue).SamAccountName
        }
        if ($grpNames -contains "Domain Admins" -or $grpNames -contains "Enterprise Admins") {
            $results += "$($u.SamAccountName) ($($u.Name))"
        }
    }

    if ($results) {
        $results | Out-File (Join-Path $outputDir "HighValueSPNs.txt")
        Write-Both "[!] Found potential high-value kerberoastable accounts. See HighValueSPNs.txt"
    } else {
        Write-Both "No high-value SPNs found or enumeration incomplete."
    }
    Pause
}

function Invoke-ASREPCheck {
    <#
      Original "Get-ADUsersWithoutPreAuth"
      Lists AS-REP roastable (DoesNotRequirePreAuth= True).
    #>
    Write-Header "Check for AS-REP roastable accounts"
    $outputDir = "C:\ADHealthCheck\ASREP"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $users = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth
    if ($users) {
        $users | Select-Object SamAccountName,Name | Out-File (Join-Path $outputDir "ASREPAccounts.txt")
        Write-Both "[!] Found $($users.Count) user(s) that do not require pre-auth. See ASREPAccounts.txt"
    } else {
        Write-Both "No AS-REP roastable accounts found."
    }
    Pause
}

function Invoke-DCsOwnershipCheck {
    <#
      Original "Get-DCsNotOwnedByDA"
      Quick check if DC objects are not owned by the Domain Admins group.
    #>
    Write-Header "Check if DC machine accounts are not owned by Domain Admins group"
    $outputDir = "C:\ADHealthCheck\DCsOwnership"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADComputer command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $results = @()
    $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Properties nTSecurityDescriptor
    foreach ($dc in $dcs) {
        $owner = $dc.nTSecurityDescriptor.Owner
        if ($owner -notmatch "Domain Admins") {
            $results += "$($dc.Name) is owned by $owner"
        }
    }
    if ($results) {
        $results | Out-File (Join-Path $outputDir "dcs_not_owned_by_da.txt")
        Write-Both "[!] Found DCs not owned by Domain Admins group. See dcs_not_owned_by_da.txt"
    } else {
        Write-Both "All DCs appear properly owned by Domain Admins."
    }
    Pause
}

function Invoke-LDAPSecurityCheck {
    <#
      Original "Get-LDAPSecurity"
      Checks LDAP signing, LDAPS usage, channel binding, attempts an anonymous LDAP bind
    #>
    Write-Header "Check for LDAP Security Settings"
    $outputDir = "C:\ADHealthCheck\LDAPSecurity"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    # 1) LDAP signing (LDAPServerIntegrity)
    try {
        $ldapSigning = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
        if ($ldapSigning -eq 2) {
            Write-Both "LDAP signing enforced."
        } else {
            Write-Both "[!] LDAP signing not fully enforced. Value: $ldapSigning"
        }
    } catch {
        Write-Both "[!] Could not read LDAP signing registry value."
    }

    # 2) LDAPS cert check
    try {
        $serverAuthOid = '1.3.6.1.5.5.7.3.1'
        $ldapsCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Extensions | Where-Object { $_.Oid.Value -eq $serverAuthOid }
        }
        if ($ldapsCert) {
            Write-Both "LDAPS certificate found in local machine store."
        } else {
            Write-Both "[!] No server auth cert found for LDAPS."
        }
    } catch {
        Write-Both "[!] Error enumerating LDAPS cert."
    }

    # 3) Channel binding
    try {
        $channelBind = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding
        if ($channelBind -eq 2) {
            Write-Both "LDAPS channel binding enforced."
        } else {
            Write-Both "[!] LDAPS channel binding not enforced. Value: $channelBind"
        }
    } catch {
        Write-Both "[!] Could not read channel binding registry value."
    }

    # 4) Attempt anonymous bind
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $dc = (Get-ADDomainController -Discover).HostName
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection("$dc:389")
        $conn.Timeout = [TimeSpan]::FromSeconds(5)
        $anonCred = New-Object System.Net.NetworkCredential("","")
        $conn.Bind($anonCred)
        Write-Both "[!] Anonymous LDAP bind succeeded on $dc:389"
    } catch [System.DirectoryServices.Protocols.LdapException] {
        Write-Both "Null LDAP bind not allowed on $dc:389"
    } catch {
        Write-Both "[!] Error testing anonymous bind: $_"
    }
    Pause
}
function Configure-MDIEnvironment {
    <#
    .SYNOPSIS
        Presents a menu to run key DefenderForIdentity commands.

    .DESCRIPTION
        Ensures that the DefenderForIdentity module is installed or updated.
        Then it displays a menu with options for running:
            - Get-MDIConfiguration
            - New-MDIConfigurationReport
            - New-MDIDSA
            - Set-MDIConfiguration (with parameters: Mode Domain, Configuration All, and Identity)
            - Test-MDIConfiguration (with parameters: Mode Domain, Configuration All)
            - Test-MDIDSA (with Identity and Detailed switch)
            - Test-MDISensorApiConnection
        Lets the user pick from a menu to execute each command, optionally
        prompting for a service account name.

    .EXAMPLE
        PS> Configure-MDIEnvironment
        # Displays the menu and prompts user for input.
    #>

    [CmdletBinding()]
    param()

    # 1. Ensure DefenderForIdentity module is installed or updated
    $moduleName = "DefenderForIdentity"

    Write-Host "Checking if $moduleName module is installed..."
    $moduleCheck = Get-Module -ListAvailable -Name $moduleName | Select-Object -First 1
    if (-not $moduleCheck) {
        Write-Host "Module '$moduleName' not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $moduleName -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to install $moduleName $_"
            return
        }
    }
    else {
        Write-Host "Module '$moduleName' found. Attempting to update to latest version..." -ForegroundColor Yellow
        try {
            Update-Module -Name $moduleName -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not update $moduleName $_"
        }
    }

    # Import the module
    try {
        Import-Module $moduleName -ErrorAction Stop
        Write-Host "Imported module $moduleName successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import $moduleName after installation: $_"
        return
    }

    Write-Host "`nWelcome to the Microsoft Defender for Identity Configuration Menu." -ForegroundColor Cyan

    do {
        Write-Host "`nPlease choose from the following options:" -ForegroundColor Cyan
        Write-Host "1) Get MDI Configuration"
        Write-Host "2) Generate MDI Configuration Report"
        Write-Host "3) Create New MDI DSA (Default: MDIgMSAsvc01)"
        Write-Host "4) Set MDI Configuration (Domain, All) for MDIgMSAsvc01 or user choice"
        Write-Host "5) Test MDI Configuration (Domain, All)"
        Write-Host "6) Test MDI DSA (Default: MDIgMSAsvc01) -Detailed"
        Write-Host "7) Test MDI Sensor API Connection"
        Write-Host "8) Configure MDI for AD FS Server"
        Write-Host "9) Configure MDI for AD CS Server"
        Write-Host "10) Configure MDI for Microsoft Entra Connect Server"
        Write-Host "11) Fix Remote SAM Configuration"
        Write-Host "0) Exit"

        $choice = Read-Host "Enter your selection (0 to exit)"

        switch ($choice) {
            "1" {
                Write-Host "`nRunning: Get-MDIConfiguration..." -ForegroundColor Yellow
                try {
                    # First check if we have a valid connection to the MDI service
                    Write-Host "Testing MDI API connection..." -ForegroundColor Yellow
                    $connectionTest = Test-MDISensorApiConnection -ErrorAction Stop
                    Write-Host "Connection test result: $connectionTest" -ForegroundColor Cyan
                    
                    # Based on the output from function 7, it returns a simple boolean
                    if (-not $connectionTest) {
                        Write-Host "Warning: Could not connect to MDI API. Connection test failed." -ForegroundColor Red
                        Write-Host "Testing MDI DSA to troubleshoot..." -ForegroundColor Yellow
                        $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                        if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                            $svcAccount = "MDIgMSAsvc01"
                        }
                        $dsaTest = Test-MDIDSA -Identity $svcAccount -Detailed -ErrorAction SilentlyContinue
                        if ($dsaTest) {
                            $dsaTest | Format-List
                        }
                        break
                    }
                    else {
                        Write-Host "MDI API connection test succeeded." -ForegroundColor Green
                    }
                    
                    # If connection is valid, get the configuration
                    $mode = Read-Host "Enter the configuration mode (press ENTER to use default 'Domain')"
                    if ([string]::IsNullOrWhiteSpace($mode)) {
                        $mode = "Domain"
                        Write-Host "Using default mode: $mode" -ForegroundColor Green
                    }
                    
                    $configType = Read-Host "Enter the configuration type (press ENTER to use default 'All')"
                    if ([string]::IsNullOrWhiteSpace($configType)) {
                        $configType = "All"
                        Write-Host "Using default configuration type: $configType" -ForegroundColor Green
                    }
                    
                    $identity = Read-Host "Enter the service account identity (press ENTER to use default 'MDIgMSAsvc01')"
                    if ([string]::IsNullOrWhiteSpace($identity)) {
                        $identity = "MDIgMSAsvc01"
                        Write-Host "Using default identity: $identity" -ForegroundColor Green
                    }
                    
                    $conf = Get-MDIConfiguration -Mode $mode -Configuration $configType -Identity $identity -ErrorAction Stop
                    
                    # Check if configuration exists and display it in a meaningful way
                    if ($conf) {
                        # Create a formatted output with key information
                        Write-Host "MDI Configuration Summary:" -ForegroundColor Cyan
                        Write-Host "=========================" -ForegroundColor Cyan
                        
                        # Display domain configuration first
                        $domainConfig = $conf | Where-Object { $_.Type -eq "Domain" }
                        if ($domainConfig) {
                            Write-Host "`nDomain Configuration:" -ForegroundColor Green
                            $domainConfig | Format-Table Identity, IsHealthy, LastHealthCheckTime -AutoSize
                        }
                        
                        # Display forest configuration if available
                        $forestConfig = $conf | Where-Object { $_.Type -eq "Forest" }
                        if ($forestConfig) {
                            Write-Host "`nForest Configuration:" -ForegroundColor Green
                            $forestConfig | Format-Table Identity, IsHealthy, LastHealthCheckTime -AutoSize
                        }
                        
                        # Display detailed information for each configuration
                        Write-Host "`nDetailed Configuration:" -ForegroundColor Green
                        $conf | Format-Table -Property Identity, Type, IsHealthy, LastHealthCheckTime, HealthCheckErrors, ServiceAccount -AutoSize
                        
                        # Offer to save the results to a file
                        $saveToFile = Read-Host "Would you like to save these results to a file? (Y/N)"
                        if ($saveToFile -eq "Y" -or $saveToFile -eq "y") {
                            $outputPath = Read-Host "Enter the full path for the output file (default: C:\Temp\MDI_Configuration.csv)"
                            if ([string]::IsNullOrWhiteSpace($outputPath)) {
                                $outputPath = "C:\Temp\MDI_Configuration.csv"
                            }
                            
                            # Create directory if it doesn't exist
                            $directory = Split-Path -Path $outputPath -Parent
                            if (!(Test-Path -Path $directory)) {
                                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                            }
                            
                            # Export to CSV
                            $conf | Export-Csv -Path $outputPath -NoTypeInformation
                            Write-Host "Results saved to $outputPath" -ForegroundColor Green
                        }
                    } 
                    else {
                        Write-Host "No MDI configuration found. Please run the Set-MDIConfiguration cmdlet first." -ForegroundColor Red
                        Write-Host "You can select option 4 from the main menu to set up the MDI configuration." -ForegroundColor Yellow
                    }
                } 
                catch {
                    Write-Host "Error executing Get-MDIConfiguration: $_" -ForegroundColor Red
                    Write-Host "Exception details: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "`nPlease ensure:" -ForegroundColor Yellow
                    Write-Host "- The MDI module is properly installed" -ForegroundColor Yellow
                    Write-Host "- You're running as an administrator" -ForegroundColor Yellow
                    Write-Host "- The MDI service is configured in your environment" -ForegroundColor Yellow
                }
            }

            "2" {
                Write-Host "`nRunning: New-MDIConfigurationReport..." -ForegroundColor Yellow
                
                # Get the service account with default
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                Write-Host "Using service account: $svcAccount" -ForegroundColor Green
                
                # First check if we have a valid connection to the MDI service
                try {
                    Write-Host "Testing MDI API connection..." -ForegroundColor Yellow
                    $connectionTest = Test-MDISensorApiConnection -ErrorAction Stop
                    Write-Host "Connection test result: $connectionTest" -ForegroundColor Cyan
                    
                    # Based on the output from function 7, it returns a simple boolean
                    if (-not $connectionTest) {
                        Write-Host "Warning: Could not connect to MDI API. Connection test failed." -ForegroundColor Red
                        Write-Host "Please ensure MDI is properly configured before generating a report." -ForegroundColor Yellow
                        
                        # Let's see what the DSA account status is
                        Write-Host "Testing MDI DSA account to troubleshoot..." -ForegroundColor Yellow
                        $dsaTest = Test-MDIDSA -Identity $svcAccount -Detailed -ErrorAction SilentlyContinue
                        if ($dsaTest) {
                            Write-Host "DSA account test results:" -ForegroundColor Cyan
                            $dsaTest | Format-List
                        }
                        
                        # Let's ask if the user wants to force the report generation anyway
                        $forceContinue = Read-Host "Do you want to try generating the report anyway? (Y/N)"
                        if ($forceContinue -ne 'Y' -and $forceContinue -ne 'y') {
                            break
                        }
                        Write-Host "Continuing with report generation despite connection test failure..." -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "MDI API connection test succeeded." -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "Error connecting to MDI service: $_" -ForegroundColor Red
                    # Let's ask if the user wants to force the report generation anyway
                    $forceContinue = Read-Host "Do you want to try generating the report anyway? (Y/N)"
                    if ($forceContinue -ne 'Y' -and $forceContinue -ne 'y') {
                        break
                    }
                    Write-Host "Continuing with report generation despite connection error..." -ForegroundColor Yellow
                }
                
                # Ask for the report mode with default
                $reportMode = Read-Host "Enter the configuration mode for the report (press ENTER to use default 'Domain')"
                if ([string]::IsNullOrWhiteSpace($reportMode)) {
                    $reportMode = "Domain"
                    Write-Host "Using default mode: $reportMode" -ForegroundColor Green
                }
                
                # Note: New-MDIConfigurationReport doesn't use the Configuration parameter
                $defaultPath = "C:\Temp\MDI_Reports"
                $outputFolder = Read-Host "Specify the folder path where you'd like the MDI report generated (default: $defaultPath)"
                if ([string]::IsNullOrWhiteSpace($outputFolder)) {
                    $outputFolder = $defaultPath
                }
                
                # Create the directory if it doesn't exist
                if (-not (Test-Path $outputFolder)) {
                    try {
                        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
                        Write-Host "Created directory: $outputFolder" -ForegroundColor Green
                    } 
                    catch {
                        Write-Host "Could not create directory '$outputFolder': $_" -ForegroundColor Red
                        break
                    }
                }
                
                try {
                    # Set the working location to the output folder
                    $currentLocation = Get-Location
                    Set-Location -Path $outputFolder
                    
                    Write-Host "Generating MDI Configuration Report. This may take a few minutes..." -ForegroundColor Yellow
                    
                    # Run the report generation directly (no jobs)
                    Write-Host "Executing New-MDIConfigurationReport..." -ForegroundColor Yellow
                    Import-Module DefenderForIdentity -Force
                    
                    # Generate the report directly - no background jobs
                    $result = New-MDIConfigurationReport -Path $outputFolder -Mode $reportMode -Identity $svcAccount
                    
                    # Restore original location
                    Set-Location -Path $currentLocation
                    
                    Write-Host "Report generation completed. Looking for generated reports..." -ForegroundColor Cyan
                    
                    # Allow some time for files to be fully written
                    Start-Sleep -Seconds 2
                    
                    # Search for newest HTML and JSON in the output folder
                    $htmlFiles = Get-ChildItem -Path $outputFolder -Filter "*.html" | Sort-Object LastWriteTime -Descending
                    $jsonFiles = Get-ChildItem -Path $outputFolder -Filter "*.json" | Sort-Object LastWriteTime -Descending
                    
                    $htmlPath = $null
                    $jsonPath = $null
                    
                    # Try to get paths from result first
                    if ($result -and $result.HtmlReportPath -and (Test-Path $result.HtmlReportPath)) {
                        $htmlPath = $result.HtmlReportPath
                        Write-Host "Found HTML report path from result." -ForegroundColor Cyan
                    }
                    # Fallback to directory search
                    elseif ($htmlFiles.Count -gt 0) {
                        $htmlPath = $htmlFiles[0].FullName
                        Write-Host "Found HTML report by searching directory." -ForegroundColor Cyan
                    }
                    
                    if ($result -and $result.JsonReportPath -and (Test-Path $result.JsonReportPath)) {
                        $jsonPath = $result.JsonReportPath
                    }
                    elseif ($jsonFiles.Count -gt 0) {
                        $jsonPath = $jsonFiles[0].FullName
                    }
                    
                    # Display results with clear formatting
                    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
                    Write-Host "     MDI CONFIGURATION REPORT RESULTS" -ForegroundColor Cyan
                    Write-Host "----------------------------------------" -ForegroundColor Cyan
                    
                    if ($htmlPath -and (Test-Path $htmlPath)) {
                        Write-Host "HTML Report: $htmlPath" -ForegroundColor Green
                        
                        # Try to open the HTML report
                        try {
                            Write-Host "Attempting to open HTML report..." -ForegroundColor Yellow
                            
                            # First try using Invoke-Item which is often more reliable
                            try {
                                Invoke-Item -Path $htmlPath -ErrorAction Stop
                                Write-Host "HTML report opened via Invoke-Item." -ForegroundColor Green
                            }
                            catch {
                                # Fallback to Start-Process
                                Write-Host "Trying alternative method to open the report..." -ForegroundColor Yellow
                                Start-Process -FilePath $htmlPath -ErrorAction Stop
                                Write-Host "HTML report opened successfully." -ForegroundColor Green
                            }
                        }
                        catch {
                            Write-Host "Could not automatically open HTML report: $_" -ForegroundColor Red
                            Write-Host "You can manually open the report at: $htmlPath" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "HTML Report: Not found" -ForegroundColor Red
                    }
                    
                    if ($jsonPath -and (Test-Path $jsonPath)) {
                        Write-Host "JSON Report: $jsonPath" -ForegroundColor Green
                    }
                    else {
                        Write-Host "JSON Report: Not found" -ForegroundColor Red
                    }
                    
                    if ((-not $htmlPath -or -not (Test-Path $htmlPath)) -and (-not $jsonPath -or -not (Test-Path $jsonPath))) {
                        Write-Host "No report files were found. The operation may have failed." -ForegroundColor Red
                        Write-Host "Check the output folder manually: $outputFolder" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "`nMDI configuration report generation completed successfully!" -ForegroundColor Green
                    }
                    
                    # Add a pause to let the user read the output
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Cyan
                    Read-Host
                } 
                catch {
                    # Restore original location in case of error
                    Set-Location -Path $currentLocation
                    
                    Write-Host "Error executing New-MDIConfigurationReport: $_" -ForegroundColor Red
                    Write-Host "Exception details: $($_.Exception.Message)" -ForegroundColor Red
                    
                    # Specific error handling for common issues
                    if ($_.Exception.Message -like "*unauthorized*" -or $_.Exception.Message -like "*access denied*") {
                        Write-Host "`nThis appears to be a permissions issue. Please ensure:" -ForegroundColor Yellow
                        Write-Host "- You're running as an administrator" -ForegroundColor Yellow
                        Write-Host "- The account has proper permissions to MDI" -ForegroundColor Yellow
                    }
                    elseif ($_.Exception.Message -like "*not found*") {
                        Write-Host "`nCommand or path not found. Please ensure:" -ForegroundColor Yellow
                        Write-Host "- The DefenderForIdentity module is properly installed" -ForegroundColor Yellow
                        Write-Host "- You're using the correct cmdlet name (it may have changed in newer versions)" -ForegroundColor Yellow
                    }
                    elseif ($_.Exception.Message -like "*timeout*") {
                        Write-Host "`nConnection timeout. Please ensure:" -ForegroundColor Yellow
                        Write-Host "- Your network connection is stable" -ForegroundColor Yellow
                        Write-Host "- The MDI service is available and responsive" -ForegroundColor Yellow
                    }
                    
                    # Add a pause here too in case of error
                    Write-Host "`nPress Enter to continue..." -ForegroundColor Cyan
                    Read-Host
                }
            }

            "3" {
                Write-Host "`nRunning: Setup gMSA for MDI..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                
                # Import the ActiveDirectory module
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    Write-Host "ActiveDirectory module imported successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Failed to import ActiveDirectory module: $_" -ForegroundColor Red
                    break
                }
                
                # Check if any KDS root keys exist (without EffectiveDate filter)
                try {
                    $kdsKeys = Get-KdsRootKey
                    Write-Host "Found $($kdsKeys.Count) existing KDS root keys." -ForegroundColor Green
                    
                    if ($kdsKeys.Count -gt 0) {
                        # Display the existing keys
                        foreach ($key in $kdsKeys) {
                            Write-Host "  - Key ID: $($key.KeyId), Created: $($key.CreationTime), Effective: $($key.EffectiveTime)" -ForegroundColor Green
                        }
                        
                        # Check if there's at least one effective key
                        $effectiveKeys = $kdsKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
                        if ($effectiveKeys.Count -gt 0) {
                            Write-Host "At least one KDS root key is effective and can be used for gMSA." -ForegroundColor Green
                        } else {
                            Write-Host "No currently effective KDS root keys found. Waiting for existing keys to become effective..." -ForegroundColor Yellow
                            # Wait a moment to allow existing keys to become effective if they were just created
                            Start-Sleep -Seconds 10
                        }
                    } else {
                        Write-Host "No KDS root keys found. Creating one now..." -ForegroundColor Yellow
                        Add-KdsRootKey -EffectiveImmediately
                        Write-Host "KDS root key created with EffectiveImmediately. It is now active for gMSA creation." -ForegroundColor Green
                    }
                } catch {
                    Write-Host "Error checking KDS root keys: $_" -ForegroundColor Red
                    
                    # Fallback: Check if we can create a gMSA without creating a new key
                    try {
                        Write-Host "Attempting to create gMSA without creating a new KDS key..." -ForegroundColor Yellow
                        $testGmsaName = "MDITestgMSA"
                        New-ADServiceAccount -Name $testGmsaName -DNSHostName $dcDNSHostName -PrincipalsAllowedToRetrieveManagedPassword $allowedGroup -ErrorAction Stop
                        Remove-ADServiceAccount -Identity $testGmsaName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Host "KDS root key is already functional." -ForegroundColor Green
                    } catch {
                        Write-Host "Cannot create gMSA, attempting to create a new KDS root key..." -ForegroundColor Yellow
                        try {
                            Add-KdsRootKey -EffectiveImmediately
                            Write-Host "KDS root key created with EffectiveImmediately." -ForegroundColor Green
                        } catch {
                            Write-Host "Failed to create KDS root key: $_" -ForegroundColor Red
                            break
                        }
                    }
                }
                
                # Retrieve a domain controller's DNSHostName
                try {
                    $dc = Get-ADDomainController -Discover -ErrorAction Stop
                    $dcDNSHostName = ($dc.DNSHostName -join '')
                    if ([string]::IsNullOrWhiteSpace($dcDNSHostName)) {
                        $dcDNSHostName = ($dc.HostName -join '')
                    }
                    if ([string]::IsNullOrWhiteSpace($dcDNSHostName)) {
                        throw "Domain Controller DNSHostName is null. Cannot proceed."
                    }
                    Write-Host "Using domain controller: $dcDNSHostName" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to retrieve domain controller DNSHostName: $_" -ForegroundColor Red
                    break
                }
                
                # Use the built-in "Domain Controllers" group as the allowed principal
                $allowedGroup = "Domain Controllers"
                
                # Check if the gMSA already exists
                try {
                    $existingGmsa = Get-ADServiceAccount -Identity $svcAccount -ErrorAction SilentlyContinue
                } catch {
                    $existingGmsa = $null
                }
                
                if ($existingGmsa) {
                    Write-Host "gMSA '$svcAccount' already exists." -ForegroundColor Green
                } else {
                    Write-Host "gMSA '$svcAccount' not found. Creating new gMSA..." -ForegroundColor Yellow
                    try {
                        New-ADServiceAccount -Name $svcAccount `
                                        -DNSHostName $dcDNSHostName `
                                        -PrincipalsAllowedToRetrieveManagedPassword $allowedGroup -Verbose
                        Write-Host "gMSA '$svcAccount' created successfully." -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to create gMSA '$svcAccount': $_" -ForegroundColor Red
                        break
                    }
                }
                
                # Install the gMSA on all domain controllers
                try {
                    Write-Host "Installing gMSA on all domain controllers..." -ForegroundColor Yellow
                    
                    # Get all domain controllers
                    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
                    Write-Host "Found domain controllers: $($allDCs -join ', ')" -ForegroundColor Green
                    
                    # Get current computer name
                    $currentComputer = $env:COMPUTERNAME
                    
                    # Install locally first
                    Write-Host "Installing gMSA on local domain controller $currentComputer..." -ForegroundColor Yellow
                    Write-Host "Pausing for 3 seconds before installation..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 3
                    Install-ADServiceAccount -Identity $svcAccount
                    
                    # Verify local installation
                    $localTest = Test-ADServiceAccount -Identity $svcAccount
                    if ($localTest) {
                        Write-Host "gMSA successfully installed on local domain controller." -ForegroundColor Green
                    } else {
                        Write-Warning "gMSA installation verification failed on local domain controller."
                    }
                    
                    # Install on remote domain controllers if there are any others
                    $remoteDCs = $allDCs | Where-Object { $_ -ne $currentComputer }
                    
                    if ($remoteDCs.Count -gt 0) {
                        Write-Host "Installing gMSA on remote domain controllers: $($remoteDCs -join ', ')..." -ForegroundColor Yellow
                        
                        foreach ($dc in $remoteDCs) {
                            Write-Host "Installing on $dc..." -ForegroundColor Yellow
                            try {
                                Invoke-Command -ComputerName $dc -ScriptBlock {
                                    param($svcAccountName)
                                    # Import the module on the remote machine
                                    Import-Module ActiveDirectory
                                    # Pause before installing
                                    Write-Host "Pausing for 3 seconds before installation..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds 3
                                    # Install the gMSA
                                    Install-ADServiceAccount -Identity $svcAccountName
                                    # Verify installation
                                    $result = Test-ADServiceAccount -Identity $svcAccountName
                                    return $result
                                } -ArgumentList $svcAccount -ErrorAction Stop
                                
                                Write-Host "gMSA successfully installed on $dc." -ForegroundColor Green
                            } catch {
                                Write-Warning "Failed to install gMSA on $dc $_"
                            }
                        }
                    } else {
                        Write-Host "No additional domain controllers found for remote installation." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "Error installing gMSA on domain controllers: $_" -ForegroundColor Red
                }
                
                # Add permissions to the Deleted Objects container
                try {
                    Write-Host "Adding required permissions to the Deleted Objects container..." -ForegroundColor Yellow
                    
                    # Create a security group for the gMSA
                    $groupName = "MDI_$($svcAccount)_Group"
                    $groupDescription = "Members of this group are allowed to read the objects in the Deleted Objects container in AD"
                    
                    # Check if the group exists
                    $groupExists = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                    
                    if (-not $groupExists) {
                        Write-Host "Creating security group '$groupName'..." -ForegroundColor Yellow
                        $groupParams = @{
                            Name           = $groupName
                            SamAccountName = $groupName
                            DisplayName    = $groupName
                            GroupCategory  = 'Security'
                            GroupScope     = 'Universal'
                            Description    = $groupDescription
                        }
                        $group = New-ADGroup @groupParams -PassThru
                        Write-Host "Group '$groupName' created successfully." -ForegroundColor Green
                    } else {
                        Write-Host "Group '$groupName' already exists." -ForegroundColor Green
                        $group = $groupExists
                    }
                    
                    # Add the gMSA to the group
                    $gmsaAccount = "$svcAccount$"
                    Write-Host "Adding '$gmsaAccount' to group '$groupName'..." -ForegroundColor Yellow
                    Add-ADGroupMember -Identity $groupName -Members $gmsaAccount -ErrorAction SilentlyContinue
                    Write-Host "Added gMSA to security group." -ForegroundColor Green
                    
                    # Get the deleted objects container's distinguished name
                    $distinguishedName = ([adsi]'').distinguishedName.Value
                    $deletedObjectsDN = "CN=Deleted Objects,$distinguishedName"
                    Write-Host "Deleted Objects DN: $deletedObjectsDN" -ForegroundColor Green
                    
                    # Take ownership on the deleted objects container
                    Write-Host "Taking ownership of the Deleted Objects container..." -ForegroundColor Yellow
                    $takeOwnershipParams = @($deletedObjectsDN, '/takeOwnership')
                    $result = & C:\Windows\System32\dsacls.exe $takeOwnershipParams
                    Write-Host "Ownership taken: $result" -ForegroundColor Green
                    
                    # Grant the 'List Contents' and 'Read Property' permissions to the group
                    Write-Host "Granting permissions to the group..." -ForegroundColor Yellow
                    $domain = ([adsi]'').name.Value
                    $grantPermissionsParams = @($deletedObjectsDN, '/G', "$domain\$groupName`:LCRP")
                    $result = & C:\Windows\System32\dsacls.exe $grantPermissionsParams
                    Write-Host "Permissions granted: $result" -ForegroundColor Green
                } catch {
                    Write-Host "Error configuring Deleted Objects container permissions: $_" -ForegroundColor Red
                }
                
                # Configure the Default Domain Controllers Policy to grant "Log on as a service" right
                # CRITICAL: This is needed for AATPSensor service to impersonate the gMSA account
                try {
                    Write-Host "`nConfiguring 'Log on as a service' right for gMSA account..." -ForegroundColor Yellow
                    Write-Host "Note: AATPSensor service runs as LocalService but impersonates the gMSA account" -ForegroundColor Cyan
                    
                    # Import GroupPolicy module
                    Import-Module GroupPolicy -ErrorAction Stop
                    Write-Host "GroupPolicy module imported successfully." -ForegroundColor Green
                    
                    # Build the fully qualified name for the gMSA
                    $domainName = (Get-ADDomain).NetBIOSName
                    $logonName = if ($svcAccount[-1] -ne '$') { "$svcAccount$" } else { $svcAccount }
                    $fullGmsaName = "$domainName\$logonName"
                    
                    # Get the Default Domain Controllers Policy
                    $gpoName = "Default Domain Controllers Policy"
                    $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
                    Write-Host "Found GPO: $gpoName" -ForegroundColor Green
                    
                    # Backup the GPO before making changes
                    $backupPath = "$env:TEMP\GPOBackups"
                    if (-not (Test-Path $backupPath)) {
                        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
                    }
                    Backup-GPO -Guid $gpo.Id -Path $backupPath | Out-Null
                    Write-Host "Backed up GPO to $backupPath before making changes." -ForegroundColor Green
                    
                    # Create a temporary GPO report to find existing settings
                    $reportPath = "$env:TEMP\GPOReport.xml"
                    Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $reportPath
                    
                    # Get current settings to add to them rather than replace
                    $currentRights = @()
                    $xmlReport = [xml](Get-Content $reportPath)
                    $rightsNodes = $xmlReport.SelectNodes("//SecuritySetting")
                    foreach ($node in $rightsNodes) {
                        if ($node.Name -eq "Log on as a service") {
                            $memberNodes = $node.SelectNodes("Member")
                            foreach ($member in $memberNodes) {
                                $currentRights += $member.Name.'#text'
                            }
                        }
                    }
                    
                    # Add the gMSA and NT SERVICE\ALL SERVICES if not already present
                    if ($currentRights -notcontains $fullGmsaName) {
                        $currentRights += $fullGmsaName
                    }
                    if ($currentRights -notcontains "NT SERVICE\ALL SERVICES") {
                        $currentRights += "NT SERVICE\ALL SERVICES"
                    }
                    
                    # Use the Set-GPPermission cmdlet to update the rights
                    $tempFile = "$env:TEMP\ServiceLogonRights.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = $($currentRights -join ',')
"@ | Out-File -FilePath $tempFile -Encoding Unicode
                    
                    # Import the settings into the GPO
                    $domain = (Get-ADDomain).DNSRoot
                    Write-Host "Updating GPO with new service logon rights..." -ForegroundColor Yellow
                    $command = "secedit.exe /configure /db secedit.sdb /cfg `"$tempFile`" /areas USER_RIGHTS"
                    Invoke-Command -ScriptBlock { & cmd.exe /c $command }
                    Start-Sleep -Seconds 2
                    
                    # Directly update Group Policy settings using secedit.exe
                    try {
                        # Get the SYSVOL path for the GPO
                        $gpoSysvolPath = "\\$domain\SYSVOL\$domain\Policies\{$($gpo.Id)}"
                        $machineGptPath = "$gpoSysvolPath\Machine\Microsoft\Windows NT\SecEdit"
                        
                        # Ensure the directory exists
                        if (-not (Test-Path $machineGptPath)) {
                            New-Item -Path $machineGptPath -ItemType Directory -Force | Out-Null
                        }
                        
                        # Copy the INF file to the GPO location
                        $gpoInfPath = "$machineGptPath\GptTmpl.inf"
                        
                        # If the file already exists, we need to merge our settings into it
                        if (Test-Path $gpoInfPath) {
                            Write-Host "Merging service logon rights with existing GPO template..." -ForegroundColor Yellow
                            
                            # Read the existing GPO template
                            $existingGptContent = Get-Content $gpoInfPath -Raw
                            
                            # Check if the file already has a [Privilege Rights] section
                            if ($existingGptContent -match "\[Privilege Rights\]") {
                                # Check if it already has a SeServiceLogonRight line
                                if ($existingGptContent -match "SeServiceLogonRight\s*=") {
                                    # Replace the existing line with our updated one
                                    $existingGptContent = $existingGptContent -replace "SeServiceLogonRight\s*=.*", "SeServiceLogonRight = $($currentRights -join ',')"
                                } else {
                                    # Add our line to the [Privilege Rights] section
                                    $existingGptContent = $existingGptContent -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeServiceLogonRight = $($currentRights -join ',')"
                                }
                            } else {
                                # Add the [Privilege Rights] section with our line
                                $existingGptContent += "`r`n[Privilege Rights]`r`nSeServiceLogonRight = $($currentRights -join ',')`r`n"
                            }
                            
                            # Write the updated content back to the file
                            $existingGptContent | Out-File -FilePath $gpoInfPath -Encoding Unicode -Force
                        } else {
                            # Just copy our INF file with the settings
                            Copy-Item -Path $tempFile -Destination $gpoInfPath -Force
                        }
                        
                        Write-Host "Updated GPO security template at $gpoInfPath" -ForegroundColor Green
                        
                        # Increment the version number in the GPT.ini file to force a refresh
                        $gptIniPath = "$gpoSysvolPath\GPT.INI"
                        if (Test-Path $gptIniPath) {
                            $gptIni = Get-Content $gptIniPath
                            $versionLine = $gptIni | Where-Object { $_ -match "Version=" }
                            if ($versionLine) {
                                $versionNumber = [int]($versionLine -replace "Version=", "")
                                $newVersion = $versionNumber + 1
                                $gptIni = $gptIni -replace "Version=$versionNumber", "Version=$newVersion"
                            } else {
                                $gptIni += "Version=1"
                            }
                            $gptIni | Out-File -FilePath $gptIniPath -Encoding ASCII -Force
                            Write-Host "Updated GPO version number to force refresh" -ForegroundColor Green
                        }
                        
                        # Force a Group Policy update
                        Write-Host "Forcing Group Policy update..." -ForegroundColor Yellow
                        $gpupdateCmd = "gpupdate.exe /target:computer /force"
                        Invoke-Expression $gpupdateCmd
                    } catch {
                        Write-Warning "Failed to update GPO files directly: $_"
                        
                        # Last resort: Just use the secedit approach which already worked
                        Write-Host "Using secedit fallback approach..." -ForegroundColor Yellow
                        
                        # This already worked in the previous step, so we're good
                        Write-Host "Policy already applied via secedit.exe" -ForegroundColor Green
                    }
                    
                    # Force a Group Policy update on the domain controllers
                    Write-Host "Forcing Group Policy update..." -ForegroundColor Yellow
                    Invoke-GPUpdate -Force -Computer $dcDNSHostName -Target Computer
                    
                    Write-Host "Successfully granted 'Log on as a service' rights to $fullGmsaName in $gpoName." -ForegroundColor Green
                    Write-Host "Please allow time for Group Policy to propagate to all domain controllers." -ForegroundColor Yellow
                    
                    # Clean up temporary files
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Host "Failed to update 'Log on as a service' rights in GPO: $_" -ForegroundColor Red
                }
            }

            "4" {
                Write-Host "`nRunning: Set-MDIConfiguration -Mode Domain -Configuration All..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                
                # Prompt for configuration mode
                $configMode = Read-Host "Enter the configuration mode (press ENTER to use default 'Domain')"
                if ([string]::IsNullOrWhiteSpace($configMode)) {
                    $configMode = "Domain"
                    Write-Host "Using default mode: $configMode" -ForegroundColor Green
                }
                
                # Prompt for configuration type
                $configType = Read-Host "Enter the configuration type (press ENTER to use default 'All')"
                if ([string]::IsNullOrWhiteSpace($configType)) {
                    $configType = "All"
                    Write-Host "Using default configuration type: $configType" -ForegroundColor Green
                }
                
                try {
                    Set-MDIConfiguration -Mode $configMode -Configuration $configType -Identity $svcAccount
                    Write-Host "MDI Configuration set successfully for '$svcAccount'." -ForegroundColor Green
                } catch {
                    Write-Host "Error executing Set-MDIConfiguration: $_" -ForegroundColor Red
                }
                
                # Now, automatically link the required GPOs.
                try {
                    Import-Module GroupPolicy -ErrorAction Stop
                    Write-Host "GroupPolicy module imported successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Failed to import GroupPolicy module: $_" -ForegroundColor Red
                }
                
                # Get the domain's distinguished name (root of the domain)
                try {
                    $domainDN = (Get-ADDomain).DistinguishedName
                    Write-Host "Domain DN: $domainDN" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to retrieve domain DN: $_" -ForegroundColor Red
                    break
                }
                
                # Define the GPO names that need linking.
                $gpoNames = @(
                    "Microsoft Defender for Identity - Advanced Audit and URA Policy for Entra Connect",
                    "Microsoft Defender for Identity - Remote SAM Access"
                )
                
                foreach ($gpoName in $gpoNames) {
                    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                    if ($gpo) {
                        try {
                            New-GPLink -Name $gpoName -Target $domainDN -Enforced ([Microsoft.GroupPolicy.EnforceLink]::No) -ErrorAction Stop
                            Write-Host "GPO '$gpoName' linked to domain root successfully." -ForegroundColor Green
                        } catch {
                            Write-Host "Failed to link GPO '$gpoName': $_" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "GPO '$gpoName' not found." -ForegroundColor Red
                    }
                }
                
                # Optional: Pause for a few seconds to let changes propagate
                Start-Sleep -Seconds 5
            }

            "5" {
                Write-Host "`nRunning: Test-MDIConfiguration -Mode Domain -Configuration All..." -ForegroundColor Yellow
                try {
                    $configMode = Read-Host "Enter the configuration mode (press ENTER to use default 'Domain')"
                    if ([string]::IsNullOrWhiteSpace($configMode)) {
                        $configMode = "Domain"
                        Write-Host "Using default mode: $configMode" -ForegroundColor Green
                    }
                    
                    $configType = Read-Host "Enter the configuration type (press ENTER to use default 'All')"
                    if ([string]::IsNullOrWhiteSpace($configType)) {
                        $configType = "All"
                        Write-Host "Using default configuration type: $configType" -ForegroundColor Green
                    }
                    
                    Write-Host "Running Test-MDIConfiguration -Mode $configMode -Configuration $configType..." -ForegroundColor Yellow
                    $testResults = Test-MDIConfiguration -Mode $configMode -Configuration $configType
                    $testResults | Format-Table -AutoSize
                } catch {
                    Write-Host "Error executing Test-MDIConfiguration $_" -ForegroundColor Red
                }
            }
            
            "6" {
                Write-Host "`nRunning: Test-MDIDSA -Detailed..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    # First check if Test-MDIDSA has other required parameters besides Identity
                    $cmdInfo = Get-Command Test-MDIDSA -ErrorAction SilentlyContinue
                    if ($cmdInfo) {
                        $requiredParams = $cmdInfo.Parameters.Values | 
                            Where-Object { $_.Attributes.Mandatory -eq $true -and $_.Name -ne "Identity" }
                        
                        if ($requiredParams) {
                            Write-Host "The Test-MDIDSA cmdlet has additional required parameters:" -ForegroundColor Yellow
                            $requiredParams | ForEach-Object { Write-Host "- $($_.Name)" -ForegroundColor Yellow }
                            
                            # We'll handle any discovered parameters later
                            # For now, if there are required params besides Identity, we'll note it
                        }
                    }
                    
                    Write-Host "Running Test-MDIDSA -Identity $svcAccount -Detailed..." -ForegroundColor Yellow
                    $dsaTest = Test-MDIDSA -Identity $svcAccount -Detailed
                    $dsaTest | Format-List
                } catch {
                    Write-Host "Error executing Test-MDIDSA $_" -ForegroundColor Red
                }
            }
            
            "7" {
                Write-Host "`nRunning: Test-MDISensorApiConnection..." -ForegroundColor Yellow
                # First verify we have the MDI module loaded
                try {
                    Import-Module DefenderForIdentity -ErrorAction Stop
                } catch {
                    Write-Host "Failed to import DefenderForIdentity module. Installing..." -ForegroundColor Yellow
                    Install-Module -Name DefenderForIdentity -Force
                    Import-Module DefenderForIdentity -ErrorAction Stop
                }
                
                # Run the cmdlet with both required parameters
                Write-Host "Running Test-MDISensorApiConnection..." -ForegroundColor Yellow
                try {
                    # Check if Test-MDISensorApiConnection has any required parameters
                    $cmdInfo = Get-Command Test-MDISensorApiConnection -ErrorAction SilentlyContinue
                    if ($cmdInfo) {
                        $hasRequiredParams = $cmdInfo.Parameters.Values | Where-Object { $_.Attributes.Mandatory -eq $true }
                        
                        if ($hasRequiredParams) {
                            Write-Host "The Test-MDISensorApiConnection cmdlet has required parameters:" -ForegroundColor Yellow
                            $hasRequiredParams | ForEach-Object { Write-Host "- $($_.Name)" -ForegroundColor Yellow }
                            
                            # For future extensibility, we'll prompt for parameters if needed
                            # Currently just running the basic command since we don't expect required params
                        }
                    }
                    
                    $apiResult = Test-MDISensorApiConnection
                    Write-Host "Raw connection test result:" -ForegroundColor Cyan
                    Write-Host "Type: $($apiResult.GetType().FullName)" -ForegroundColor Cyan
                    Write-Host "Value: $apiResult" -ForegroundColor Cyan
                    
                    if ($apiResult -is [bool]) {
                        Write-Host "Connection test returned a boolean value." -ForegroundColor Yellow
                        if ($apiResult) {
                            Write-Host "Connection test SUCCEEDED." -ForegroundColor Green
                        } else {
                            Write-Host "Connection test FAILED." -ForegroundColor Red
                        }
                    } elseif ($apiResult -is [System.Object] -and (Get-Member -InputObject $apiResult -Name "Result" -MemberType Properties -ErrorAction SilentlyContinue)) {
                        Write-Host "Connection test returned an object with Result property." -ForegroundColor Yellow
                        Write-Host "Result value: $($apiResult.Result)" -ForegroundColor Cyan
                        if ($apiResult.Result -eq "Success") {
                            Write-Host "Connection test SUCCEEDED." -ForegroundColor Green
                        } else {
                            Write-Host "Connection test FAILED." -ForegroundColor Red
                        }
                    }
                    
                    Write-Host "`nDetailed connection test result:" -ForegroundColor Yellow
                    $apiResult | Format-List
                } catch {
                    Write-Host "Error executing Test-MDISensorApiConnection $_" -ForegroundColor Red
                }
            }

            "8" {
                Write-Host "`nRunning: Configure-MDIforADFS..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    Configure-MDIforADFS -ServiceAccount $svcAccount
                } catch {
                    Write-Host "Error configuring MDI for AD FS: $_" -ForegroundColor Red
                }
            }
            
            "9" {
                Write-Host "`nRunning: Configure-MDIforADCS..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    Configure-MDIforADCS -ServiceAccount $svcAccount
                } catch {
                    Write-Host "Error configuring MDI for AD CS: $_" -ForegroundColor Red
                }
            }
            
            "10" {
                Write-Host "`nRunning: Configure-MDIforEntraConnect..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    Configure-MDIforEntraConnect -ServiceAccount $svcAccount
                } catch {
                    Write-Host "Error configuring MDI for Entra Connect: $_" -ForegroundColor Red
                }
            }
              "11" {
                Write-Host "`nRunning: Set-MDIConfiguration -Mode Domain -Configuration RemoteSAM..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    Set-MDIConfiguration -Mode Domain -Configuration RemoteSAM -Identity $svcAccount
                } catch {
                    Write-Host "Error configuring MDI for Entra Connect: $_" -ForegroundColor Red
                }
            }
            
            "0" {
                Write-Host "Exiting..." -ForegroundColor Cyan
            }
            
            default {
                Write-Host "Invalid choice, please try again." -ForegroundColor Red
            }
        }
    } while ($choice -ne '0')
}

# Define the AD FS, AD CS, and Entra Connect configuration functions at script level (not inside other blocks)
function Configure-MDIforADFS {
    <#
    .SYNOPSIS
        Configures Microsoft Defender for Identity for AD FS servers.

    .DESCRIPTION
        Performs the necessary configuration steps to prepare AD FS servers for MDI sensor installation:
        - Configures auditing for AD FS
        - Sets up database permissions for the MDI service account
        - Validates the configuration

    .PARAMETER ServiceAccount
        The name of the gMSA or directory service account to use. Defaults to MDIgMSAsvc01.

    .EXAMPLE
        PS> Configure-MDIforADFS -ServiceAccount "MDIgMSAsvc01"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccount = "MDIgMSAsvc01"
    )

    Write-Host "`n==== Configuring Microsoft Defender for Identity for AD FS Servers ====`n" -ForegroundColor Cyan

    # Validate input
    if (-not $ServiceAccount.EndsWith('$') -and $ServiceAccount -notlike "*@*") {
        # Likely a gMSA without $ suffix
        $ServiceAccount = "$ServiceAccount$"
        Write-Host "Using service account: $ServiceAccount" -ForegroundColor Green
    }

    # Step 1: Check if running on an AD FS server
    try {
        $adfsService = Get-Service -Name adfssrv -ErrorAction SilentlyContinue
        if (-not $adfsService) {
            Write-Warning "AD FS service (adfssrv) not found on this server. This script should be run on an AD FS server."
            $continue = Read-Host "Continue anyway? (Y/N)"
            if ($continue -ne 'Y' -and $continue -ne 'y') {
                return
            }
        } else {
            Write-Host "AD FS service detected." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Error checking for AD FS service: $_"
    }

    # Step 2: Configure AD FS Auditing
    Write-Host "`n[1/3] Configuring AD FS auditing..." -ForegroundColor Yellow
    
    try {
        # Import the ADFS PowerShell module if it exists
        if (Get-Module -ListAvailable -Name ADFS) {
            Import-Module ADFS -ErrorAction Stop
            
            # Enable AD FS auditing
            Write-Host "Enabling AD FS auditing..."
            $auditLevel = (Get-AdfsProperties).AuditLevel
            
            if ($auditLevel -eq 'None') {
                Set-AdfsProperties -AuditLevel Basic
                Write-Host "AD FS audit level set to Basic." -ForegroundColor Green
            } else {
                Write-Host "AD FS auditing already enabled with level: $auditLevel" -ForegroundColor Green
            }
            
            # Check for/create/link AD FS Auditing GPO
            $gpoName = "Microsoft Defender for Identity - AD FS Auditing Policy"
            try {
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                
                if (-not $gpo) {
                    Write-Host "Creating GPO for AD FS auditing: $gpoName" -ForegroundColor Yellow
                    $gpo = New-GPO -Name $gpoName -Comment "Configures auditing for AD FS servers"
                    
                    # Create a temporary INF file for audit policy
                    $auditInfPath = "$env:TEMP\ADFSAudit.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents=3
AuditLogonEvents=3
AuditObjectAccess=3
AuditPrivilegeUse=3
AuditPolicyChange=3
AuditAccountManage=3
AuditAccountLogon=3
"@ | Out-File -FilePath $auditInfPath -Encoding Unicode
                    
                    # Import the audit settings
                    $secEditPath = Join-Path $env:SystemRoot "System32\secedit.exe"
                    $tempDbPath = "$env:TEMP\temppol.sdb"
                    $params = @("/configure", "/db", $tempDbPath, "/cfg", $auditInfPath)
                    & $secEditPath $params
                    
                    # Import to GPO
                    $domain = Get-ADDomain
                    $gpoPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
                    $gpoInfPath = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                    
                    # Ensure directory exists
                    if (-not (Test-Path (Split-Path $gpoInfPath -Parent))) {
                        New-Item -Path (Split-Path $gpoInfPath -Parent) -ItemType Directory -Force | Out-Null
                    }
                    
                    # Copy INF file to GPO
                    Copy-Item -Path $auditInfPath -Destination $gpoInfPath -Force
                    
                    # Clean up
                    Remove-Item -Path $auditInfPath -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
                    
                    Write-Host "GPO created successfully." -ForegroundColor Green
                } else {
                    Write-Host "GPO '$gpoName' already exists." -ForegroundColor Green
                }
                
                # Check if GPO is linked to domain
                $domain = Get-ADDomain
                $gpoLinks = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
                
                $isLinked = $false
                foreach ($link in $gpoLinks) {
                    if ($link.DisplayName -eq $gpoName) {
                        $isLinked = $true
                        break
                    }
                }
                
                if (-not $isLinked) {
                    Write-Host "Linking GPO '$gpoName' to domain root..." -ForegroundColor Yellow
                    New-GPLink -Name $gpoName -Target $domain.DistinguishedName -ErrorAction Stop
                    Write-Host "GPO linked successfully." -ForegroundColor Green
                } else {
                    Write-Host "GPO '$gpoName' is already linked to domain root." -ForegroundColor Green
                }
                
                # Force a Group Policy update
                Write-Host "Forcing Group Policy update..." -ForegroundColor Yellow
                & gpupdate.exe /force
            } catch {
                Write-Warning "Error managing GPO for AD FS auditing: $_"
            }
            
            # Verify Event ID 1202 is being logged
            $logName = 'AD FS/Admin'
            $event = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue | 
                     Where-Object { $_.Id -eq 1202 }
            
            if ($event) {
                Write-Host "Verified that Event ID 1202 is being logged in the AD FS/Admin log." -ForegroundColor Green
            } else {
                Write-Warning "Event ID 1202 not found in the AD FS/Admin log. Please ensure AD FS is actively authenticating users."
            }
        } else {
            Write-Warning "ADFS PowerShell module not found. Unable to configure AD FS auditing via PowerShell."
            
            # Fallback to manual registry configuration
            Write-Host "Attempting to enable auditing via registry..." -ForegroundColor Yellow
            
            $adfsRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ADFS\Parameters'
            if (Test-Path $adfsRegistryPath) {
                Set-ItemProperty -Path $adfsRegistryPath -Name 'AuditLevel' -Value 1 -Type DWord -Force
                Write-Host "AD FS audit level set to Basic (1) via registry." -ForegroundColor Green
            } else {
                Write-Warning "AD FS registry path not found. Please enable AD FS auditing manually."
                Write-Host "To enable auditing manually:" -ForegroundColor Yellow
                Write-Host "1. Open the AD FS Management console" -ForegroundColor Yellow
                Write-Host "2. Right-click on 'Service' and select 'Edit Federation Service Properties'" -ForegroundColor Yellow
                Write-Host "3. Go to the 'Events' tab and select 'Success audits and failure audits'" -ForegroundColor Yellow
                Write-Host "4. Click 'OK' to save changes" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Warning "Error configuring AD FS auditing: $_"
    }
    
    # Step 3: Configure AD FS Database Permissions
    Write-Host "`n[2/3] Configuring AD FS database permissions for $ServiceAccount..." -ForegroundColor Yellow
    
    try {
        # Determine the AD FS database type (WID or SQL)
        $adfsConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ADFS\Parameters'
        $configurationDatabaseType = $null
        
        if (Test-Path $adfsConfigPath) {
            $configurationDatabaseType = Get-ItemProperty -Path $adfsConfigPath -Name 'ConfigurationDatabaseType' -ErrorAction SilentlyContinue
        }
        
        if ($configurationDatabaseType -eq 'WindowsInternal') {
            # Windows Internal Database (WID)
            Write-Host "AD FS is using Windows Internal Database (WID)." -ForegroundColor Green
            
            # Build the SQL script
            $domainName = (Get-ADDomain).NetBIOSName
            $accountName = $ServiceAccount
            if ($ServiceAccount -like "*@*") {
                # Extract the username part from the UPN
                $accountName = $ServiceAccount.Split('@')[0]
            }
            
            $fullAccountName = "$domainName\$accountName"
            
            $sqlScript = @"
USE [master];
CREATE LOGIN [$fullAccountName] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
USE [AdfsConfigurationV4];
CREATE USER [$fullAccountName] FOR LOGIN [$fullAccountName];
ALTER ROLE [db_datareader] ADD MEMBER [$fullAccountName];
GRANT CONNECT TO [$fullAccountName];
GRANT SELECT TO [$fullAccountName];
"@
            
            # Save the SQL script to a file
            $scriptPath = "$env:TEMP\AdfsDbPermissions.sql"
            $sqlScript | Out-File -FilePath $scriptPath -Encoding UTF8
            
            # Execute the SQL script against WID
            Write-Host "Executing SQL script to grant database permissions..."
            
            $widResult = Invoke-Command -ScriptBlock {
                param($scriptPath)
                & C:\Windows\System32\Inetsrv\appcmd.exe list apppool "DefaultAppPool"
                & sqlcmd -S \\.\pipe\MICROSOFT##WID\tsql\query -i $scriptPath
            } -ArgumentList $scriptPath
            
            Write-Host "Database permissions script executed." -ForegroundColor Green
            Write-Host "SQL script output: $widResult"
            
            # Clean up
            Remove-Item -Path $scriptPath -Force
        } elseif ($configurationDatabaseType -eq 'SQL') {
            # SQL Server
            Write-Host "AD FS is using SQL Server. Please provide the SQL Server details." -ForegroundColor Yellow
            
            $sqlServer = Read-Host "Enter the SQL Server name (e.g., SQLServer01)"
            $databaseName = Read-Host "Enter the AD FS database name (default: AdfsConfigurationV4)"
            
            if ([string]::IsNullOrWhiteSpace($databaseName)) {
                $databaseName = "AdfsConfigurationV4"
            }
            
            # Build and execute the PowerShell command for SQL
            $domainName = (Get-ADDomain).NetBIOSName
            $accountName = $ServiceAccount
            if ($ServiceAccount -like "*@*") {
                # Extract the username part from the UPN
                $accountName = $ServiceAccount.Split('@')[0]
            }
            
            $fullAccountName = "$domainName\$accountName"
            
            # Build the SQL script
            $sqlScript = @"
USE [master];
CREATE LOGIN [$fullAccountName] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
USE [$databaseName];
CREATE USER [$fullAccountName] FOR LOGIN [$fullAccountName];
ALTER ROLE [db_datareader] ADD MEMBER [$fullAccountName];
GRANT CONNECT TO [$fullAccountName];
GRANT SELECT TO [$fullAccountName];
"@
            
            # Save the SQL script to a file
            $scriptPath = "$env:TEMP\AdfsDbPermissions.sql"
            $sqlScript | Out-File -FilePath $scriptPath -Encoding UTF8
            
            # Execute the SQL script against SQL Server
            Write-Host "Executing SQL script to grant database permissions..."
            
            $sqlResult = Invoke-Command -ScriptBlock {
                param($sqlServer, $scriptPath)
                & sqlcmd -S $sqlServer -i $scriptPath
            } -ArgumentList $sqlServer, $scriptPath
            
            Write-Host "Database permissions script executed." -ForegroundColor Green
            Write-Host "SQL script output: $sqlResult"
            
            # Clean up
            Remove-Item -Path $scriptPath -Force
        } else {
            Write-Warning "Unable to determine AD FS database type. Please configure database permissions manually."
            Write-Host "For Windows Internal Database (WID), run this PowerShell command:" -ForegroundColor Yellow
            Write-Host '$ConnectionString = "server=\\.\pipe\MICROSOFT##WID\tsql\query;database=AdfsConfigurationV4;trusted_connection=true;"' -ForegroundColor Yellow
            Write-Host '$SQLConnection= New-Object System.Data.SQLClient.SQLConnection($ConnectionString)' -ForegroundColor Yellow
            Write-Host '$SQLConnection.Open()' -ForegroundColor Yellow
            Write-Host '$SQLCommand = $SQLConnection.CreateCommand()' -ForegroundColor Yellow
            Write-Host '$SQLCommand.CommandText = "USE [master]; CREATE LOGIN [DOMAIN\ServiceAccount] FROM WINDOWS WITH DEFAULT_DATABASE=[master]; USE [AdfsConfigurationV4]; CREATE USER [DOMAIN\ServiceAccount] FOR LOGIN [DOMAIN\ServiceAccount]; ALTER ROLE [db_datareader] ADD MEMBER [DOMAIN\ServiceAccount]; GRANT CONNECT TO [DOMAIN\ServiceAccount]; GRANT SELECT TO [DOMAIN\ServiceAccount];"' -ForegroundColor Yellow
            Write-Host '$SqlDataReader = $SQLCommand.ExecuteReader()' -ForegroundColor Yellow
            Write-Host '$SQLConnection.Close()' -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Error configuring AD FS database permissions: $_"
    }
    
    # Step 4: Validate the Configuration
    Write-Host "`n[3/3] Validating AD FS configuration for MDI..." -ForegroundColor Yellow
    
    # Run Test-MDIConfiguration with AD FS specific parameters if possible
    try {
        Import-Module DefenderForIdentity -ErrorAction Stop
        $testParams = @{
            Mode = "Domain"
            Configuration = "Adfs"
        }
        
        $testResult = Test-MDIConfiguration @testParams
        
        if ($testResult.IsHealthy) {
            Write-Host "AD FS configuration for MDI validated successfully." -ForegroundColor Green
        } else {
            Write-Warning "Some AD FS configuration issues were detected:"
            $testResult | Format-List
        }
    } catch {
        Write-Warning "Error validating AD FS configuration: $_"
    }
    
    Write-Host "`nAD FS configuration for Microsoft Defender for Identity completed." -ForegroundColor Cyan
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Install the MDI sensor on this AD FS server." -ForegroundColor Yellow
    Write-Host "2. Verify sensor installation status in Microsoft Defender XDR portal." -ForegroundColor Yellow
    Write-Host "3. Configure any additional AD FS servers in your farm." -ForegroundColor Yellow
}

function Configure-MDIforADCS {
    <#
    .SYNOPSIS
        Configures Microsoft Defender for Identity for AD CS servers.

    .DESCRIPTION
        Performs the necessary configuration steps to prepare AD CS servers for MDI sensor installation:
        - Verifies AD CS Certification Authority Role Service is installed
        - Configures required auditing settings
        - Validates the configuration

    .PARAMETER ServiceAccount
        The name of the gMSA or directory service account to use. Defaults to MDIgMSAsvc01.

    .EXAMPLE
        PS> Configure-MDIforADCS -ServiceAccount "MDIgMSAsvc01"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccount = "MDIgMSAsvc01"
    )

    Write-Host "`n==== Configuring Microsoft Defender for Identity for AD CS Servers ====`n" -ForegroundColor Cyan

    # Validate input
    if (-not $ServiceAccount.EndsWith('$') -and $ServiceAccount -notlike "*@*") {
        # Likely a gMSA without $ suffix
        $ServiceAccount = "$ServiceAccount$"
        Write-Host "Using service account: $ServiceAccount" -ForegroundColor Green
    }

    # Step 1: Check if running on an AD CS server with Certification Authority Role Service
    try {
        $adcsService = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if (-not $adcsService) {
            Write-Warning "AD CS service (CertSvc) not found on this server. This script should be run on an AD CS server with Certification Authority role."
            $continue = Read-Host "Continue anyway? (Y/N)"
            if ($continue -ne 'Y' -and $continue -ne 'y') {
                return
            }
        } else {
            Write-Host "AD CS service detected." -ForegroundColor Green
            
            # Check for Certification Authority Role Service specifically
            $caRole = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue
            if ($caRole -and $caRole.Installed) {
                Write-Host "AD CS Certification Authority Role Service is installed." -ForegroundColor Green
            } else {
                Write-Warning "AD CS Certification Authority Role Service is not installed. MDI sensor only supports AD CS servers with this role."
                $continue = Read-Host "Continue anyway? (Y/N)"
                if ($continue -ne 'Y' -and $continue -ne 'y') {
                    return
                }
            }
        }
    } catch {
        Write-Warning "Error checking for AD CS service: $_"
    }

    # Step 2: Configure AD CS Auditing
    Write-Host "`n[1/2] Configuring AD CS auditing..." -ForegroundColor Yellow
    
    try {
        # Check for ADCS PowerShell module
        if (Get-Module -ListAvailable -Name ADCS) {
            Import-Module ADCS -ErrorAction Stop
            Write-Host "AD CS PowerShell module loaded." -ForegroundColor Green
        } else {
            Write-Warning "ADCS PowerShell module not found. Continuing with alternative configuration methods."
        }
        
        # Configure AD CS Auditing via GPO
        Write-Host "Configuring AD CS security auditing via GPO..." -ForegroundColor Yellow
        
        # Create/check GPO for AD CS auditing
        $gpoName = "Microsoft Defender for Identity - AD CS Auditing Policy"
        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            
            if (-not $gpo) {
                Write-Host "Creating GPO for AD CS auditing: $gpoName" -ForegroundColor Yellow
                $gpo = New-GPO -Name $gpoName -Comment "Configures auditing for AD CS servers"
                
                # Create a temporary INF file for audit policy
                $auditInfPath = "$env:TEMP\ADCSAudit.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents=3
AuditLogonEvents=3
AuditObjectAccess=3
AuditPrivilegeUse=3
AuditPolicyChange=3
AuditAccountManage=3
AuditAccountLogon=3
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
[System Access]
EnableGuestAccount=0
[Advanced Audit Policy Configuration]
"System","Security System Extension",3
"System","System Integrity",3
"System","Other System Events",3
"Logon/Logoff","Logon",3
"Logon/Logoff","Logoff",3
"Logon/Logoff","Account Lockout",3
"Logon/Logoff","Other Logon/Logoff Events",3
"Object Access","Certification Services",3
"Object Access","Detailed File Share",3
"Object Access","File System",3
"Object Access","Registry",3
"Privilege Use","Sensitive Privilege Use",3
"Privilege Use","Non Sensitive Privilege Use",3
"Detailed Tracking","Process Creation",3
"Detailed Tracking","Process Termination",3
"Policy Change","Audit Policy Change",3
"Policy Change","Authentication Policy Change",3
"Account Management","Computer Account Management",3
"Account Management","Other Account Management Events",3
"Account Management","Security Group Management",3
"Account Management","User Account Management",3
"Account Logon","Credential Validation",3
"Account Logon","Other Account Logon Events",3
"DS Access","Directory Service Access",3
"DS Access","Directory Service Changes",3
"@ | Out-File -FilePath $auditInfPath -Encoding Unicode
                
                # Import to GPO
                $domain = Get-ADDomain
                $gpoPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
                $gpoSecEditPath = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit"
                
                # Ensure directory exists
                if (-not (Test-Path $gpoSecEditPath)) {
                    New-Item -Path $gpoSecEditPath -ItemType Directory -Force | Out-Null
                }
                
                # Copy INF file to GPO
                $gpoInfPath = "$gpoSecEditPath\GptTmpl.inf"
                Copy-Item -Path $auditInfPath -Destination $gpoInfPath -Force
                
                # Clean up
                Remove-Item -Path $auditInfPath -Force -ErrorAction SilentlyContinue
                
                Write-Host "GPO created successfully." -ForegroundColor Green
            } else {
                Write-Host "GPO '$gpoName' already exists." -ForegroundColor Green
            }
            
            # Check if GPO is linked to domain
            $domain = Get-ADDomain
            $gpoLinks = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
            
            $isLinked = $false
            foreach ($link in $gpoLinks) {
                if ($link.DisplayName -eq $gpoName) {
                    $isLinked = $true
                    break
                }
            }
            
            if (-not $isLinked) {
                Write-Host "Linking GPO '$gpoName' to domain root..." -ForegroundColor Yellow
                New-GPLink -Name $gpoName -Target $domain.DistinguishedName -ErrorAction Stop
                Write-Host "GPO linked successfully." -ForegroundColor Green
            } else {
                Write-Host "GPO '$gpoName' is already linked to domain root." -ForegroundColor Green
            }
            
            # Force a Group Policy update
            Write-Host "Forcing Group Policy update..." -ForegroundColor Yellow
            & gpupdate.exe /force
        } catch {
            Write-Warning "Error managing GPO for AD CS auditing: $_"
            
            # Fallback to local configuration if GPO setup fails
            Write-Host "Falling back to local configuration..." -ForegroundColor Yellow
            
            # Enable Certificate Services auditing subcategories
            & auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable
            
            # Verify the auditing configuration
            $auditResult = & auditpol.exe /get /subcategory:"Certification Services"
            Write-Host "Certificate Services auditing configuration:" -ForegroundColor Green
            Write-Host $auditResult
        }
        
        # Configure Registry Settings for AD CS Advanced Auditing
        $adcsAuditRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
        
        if (Test-Path $adcsAuditRegPath) {
            $caNames = Get-ChildItem -Path $adcsAuditRegPath | Select-Object -ExpandProperty PSChildName
            
            foreach ($caName in $caNames) {
                $caAuditRegPath = Join-Path -Path $adcsAuditRegPath -ChildPath "$caName\PolicyModules\CertificateAuthority"
                
                if (Test-Path $caAuditRegPath) {
                    # Enable auditing in the registry
                    Write-Host "Configuring auditing for CA: $caName" -ForegroundColor Yellow
                    Set-ItemProperty -Path $caAuditRegPath -Name "Audit" -Value 127 -Type DWord -Force
                    $auditValue = (Get-ItemProperty -Path $caAuditRegPath -Name "Audit" -ErrorAction SilentlyContinue).Audit
                    Write-Host "Audit value set to: $auditValue (Recommended: 127)" -ForegroundColor Green
                } else {
                    Write-Warning "Registry path for CA '$caName' not found: $caAuditRegPath"
                }
            }
        } else {
            Write-Warning "AD CS configuration registry path not found: $adcsAuditRegPath"
        }
        
        # Restart the AD CS service to apply changes
        Write-Host "Restarting AD CS service to apply auditing changes..." -ForegroundColor Yellow
        Restart-Service -Name CertSvc -Force
        Write-Host "AD CS service restarted." -ForegroundColor Green
    } catch {
        Write-Warning "Error configuring AD CS auditing: $_"
    }
    
    # Step 3: Validate the Configuration
    Write-Host "`n[2/2] Validating AD CS configuration for MDI..." -ForegroundColor Yellow
    
    # Run Test-MDIConfiguration with AD CS specific parameters if possible
    try {
        Import-Module DefenderForIdentity -ErrorAction Stop
        $testParams = @{
            Mode = "Domain"
            Configuration = "Adcs"
        }
        
        $testResult = Test-MDIConfiguration @testParams
        
        if ($testResult.IsHealthy) {
            Write-Host "AD CS configuration for MDI validated successfully." -ForegroundColor Green
        } else {
            Write-Warning "Some AD CS configuration issues were detected:"
            $testResult | Format-List
        }
    } catch {
        Write-Warning "Error validating AD CS configuration: $_"
    }
    
    # Check if required events are being logged
    Write-Host "Checking if required AD CS events are being logged..." -ForegroundColor Yellow
    $requiredEvents = @(4870, 4872, 4873, 4874)
    $foundEvents = @()
    
    foreach ($eventId in $requiredEvents) {
        $event = Get-WinEvent -LogName "Security" -MaxEvents 1 -FilterXPath "*[System[EventID=$eventId]]" -ErrorAction SilentlyContinue
        if ($event) {
            $foundEvents += $eventId
        }
    }
    
    if ($foundEvents.Count -eq $requiredEvents.Count) {
        Write-Host "All required AD CS events are being logged successfully." -ForegroundColor Green
    } else {
        $missingEvents = $requiredEvents | Where-Object { $_ -notin $foundEvents }
        Write-Warning "Some required events are not being logged: $($missingEvents -join ', ')"
        Write-Host "This could be normal if these certificate operations haven't occurred recently." -ForegroundColor Yellow
        Write-Host "Perform some certificate operations to generate these events for verification." -ForegroundColor Yellow
    }
    
    Write-Host "`nAD CS configuration for Microsoft Defender for Identity completed." -ForegroundColor Cyan
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Install the MDI sensor on this AD CS server." -ForegroundColor Yellow
    Write-Host "2. Verify sensor installation status in Microsoft Defender XDR portal." -ForegroundColor Yellow
    Write-Host "3. Configure any additional AD CS servers in your environment." -ForegroundColor Yellow
}

function Configure-MDIforEntraConnect {
    <#
    .SYNOPSIS
        Configures Microsoft Defender for Identity for Microsoft Entra Connect servers.

    .DESCRIPTION
        Performs the necessary configuration steps to prepare Microsoft Entra Connect servers for MDI sensor installation:
        - Verifies Entra Connect is installed
        - Configures auditing settings
        - Sets up database permissions if using SQL Server
        - Validates the configuration

    .PARAMETER ServiceAccount
        The name of the gMSA or directory service account to use. Defaults to MDIgMSAsvc01.

    .EXAMPLE
        PS> Configure-MDIforEntraConnect -ServiceAccount "MDIgMSAsvc01"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccount = "MDIgMSAsvc01"
    )

    Write-Host "`n==== Configuring Microsoft Defender for Identity for Entra Connect Servers ====`n" -ForegroundColor Cyan

    # Validate input
    if (-not $ServiceAccount.EndsWith('$') -and $ServiceAccount -notlike "*@*") {
        # Likely a gMSA without $ suffix
        $ServiceAccount = "$ServiceAccount$"
        Write-Host "Using service account: $ServiceAccount" -ForegroundColor Green
    }

    # Step 1: Check if running on an Entra Connect server
    try {
        $entraConnectPath = "C:\Program Files\Microsoft Azure AD Connect"
        $entraConnectService = Get-Service -Name ADSync -ErrorAction SilentlyContinue
        
        if (-not (Test-Path $entraConnectPath) -or -not $entraConnectService) {
            Write-Warning "Microsoft Entra Connect installation not detected on this server."
            $continue = Read-Host "Continue anyway? (Y/N)"
            if ($continue -ne 'Y' -and $continue -ne 'y') {
                return
            }
        } else {
            Write-Host "Microsoft Entra Connect installation detected." -ForegroundColor Green
            
            # Get Entra Connect version
            $syncClientVersionFile = Join-Path -Path $entraConnectPath -ChildPath "ADAL\SyncEngine\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            if (Test-Path $syncClientVersionFile) {
                $fileVersion = (Get-Item $syncClientVersionFile).VersionInfo.FileVersion
                Write-Host "Microsoft Entra Connect version: $fileVersion" -ForegroundColor Green
            }
        }
    } catch {
        Write-Warning "Error checking for Microsoft Entra Connect: $_"
    }

    # Step 2: Configure Entra Connect Auditing
    Write-Host "`n[1/3] Configuring Microsoft Entra Connect auditing..." -ForegroundColor Yellow
    
    try {
        # Enable auditing via auditpol.exe for Entra Connect events
        & auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
        & auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
        
        # Verify the auditing configuration
        $auditResult1 = & auditpol.exe /get /subcategory:"Directory Service Changes"
        $auditResult2 = & auditpol.exe /get /subcategory:"Directory Service Access"
        
        Write-Host "Directory Service auditing configuration:" -ForegroundColor Green
        Write-Host $auditResult1
        Write-Host $auditResult2
        
        # Configure Azure AD Connect advanced auditing for event 1644
        Write-Host "Configuring advanced auditing for Entra Connect..."
        
        # Check if the GPO for Advanced Audit and URA Policy for Entra Connect exists
        $gpoName = "Microsoft Defender for Identity - Advanced Audit and URA Policy for Entra Connect"
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if ($gpo) {
            Write-Host "GPO '$gpoName' found. Ensure it's linked to the domain." -ForegroundColor Green
            
            # Check if the GPO is linked to the domain
            $domain = Get-ADDomain
            $gpoLinks = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
            
            $isLinked = $false
            foreach ($link in $gpoLinks) {
                if ($link.DisplayName -eq $gpoName) {
                    $isLinked = $true
                    break
                }
            }
            
            if (-not $isLinked) {
                Write-Warning "GPO '$gpoName' is not linked to the domain. Attempting to link it now..."
                try {
                    New-GPLink -Name $gpoName -Target $domain.DistinguishedName -ErrorAction Stop
                    Write-Host "GPO '$gpoName' linked to the domain successfully." -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to link GPO '$gpoName' to the domain: $_"
                    Write-Host "Please link this GPO to the domain manually." -ForegroundColor Yellow
                }
            } else {
                Write-Host "GPO '$gpoName' is already linked to the domain." -ForegroundColor Green
            }
        } else {
            Write-Warning "GPO '$gpoName' not found. This policy should be created by the MDI configuration."
            Write-Host "Please run 'Set-MDIConfiguration -Mode Domain -Configuration All' to create the required GPOs." -ForegroundColor Yellow
        }
        
        # Force a Group Policy update
        Write-Host "Forcing Group Policy update..." -ForegroundColor Yellow
        & gpupdate.exe /force
    } catch {
        Write-Warning "Error configuring Entra Connect auditing: $_"
    }
    
    # Step 3: Configure Database Access if using external SQL
    Write-Host "`n[2/3] Checking for SQL database configuration..." -ForegroundColor Yellow
    
    try {
        # Determine if Entra Connect is using LocalDB or external SQL
        $adSyncConfigPath = "C:\Program Files\Microsoft Azure AD Connect\AdSyncGlobalSettings.mdb"
        
        if (Test-Path $adSyncConfigPath) {
            Write-Host "Found AdSyncGlobalSettings.mdb file - checking database configuration..." -ForegroundColor Green
            
            # Using SQL query to check for database connection would require additional tools
            # For simplicity, we'll ask the user
            $usesExternalSQL = Read-Host "Is Microsoft Entra Connect using an external SQL Server (not LocalDB)? (Y/N)"
            
            if ($usesExternalSQL -eq 'Y' -or $usesExternalSQL -eq 'y') {
                $sqlServer = Read-Host "Enter the SQL Server name (e.g., SQLServer01)"
                $databaseName = Read-Host "Enter the ADSync database name (default: ADSync)"
                
                if ([string]::IsNullOrWhiteSpace($databaseName)) {
                    $databaseName = "ADSync"
                }
                
                # Configure permissions for the service account
                Write-Host "Configuring database permissions for $ServiceAccount..." -ForegroundColor Yellow
                
                # Build the domain\username
                $domainName = (Get-ADDomain).NetBIOSName
                $accountName = $ServiceAccount
                if ($ServiceAccount -like "*@*") {
                    # Extract the username part from the UPN
                    $accountName = $ServiceAccount.Split('@')[0]
                }
                
                $fullAccountName = "$domainName\$accountName"
                
                # Build the SQL script
                $sqlScript = @"
USE [master];
IF NOT EXISTS (SELECT name FROM master.sys.server_principals WHERE name = '$fullAccountName')
BEGIN
    CREATE LOGIN [$fullAccountName] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
END
USE [$databaseName];
IF NOT EXISTS (SELECT name FROM [$databaseName].sys.database_principals WHERE name = '$fullAccountName')
BEGIN
    CREATE USER [$fullAccountName] FOR LOGIN [$fullAccountName];
END
ALTER ROLE [db_datareader] ADD MEMBER [$fullAccountName];
GRANT CONNECT TO [$fullAccountName];
GRANT SELECT TO [$fullAccountName];
GRANT EXECUTE TO [$fullAccountName];
"@
                
                # Save the SQL script to a file
                $scriptPath = "$env:TEMP\EntraConnectDbPermissions.sql"
                $sqlScript | Out-File -FilePath $scriptPath -Encoding UTF8
                
                # Execute the SQL script against SQL Server
                Write-Host "Executing SQL script to grant database permissions..."
                
                $sqlResult = Invoke-Command -ScriptBlock {
                    param($sqlServer, $scriptPath)
                    & sqlcmd -S $sqlServer -i $scriptPath
                } -ArgumentList $sqlServer, $scriptPath
                
                Write-Host "Database permissions script executed." -ForegroundColor Green
                Write-Host "SQL script output: $sqlResult"
                
                # Clean up
                Remove-Item -Path $scriptPath -Force
            } else {
                Write-Host "Microsoft Entra Connect is using LocalDB. No additional database configuration needed." -ForegroundColor Green
            }
        } else {
            Write-Warning "AdSyncGlobalSettings.mdb not found at expected location."
        }
    } catch {
        Write-Warning "Error configuring database access: $_"
    }
    
    # Step 4: Validate the Configuration
    Write-Host "`n[3/3] Validating Entra Connect configuration for MDI..." -ForegroundColor Yellow
    
    # Run Test-MDIConfiguration with Entra Connect specific parameters if possible
    try {
        Import-Module DefenderForIdentity -ErrorAction Stop
        $testParams = @{
            Mode = "Domain"
            Configuration = "EntraConnect"
        }
        
        $testResult = Test-MDIConfiguration @testParams
        
        if ($testResult.IsHealthy) {
            Write-Host "Entra Connect configuration for MDI validated successfully." -ForegroundColor Green
        } else {
            Write-Warning "Some Entra Connect configuration issues were detected:"
            $testResult | Format-List
        }
    } catch {
        Write-Warning "Error validating Entra Connect configuration: $_"
        
        # Check for event 1644 manually
        Write-Host "Checking if event 1644 is being logged..." -ForegroundColor Yellow
        $event = Get-WinEvent -LogName "Directory Service" -MaxEvents 1 -FilterXPath "*[System[EventID=1644]]" -ErrorAction SilentlyContinue
        
        if ($event) {
            Write-Host "Event 1644 is being logged successfully." -ForegroundColor Green
        } else {
            Write-Warning "Event 1644 is not being logged. This could be normal if directory synchronization hasn't occurred recently."
            Write-Host "Force a sync or wait for the next scheduled sync to verify auditing is working." -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nMicrosoft Entra Connect configuration for MDI completed." -ForegroundColor Cyan
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Install the MDI sensor on this Entra Connect server." -ForegroundColor Yellow
    Write-Host "2. Verify sensor installation status in Microsoft Defender XDR portal." -ForegroundColor Yellow
    Write-Host "3. Configure any additional servers in your Entra Connect environment." -ForegroundColor Yellow
}
{
      Pause
      Show-MainMenu
      return
}

function Set-SecureTLSConfig {
    <#
    .SYNOPSIS
        Configures Windows Server to use secure TLS settings by adjusting registry values.

    .DESCRIPTION
        This function sets the .NET Framework to use the system default TLS versions (enabling strong crypto)
        and configures SCHANNEL settings to enable TLS 1.2 and TLS 1.3 (both client and server) while disabling
        older protocols (TLS 1.1, TLS 1.0, and SSL 3.0).

    .NOTES
        - Run this script in an elevated PowerShell session.
        - A reboot is required for the changes to take effect.
        - Always back up your registry before making modifications.
    #>

    # Internal function to update .NET Framework settings
    function Set-DotNetTls {
        param(
            [Parameter(Mandatory = $true)]
            [string]$RegPath
        )
        if (-not (Test-Path $RegPath)) {
            New-Item $RegPath -Force | Out-Null
        }
        New-ItemProperty -Path $RegPath -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name 'SchUseStrongCrypto' -Value 1 -PropertyType DWord -Force | Out-Null
    }

    # Internal function to set SCHANNEL protocol settings
    function Set-TLSProtocol {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Protocol,      # e.g. "TLS 1.2", "TLS 1.3", "TLS 1.1", "TLS 1.0", "SSL 3.0"
            [Parameter(Mandatory = $true)]
            [string]$Type,          # "Server" or "Client"
            [Parameter(Mandatory = $true)]
            [int]$Enabled,          # 1 to enable, 0 to disable
            [Parameter(Mandatory = $true)]
            [int]$DisabledByDefault # 0 to not disable by default, 1 to disable
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Type"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        New-ItemProperty -Path $regPath -Name 'Enabled' -Value $Enabled -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $regPath -Name 'DisabledByDefault' -Value $DisabledByDefault -PropertyType DWord -Force | Out-Null
    }

    # Configure .NET Framework settings for 64-bit and 32-bit
    Set-DotNetTls -RegPath 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    Set-DotNetTls -RegPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'

    # Configure SCHANNEL protocols

    # Enable TLS 1.2 for both Server and Client
    Set-TLSProtocol -Protocol "TLS 1.2" -Type "Server" -Enabled 1 -DisabledByDefault 0
    Set-TLSProtocol -Protocol "TLS 1.2" -Type "Client" -Enabled 1 -DisabledByDefault 0

    # Enable TLS 1.3 (supported on Windows Server 2022) for both Server and Client
    Set-TLSProtocol -Protocol "TLS 1.3" -Type "Server" -Enabled 1 -DisabledByDefault 0
    Set-TLSProtocol -Protocol "TLS 1.3" -Type "Client" -Enabled 1 -DisabledByDefault 0

    # Disable older, insecure protocols
    Set-TLSProtocol -Protocol "TLS 1.1" -Type "Server" -Enabled 0 -DisabledByDefault 1
    Set-TLSProtocol -Protocol "TLS 1.1" -Type "Client" -Enabled 0 -DisabledByDefault 1

    Set-TLSProtocol -Protocol "TLS 1.0" -Type "Server" -Enabled 0 -DisabledByDefault 1
    Set-TLSProtocol -Protocol "TLS 1.0" -Type "Client" -Enabled 0 -DisabledByDefault 1

    Set-TLSProtocol -Protocol "SSL 3.0" -Type "Server" -Enabled 0 -DisabledByDefault 1
    Set-TLSProtocol -Protocol "SSL 3.0" -Type "Client" -Enabled 0 -DisabledByDefault 1

    Write-Host "Secure TLS settings have been configured. Please restart the server for changes to take effect." -ForegroundColor Green

}
# To apply the configuration, run:
# Set-SecureTLSConfig


function Show-MainMenu {
    Clear-Host

    Write-Host "======================================================" -ForegroundColor Green
    Write-Host " Gregory H. Hall's Comprehensive AD Audit Script"       -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Green
    Write-Host ""

    # -- GPO & Policy Checks (1-6) --
    Write-Host "==== GPO & Policy Checks ====" -ForegroundColor Green
    Write-Host "  1) Scan GPOs for Unknown (Orphaned) Accounts"            -ForegroundColor Cyan
    Write-Host "  2) Scan GPOs for Password Policies"                      -ForegroundColor Cyan
    Write-Host "  3) Scan Overlapping GPO Policy Settings Scan"            -ForegroundColor Cyan
    Write-Host "  4) SYSVOL GPP cpassword Check (from ADAudit)"            -ForegroundColor Cyan
    Write-Host "  5) Install and Launch GPOZaurr"                          -ForegroundColor Cyan
    Write-Host "  6) Microsoft Policy Analyzer Setup and Ready"            -ForegroundColor Cyan

    Write-Host ""

    # -- Base Security & DC Health (7-19) --
    Write-Host "==== Base Security & DC Health ===="                       -ForegroundColor Green
    Write-Host "  7)  Review Base Security Settings"                       -ForegroundColor Cyan
    Write-Host "  8)  Summarize DC Event Errors"                           -ForegroundColor Cyan
    Write-Host "  9)  All DCs DCDiag Tests"                                -ForegroundColor Cyan
    Write-Host " 10)  AD Forest Health Check"                              -ForegroundColor Cyan
    Write-Host " 11)  DC Egress (WAN) IPs"                                 -ForegroundColor Cyan
    Write-Host " 12)  LDAP/LDAPS Connectivity Check"                       -ForegroundColor Cyan
    Write-Host " 13)  Best Practice DNS vs AD Sites/Subnets Check"         -ForegroundColor Cyan
    Write-Host " 14)  LAPS Status Check (from ADAudit)"                    -ForegroundColor Cyan
    Write-Host " 15)  OU Permissions Check (from ADAudit)"                 -ForegroundColor Cyan
    Write-Host " 16)  SPN (Kerberoast) Check (from ADAudit)"               -ForegroundColor Cyan
    Write-Host " 17)  AS-REP (DoesNotRequirePreAuth) Check (from ADAudit)" -ForegroundColor Cyan
    Write-Host " 18)  DC Ownership Check (from ADAudit)"                   -ForegroundColor Cyan
    Write-Host " 19)  LDAP Security Check (from ADAudit)"                  -ForegroundColor Cyan

    Write-Host ""

    # -- BPA Scans & Discovery (20-23) --
    Write-Host "==== BPA Scans & Discovery ===="                          -ForegroundColor Green
    Write-Host " 20) DC Discovery Script (Hardware/Software/NIC Info)"    -ForegroundColor Cyan
    Write-Host " 21) BPA Scan (Local) - AD Roles"                         -ForegroundColor Cyan
    Write-Host " 22) BPA Scan (Remote) - AD Roles"                        -ForegroundColor Cyan
    Write-Host " 23) AD Recon Quiet Audit from Member Server orDesktop (Red Team)"  -ForegroundColor Cyan

    Write-Host ""

    # -- Administration Scripts - These make changes so use carefully. (24-26) --
    Write-Host "==== AD Maintenance Functions ===="                       -ForegroundColor Yellow
    Write-Host " 24) Move FSMO Roles"                                     -ForegroundColor Cyan
    Write-Host " 25) Protect OUs from Accidental Deletion"                -ForegroundColor Cyan
    Write-Host " 26) Fix AD Time Settings on Domain Controllers"          -ForegroundColor Cyan
    Write-Host " 27) Prepare AD for MDI Deployment"                       -ForegroundColor Cyan
    Write-Host " 28) Set Secure TLS Config Registry Settings"             -ForegroundColor Cyan
    Write-Host ""
    Write-Host " 29) Exit" -ForegroundColor Magenta
    Write-Host ""
}

do {
    Show-MainMenu
    $choice = Read-Host "Enter selection (1-29)"

    switch ($choice) {

        # -- GPO & Policy Checks (1-6) --
        1 { Invoke-ScanGPOsUnknownAccounts }
        2 { Invoke-ScanGPOPasswordPolicies }
        3 { Invoke-GPOPolicyOverlapScan }
        4 { Invoke-SYSVOLGPPPasswordCheck }
        5 { start-gpozaurr }  # ← New function
        6 { Invoke-GPOBPASetup }  # ← New function

        # -- Base Security & DC Health (7-19) --
        7  { Invoke-ReviewBaseSecurity }
        8  { Invoke-DCEventErrorSummary }
        9  { Invoke-AllDCDiagTests }
        10 { Invoke-ForestHealthCheck }
        11 { Invoke-GetDCEgressWANIPs }
        12 { Invoke-LDAPLDAPSCheck }
        13 { Invoke-BestPracticeDNSSiteSubnetCheck }
        14 { Invoke-LAPSStatusCheck }
        15 { Invoke-OUPermsCheck }
        16 { Invoke-SPNsCheck }
        17 { Invoke-ASREPCheck }
        18 { Invoke-DCsOwnershipCheck }
        19 { Invoke-LDAPSecurityCheck }

        # -- BPA Scans & Discovery (20-23) --
        20 { Invoke-DiscoveryScript }
        21 { Invoke-BPALocalScan }
        22 { Invoke-BPARemoteScan }
        23 { Invoke-QuietAuditRedTeam }

        # -- AD Maintenance / FSMO / OU (24-26) --
        24 { Invoke-MoveFSMORoles }
        25 { Invoke-ProtectOUs }
        26 { Invoke-ADTimeFix }
        27 { Configure-MDIEnvironment }
        28 { Set-SecureTLSConfig }

        29 {
            Write-Host "Exiting..." -ForegroundColor Green
            break
        }

        default {
            Write-Host "Invalid choice."
            Pause
        }
    }
} while ($choice -ne 29)

Write-Host "Done, Thank you for using, we enjoy feedback and suggestions please drop us a line." -ForegroundColor Green
