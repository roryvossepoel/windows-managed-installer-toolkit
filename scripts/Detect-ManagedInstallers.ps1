#requires -version 5.1

# Toolkit version: 0.1.1

$ErrorActionPreference = 'Stop'
$toolkitVersion = '0.1.1'
Write-Output "App Control for Business Managed Installer Toolkit version $toolkitVersion"
$policyRoot = 'HKLM:\Software\Policies\ManagedInstallers'
$managedMarkers = @('ManagedInstallers:')
$dummyRuleIds = @('86f235ad-3f7b-4121-bc95-ea8bde3a5db5', '9420c496-046d-45ab-bd0e-455b2649e41e')
$ruleSlotCount = 20
$blockedBinaries = @(
    'MSIEXEC.EXE', 'POWERSHELL.EXE', 'PWSH.EXE', 'CMD.EXE', 'EXPLORER.EXE',
    'RUNDLL32.EXE', 'REGSVR32.EXE', 'WSCRIPT.EXE', 'CSCRIPT.EXE', 'INSTALLUTIL.EXE'
)

function Test-VersionString([string]$Value) {
    if($Value -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }
    try { [void][version]$Value; return $true } catch { return $false }
}

function New-StableGuid([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToUpperInvariant())) }
    finally { $sha.Dispose() }
    $bytes = New-Object byte[] 16
    [Array]::Copy($hash, $bytes, 16)
    return ([guid]::new($bytes)).Guid
}

function Assert-ManagedInstallerRule($Rule) {
    if([string]::IsNullOrWhiteSpace($Rule.Name)) { throw 'Managed Installer rule name is empty.' }
    if($Rule.Publisher -notmatch '(^|,\s*)O=' -or $Rule.Publisher.Contains('*')) { throw "Invalid publisher in Managed Installer rule '$($Rule.Name)'." }
    if($Rule.Product.Contains('*') -or [string]::IsNullOrWhiteSpace($Rule.Product)) { throw "Invalid product in Managed Installer rule '$($Rule.Name)'." }
    if($Rule.Binary -notmatch '^[^\\/:*?""<>|]+\.exe$' -or $Rule.Binary.ToUpperInvariant() -in $blockedBinaries) { throw "Unsafe binary in Managed Installer rule '$($Rule.Name)'." }
    if(-not (Test-VersionString $Rule.Minimum)) { throw "Invalid four-part minimum version in Managed Installer rule '$($Rule.Name)'." }
}

function Get-DesiredRules {
    $rules = [Collections.Generic.List[object]]::new()
    foreach($slotNumber in 1..$ruleSlotCount) {
        $slot = '{0:D2}' -f $slotNumber
        $path = Join-Path $policyRoot "Rules\$slot"
        if(-not (Test-Path $path)) { continue }
        $config = Get-ItemProperty $path
        if($null -eq $config.PSObject.Properties['Enabled'] -or [int]$config.Enabled -ne 1) { continue }
        $rule = [pscustomobject]@{ Name=([string]$config.Name).Trim(); Publisher=([string]$config.Publisher).Trim(); Product=([string]$config.Product).Trim(); Binary=([string]$config.Binary).Trim().ToUpperInvariant(); Minimum=([string]$config.MinimumVersion).Trim() }
        Assert-ManagedInstallerRule $rule
        $rule | Add-Member NoteProperty Id (New-StableGuid "RULE-SLOT-$slot")
        $rules.Add($rule)
    }
    return $rules
}

function Get-ConfiguredRuleCount {
    $count = 0
    foreach($slotNumber in 1..$ruleSlotCount) {
        $slot = '{0:D2}' -f $slotNumber
        $path = Join-Path $policyRoot "Rules\$slot"
        if(-not (Test-Path -LiteralPath $path)) { continue }
        $config = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if($null -ne $config -and $null -ne $config.PSObject.Properties['Enabled']) { $count++ }
    }
    return $count
}

function Get-RuleNodes([xml]$Policy) {
    @($Policy.AppLockerPolicy.RuleCollection | ForEach-Object { @($_.ChildNodes | Where-Object { $_.LocalName -match 'Rule$' }) })
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    Write-Output '[Policy] Loading local and effective AppLocker policies.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $knownIds = $dummyRuleIds
    $localOwned = @(Get-RuleNodes $local | Where-Object { $description = [string]$_.Description; ([string]$_.Id -in $knownIds) -or @($managedMarkers | Where-Object {$description.StartsWith($_)}).Count -gt 0 })

    if($configuredRuleCount -eq 0) {
        if($localOwned.Count -gt 0) { Write-Output 'Noncompliant: no rule slots are configured, but toolkit-owned rules still exist.'; exit 1 }
        Write-Output 'Compliant: no Managed Installer rules are configured and no toolkit-owned rules remain.'
        exit 0
    }

    $desired = @(Get-DesiredRules)
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    $desiredIds = @($desired.Id)
    $stale = @($localOwned | Where-Object { ([string]$_.Id -notin $desiredIds) -and ([string]$_.Id -notin $dummyRuleIds) })
    if($stale.Count -gt 0 -or ($desired.Count -eq 0 -and $localOwned.Count -gt 0)) { Write-Output 'Noncompliant: stale managed rules exist.'; exit 1 }
    if($desired.Count -eq 0) { Write-Output 'Compliant: all configured Managed Installer rules are disabled and toolkit-owned rules are removed.'; exit 0 }
    Write-Output '[Policy] Checking the Managed Installer collection and desired publisher rules.'
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { Write-Output 'Noncompliant: Managed Installer rule collection is not enabled.'; exit 1 }
    Write-Output '[Policy] Checking EXE and DLL service enforcement and SystemApps state.'
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { Write-Output "Noncompliant: $collectionType rule collection is missing."; exit 1 }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { Write-Output "Noncompliant: services enforcement is not enabled for the $collectionType rule collection."; exit 1 }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            Write-Output "Noncompliant: SystemApps is not enabled for the $collectionType rule collection."
            exit 1
        }
    }
    foreach($rule in $desired) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if(-not $node -or [string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { Write-Output "Noncompliant: $($rule.Name)"; exit 1 }
    }
    Write-Output '[Runtime] Checking Managed Installer services.'
    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') { if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { Write-Output "Noncompliant: service $serviceName"; exit 1 } }
    Write-Output '[Runtime] Checking the compiled Managed Installer policy.'
    $binaryRoot = if([Environment]::Is64BitProcess) { "$env:windir\System32" } else { "$env:windir\Sysnative" }
    $managedInstallerPolicyPath = Join-Path $binaryRoot 'AppLocker\ManagedInstaller.AppLocker'
    if(-not (Test-Path -LiteralPath $managedInstallerPolicyPath)) { Write-Output "Noncompliant: compiled policy missing: $managedInstallerPolicyPath"; exit 1 }
    Write-Output "Compliant: $($desired.Count) Managed Installer rule(s)."
    exit 0
}
catch {
    Write-Output "Noncompliant: $($_.Exception.Message)"
    exit 1
}
