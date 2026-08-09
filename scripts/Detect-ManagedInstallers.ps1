#requires -version 5.1

$ErrorActionPreference = 'Stop'
$policyRoot = 'HKLM:\Software\Policies\ManagedInstallers'
$managedMarkers = @('ManagedInstallers:')
$dummyRuleIds = @('86f235ad-3f7b-4121-bc95-ea8bde3a5db5', '9420c496-046d-45ab-bd0e-455b2649e41e')
$customSlotCount = 20

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

function Assert-CustomRule($Rule) {
    $blocked = @('MSIEXEC.EXE','POWERSHELL.EXE','PWSH.EXE','CMD.EXE','WINGET.EXE','EXPLORER.EXE','RUNDLL32.EXE','REGSVR32.EXE','WSCRIPT.EXE','CSCRIPT.EXE','INSTALLUTIL.EXE')
    if([string]::IsNullOrWhiteSpace($Rule.Name)) { throw 'Custom rule name is empty.' }
    if($Rule.Publisher -notmatch '(^|,\s*)O=' -or $Rule.Publisher.Contains('*')) { throw "Invalid publisher in custom rule '$($Rule.Name)'." }
    if($Rule.Product.Contains('*') -or [string]::IsNullOrWhiteSpace($Rule.Product)) { throw "Invalid product in custom rule '$($Rule.Name)'." }
    if($Rule.Binary -notmatch '^[^\\/:*?""<>|]+\.exe$' -or $Rule.Binary.ToUpperInvariant() -in $blocked) { throw "Unsafe binary in custom rule '$($Rule.Name)'." }
    if(-not (Test-VersionString $Rule.Minimum)) { throw "Invalid four-part minimum version in custom rule '$($Rule.Name)'." }
}

function Get-DesiredRules {
    $rules = [Collections.Generic.List[object]]::new()
    foreach($slotNumber in 1..$customSlotCount) {
        $slot = '{0:D2}' -f $slotNumber
        $path = Join-Path $policyRoot "Custom\$slot"
        if(-not (Test-Path $path)) { continue }
        $config = Get-ItemProperty $path
        if([int]$config.Enabled -ne 1) { continue }
        $rule = [pscustomobject]@{ Name=([string]$config.Name).Trim(); Publisher=([string]$config.Publisher).Trim(); Product=([string]$config.Product).Trim(); Binary=([string]$config.Binary).Trim().ToUpperInvariant(); Minimum=([string]$config.MinimumVersion).Trim() }
        Assert-CustomRule $rule
        $rule | Add-Member NoteProperty Id (New-StableGuid "CUSTOM-SLOT-$slot")
        $rules.Add($rule)
    }
    return $rules
}

function Get-RuleNodes([xml]$Policy) {
    @($Policy.AppLockerPolicy.RuleCollection | ForEach-Object { @($_.ChildNodes | Where-Object { $_.LocalName -match 'Rule$' }) })
}

try {
    $managementValue = if(Test-Path $policyRoot) { Get-ItemPropertyValue $policyRoot -Name Enabled -ErrorAction SilentlyContinue } else { $null }
    if($null -eq $managementValue) { Write-Output 'Compliant: management is not configured; no action requested.'; exit 0 }
    $managementEnabled = [int]$managementValue -eq 1
    $desired = if($managementEnabled) { @(Get-DesiredRules) } else { @() }
    if($managementEnabled -and $desired.Count -eq 0) { Write-Output 'Noncompliant: management is enabled but no rules are selected.'; exit 1 }
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $knownIds = $dummyRuleIds
    $localOwned = @(Get-RuleNodes $local | Where-Object { $description = [string]$_.Description; ([string]$_.Id -in $knownIds) -or @($managedMarkers | Where-Object {$description.StartsWith($_)}).Count -gt 0 })
    $desiredIds = @($desired.Id)
    $stale = @($localOwned | Where-Object { ([string]$_.Id -notin $desiredIds) -and ([string]$_.Id -notin $dummyRuleIds })
    if($stale.Count -gt 0 -or ((-not $managementEnabled -or $desired.Count -eq 0) -and $localOwned.Count -gt 0)) { Write-Output 'Noncompliant: stale managed rules exist.'; exit 1 }
    if(-not $managementEnabled) { Write-Output 'Compliant: package-owned rules are removed.'; exit 0 }
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    foreach($rule in $desired) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if(-not $node -or [string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { Write-Output "Noncompliant: $($rule.Name)"; exit 1 }
    }
    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') { if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { Write-Output "Noncompliant: service $serviceName"; exit 1 } }
    $binaryRoot = if([Environment]::Is64BitProcess) { "$env:windir\System32" } else { "$env:windir\Sysnative" }
    if(-not (Test-Path (Join-Path $binaryRoot 'AppLocker\ManagedInstaller.AppLocker'))) { Write-Output 'Noncompliant: policy binary missing.'; exit 1 }
    Write-Output "Compliant: $($desired.Count) Managed Installer rule(s)."
    exit 0
}
catch {
    Write-Output "Noncompliant: $($_.Exception.Message)"
    exit 1
}
