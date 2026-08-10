#requires -version 5.1

# Toolkit version: 0.1.4

$ErrorActionPreference = 'Stop'
$toolkitVersion = '0.1.4'
$policyRoot = 'HKLM:\Software\Policies\ManagedInstallers'
$managedMarkers = @('ManagedInstallers:')
$dummyRuleIds = @('86f235ad-3f7b-4121-bc95-ea8bde3a5db5', '9420c496-046d-45ab-bd0e-455b2649e41e')
$ruleSlotCount = 20
$blockedBinaries = @(
    'MSIEXEC.EXE', 'POWERSHELL.EXE', 'PWSH.EXE', 'CMD.EXE', 'EXPLORER.EXE',
    'RUNDLL32.EXE', 'REGSVR32.EXE', 'WSCRIPT.EXE', 'CSCRIPT.EXE', 'INSTALLUTIL.EXE'
)
$binaryRoot = if([Environment]::Is64BitProcess) { "$env:windir\System32" } else { "$env:windir\Sysnative" }
$managedInstallerPolicyPath = Join-Path $binaryRoot 'AppLocker\ManagedInstaller.AppLocker'
$policyBinaryTimeoutSeconds = 300
$logRoot = Join-Path $env:ProgramData 'ManagedInstallers'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
Start-Transcript -Path (Join-Path $logRoot 'Remediation.log') -Append -Force | Out-Null
Write-Output "App Control for Business Managed Installer Toolkit version $toolkitVersion"

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
        $rule = [pscustomobject]@{ Slot=$slot; Name=([string]$config.Name).Trim(); Publisher=([string]$config.Publisher).Trim(); Product=([string]$config.Product).Trim(); Binary=([string]$config.Binary).Trim().ToUpperInvariant(); Minimum=([string]$config.MinimumVersion).Trim() }
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

function Remove-ReconciledRules([xml]$Policy) {
    foreach($collection in @($Policy.AppLockerPolicy.RuleCollection)) {
        $removedFromCollection = $false
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $localManagedRules = @(
        $LocalPolicy.AppLockerPolicy.RuleCollection |
            Where-Object Type -eq 'ManagedInstaller' |
            ForEach-Object { @($_.ChildNodes | Where-Object { $_.LocalName -match 'Rule
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }
    $effectiveManagedRules = @($mi[0].ChildNodes | Where-Object { $_.LocalName -match 'Rule
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking the complete Managed Installer collection.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $reconciledRuleCount = 0
    $existingManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isManagedInstallerRule = [string]$collection.Type -eq 'ManagedInstaller'
            if($isManagedInstallerRule -or ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $reconciledRuleCount++
                if($isManagedInstallerRule) {
                    [void]$existingManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($reconciledRuleCount -gt 0) {
        foreach($existingRule in $existingManagedRules) {
            Write-Output "[Policy] Removing existing Managed Installer rule: '$([string]$existingRule.Name)'."
        }
        Remove-ReconciledRules $local
        Save-Policy $local
        Write-Output "Removed $reconciledRuleCount reconciled rule(s). Unrelated EXE, DLL, MSI, Script, and packaged-app rules were preserved."
    } else {
        Write-Output 'No existing Managed Installer or toolkit infrastructure rules required removal.'
    }

    if($desired.Count -eq 0) {
        [xml]$effectiveAfterCleanup = Get-AppLockerPolicy -Effective -Xml
        $remainingEffectiveRules = @(
            $effectiveAfterCleanup.AppLockerPolicy.RuleCollection |
                Where-Object Type -eq 'ManagedInstaller' |
                ForEach-Object { @($_.ChildNodes | Where-Object { $_.LocalName -match 'Rule
    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    $effectiveManagedRules = @($mi[0].ChildNodes | Where-Object { $_.LocalName -match 'Rule    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
    if($effectiveManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($effectiveManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
        )
        if($remainingEffectiveRules.Count -gt 0) {
            throw "Managed Installer cleanup is being overridden by another policy source; $($remainingEffectiveRules.Count) effective rule(s) remain."
        }
        Write-Output 'No Managed Installer rule slots are enabled; the Managed Installer collection is empty.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
    if($effectiveManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($effectiveManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
    if($effectiveManagedRules.Count -ne $desired.Count) {
        throw "Effective Managed Installer collection contains $($effectiveManagedRules.Count) rule(s); expected $($desired.Count). Another policy source may be contributing rules."
    }
    $unexpectedEffectiveRules = @($effectiveManagedRules | Where-Object { [string]$_.Id -notin @($desired.Id) })
    if($unexpectedEffectiveRules.Count -gt 0) {
        throw "Unexpected effective Managed Installer rule remains: '$([string]$unexpectedEffectiveRules[0].Name)'."
    }
    foreach($rule in $desired) {
        if(-not @($mi[0].ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
    if($effectiveManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($effectiveManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
        )
        if($remainingEffectiveRules.Count -gt 0) {
            throw "Managed Installer cleanup is being overridden by another policy source; $($remainingEffectiveRules.Count) effective rule(s) remain."
        }
        Write-Output 'No Managed Installer rule slots are enabled; the Managed Installer collection is empty.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
    if($effectiveManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($effectiveManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 }) }
    )
    if($localManagedRules.Count -ne $Rules.Count) { return $false }
    if(@($localManagedRules | Where-Object { [string]$_.Id -notin @($Rules.Id) }).Count -gt 0) { return $false }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })) {
            $description = [string]$node.Description
            $removeNode = ([string]$collection.Type -eq 'ManagedInstaller') -or
                ([string]$node.Id -in $dummyRuleIds) -or
                @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($removeNode) {
                [void]$collection.RemoveChild($node)
                $removedFromCollection = $true
            }
        }
        $remainingRules = @($collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule
function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
 })
        if($removedFromCollection -and $remainingRules.Count -eq 0) { [void]$Policy.AppLockerPolicy.RemoveChild($collection) }
    }
}

function Save-Policy([xml]$Policy, [switch]$Merge) {
    $path = Join-Path $env:TEMP ("ManagedInstallers-{0}.xml" -f [guid]::NewGuid())
    try {
        $Policy.Save($path)
        if($Merge) { Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop }
        else { Set-AppLockerPolicy -XmlPolicy $path -ErrorAction Stop }
    }
    finally { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-XmlText([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

function New-DesiredPolicy([object[]]$Rules) {
    $ruleXml = foreach($rule in $Rules) {
        $id = ConvertTo-XmlText $rule.Id; $name = ConvertTo-XmlText $rule.Name; $publisher = ConvertTo-XmlText $rule.Publisher
        $product = ConvertTo-XmlText $rule.Product; $binary = ConvertTo-XmlText $rule.Binary; $minimum = ConvertTo-XmlText $rule.Minimum
        @"
        <FilePublisherRule Id="$id" Name="$name" Description="ManagedInstallers:Managed" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions><FilePublisherCondition PublisherName="$publisher" ProductName="$product" BinaryName="$binary"><BinaryVersionRange LowSection="$minimum" HighSection="*" /></FilePublisherCondition></Conditions>
        </FilePublisherRule>
"@
    }
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Managed Installer benign DLL rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Managed Installer benign EXE rule" Description="ManagedInstallers:Infrastructure" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" /></Conditions></FilePathRule>
    <RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions></RuleCollectionExtensions>
  </RuleCollection>
  <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
    $($ruleXml -join [Environment]::NewLine)
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Test-DesiredState([object[]]$Rules, [xml]$LocalPolicy) {
    if($Rules.Count -eq 0) { return $false }

    $allowedOwnedIds = @($dummyRuleIds) + @($Rules.Id)
    foreach($collection in @($LocalPolicy.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            $isOwned = ([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0
            if($isOwned -and [string]$node.Id -notin $allowedOwnedIds) { return $false }
        }
    }

    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { return $false }

    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { return $false }
        if([string]$collection[0].RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { return $false }

        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) { return $false }
    }

    foreach($rule in $Rules) {
        $node = @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id }) | Select-Object -First 1
        if($null -eq $node) { return $false }
        $condition = $node.Conditions.FilePublisherCondition
        $range = $condition.BinaryVersionRange
        if([string]$condition.PublisherName -cne $rule.Publisher -or [string]$condition.ProductName -cne $rule.Product -or [string]$condition.BinaryName -cne $rule.Binary -or [string]$range.LowSection -ne $rule.Minimum -or [string]$range.HighSection -ne '*') { return $false }
    }

    foreach($serviceName in 'AppIDSvc','appid','applockerfltr') {
        if((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -ne 'Running') { return $false }
    }
    return (Test-Path -LiteralPath $managedInstallerPolicyPath)
}

try {
    Write-Output '[Configuration] Reading Managed Installer settings from the policy registry.'
    $configuredRuleCount = Get-ConfiguredRuleCount
    [object[]]$desired = @()
    if($configuredRuleCount -gt 0) {
        $desired = @(Get-DesiredRules)
    }
    Write-Output "[Configuration] Found $configuredRuleCount configured slot(s), of which $($desired.Count) are enabled."
    foreach($rule in $desired) {
        Write-Output "[Configuration] Enabled rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    Write-Output '[Policy] Loading the local AppLocker policy and checking for previous toolkit-owned rules.'
    [xml]$local = Get-AppLockerPolicy -Local -Xml
    $ownedRuleCount = 0
    $ownedManagedRules = [Collections.Generic.List[object]]::new()
    foreach($collection in @($local.AppLockerPolicy.RuleCollection)) {
        foreach($node in @($collection.ChildNodes | Where-Object { $_.LocalName.EndsWith('Rule') })) {
            $description = [string]$node.Description
            if(([string]$node.Id -in $dummyRuleIds) -or @($managedMarkers | Where-Object { $description.StartsWith($_) }).Count -gt 0) {
                $ownedRuleCount++
                if($description.StartsWith('ManagedInstallers:Managed')) {
                    [void]$ownedManagedRules.Add($node)
                }
            }
        }
    }

    if($desired.Count -gt 0 -and (Test-DesiredState -Rules $desired -LocalPolicy $local)) {
        foreach($rule in $desired) {
            Write-Output "[Validation] Compliant rule [$($rule.Slot)]: '$($rule.Name)'."
        }
        Write-Output '[Validation] Desired Managed Installer state is already compliant; no changes required.'
        Stop-Transcript | Out-Null
        exit 0
    }

    if($ownedRuleCount -gt 0) {
        foreach($existingRule in $ownedManagedRules) {
            Write-Output "[Policy] Removing existing rule: '$([string]$existingRule.Name)'."
        }
        Remove-OwnedRules $local
        Save-Policy $local
        Write-Output "Removed $ownedRuleCount previous toolkit-owned rule(s) while preserving unrelated local AppLocker rules."
    } else {
        Write-Output 'No previous toolkit-owned rules required removal.'
    }

    if($desired.Count -eq 0) {
        Write-Output 'No Managed Installer rule slots are enabled; toolkit-owned rules are absent.'
        Stop-Transcript | Out-Null
        exit 0
    }

    Write-Output '[Runtime] Starting Managed Installer tracking and required AppLocker services.'
    $appidtelPath = if([Environment]::Is64BitProcess) { "$env:windir\System32\appidtel.exe" } else { "$env:windir\Sysnative\appidtel.exe" }
    $appidtel = Start-Process $appidtelPath -ArgumentList 'start -mionly' -Wait -PassThru -WindowStyle Hidden
    if($appidtel.ExitCode -ne 0) { throw "appidtel.exe failed with exit code $($appidtel.ExitCode)." }

    $previousBinaryTimestamp = if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
        (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
    } else { $null }

    Write-Output "[Policy] Merging $($desired.Count) Managed Installer rule(s) and required EXE/DLL extensions."
    foreach($rule in $desired) {
        Write-Output "[Policy] Applying rule [$($rule.Slot)]: '$($rule.Name)'."
    }
    $desiredPolicy = New-DesiredPolicy $desired
    Save-Policy $desiredPolicy -Merge

    Write-Output "[Runtime] Waiting up to $policyBinaryTimeoutSeconds seconds for services and the compiled Managed Installer policy."
    $waitStarted = Get-Date
    $lastProgressSeconds = -30
    $deadline = $waitStarted.AddSeconds($policyBinaryTimeoutSeconds)
    do {
        $running = @('AppIDSvc','appid','applockerfltr' | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' }).Count
        $policyBinaryUpdated = $false
        if(Test-Path -LiteralPath $managedInstallerPolicyPath) {
            $currentBinaryTimestamp = (Get-Item -LiteralPath $managedInstallerPolicyPath -ErrorAction Stop).LastWriteTimeUtc
            $policyBinaryUpdated = ($null -eq $previousBinaryTimestamp) -or ($currentBinaryTimestamp -gt $previousBinaryTimestamp)
        }
        $elapsedSeconds = [int]((Get-Date) - $waitStarted).TotalSeconds
        if($elapsedSeconds -ge ($lastProgressSeconds + 30)) {
            $binaryStatus = if($policyBinaryUpdated) { 'ready' } else { 'waiting' }
            Write-Output "[Runtime] Elapsed: $elapsedSeconds s; services running: $running/3; compiled policy: $binaryStatus."
            $lastProgressSeconds = $elapsedSeconds
        }
        if($running -eq 3 -and $policyBinaryUpdated) { break }
        Start-Sleep 5
    } while((Get-Date) -lt $deadline)
    if($running -ne 3) { throw 'Timed out waiting for Managed Installer services.' }
    if(-not $policyBinaryUpdated) { throw "Managed Installer policy binary was not created or updated within $policyBinaryTimeoutSeconds seconds: $managedInstallerPolicyPath" }

    Write-Output '[Validation] Checking effective rules, collection extensions, registry state, and services.'
    [xml]$effective = Get-AppLockerPolicy -Effective -Xml
    $mi = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller')
    if($mi.Count -ne 1 -or [string]$mi[0].EnforcementMode -ne 'Enabled') { throw 'Managed Installer rule collection is not enabled after remediation.' }
    foreach($collectionType in 'Exe','Dll') {
        $collection = @($effective.AppLockerPolicy.RuleCollection | Where-Object Type -eq $collectionType)
        if($collection.Count -ne 1) { throw "$collectionType rule collection is missing after remediation." }
        $extensions = $collection[0].RuleCollectionExtensions
        if([string]$extensions.ThresholdExtensions.Services.EnforcementMode -ne 'Enabled') { throw "Services enforcement is not enabled for the $collectionType rule collection after remediation." }

        # Get-AppLockerPolicy doesn't reliably round-trip SystemApps in XML.
        # Windows stores SystemApps Allow="Enabled" as the AllowWindows enum value 0.
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collectionType"
        $registryState = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if($null -eq $registryState -or $null -eq $registryState.PSObject.Properties['AllowWindows'] -or [int]$registryState.AllowWindows -ne 0) {
            throw "SystemApps is not enabled for the $collectionType rule collection after remediation."
        }
    }
    foreach($rule in $desired) {
        if(-not @($mi.ChildNodes | Where-Object { $_.LocalName -eq 'FilePublisherRule' -and [string]$_.Id -eq $rule.Id })) { throw "Rule missing after remediation: $($rule.Name)" }
    }
    Write-Output "Successfully reconciled $($desired.Count) Managed Installer rule(s)."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
