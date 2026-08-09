#requires -version 5.1

$ErrorActionPreference = 'Stop'
$policyRoot = 'HKLM:\Software\Policies\ManagedInstallers'
$managedMarkers = @('ManagedInstallers:', 'SolidoMI:')
$dummyRuleIds = @('86f235ad-3f7b-4121-bc95-ea8bde3a5db5', '9420c496-046d-45ab-bd0e-455b2649e41e')

function Get-PresetDefinitions {
    @(
        [pscustomobject]@{ Key='IME'; Id='70104ed1-5589-4f29-bb46-2692a86ec011'; Name='Intune Management Extension'; Publisher='O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'; Product='MICROSOFT® INTUNE™'; Binary='MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE'; Minimum='1.38.300.1' },
        [pscustomobject]@{ Key='OMADM'; Id='10b68b23-3f6d-4e4b-86ef-10fc8084f297'; Name='OMA Device Management Client'; Publisher='O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'; Product='MICROSOFT® WINDOWS® OPERATING SYSTEM'; Binary='OMADMCLIENT.EXE'; Minimum='10.0.22621.1485' },
        [pscustomobject]@{ Key='EPM'; Id='bc6b9dea-ba4a-46f2-aadc-311211de86e5'; Name='Endpoint Privilege Management V2'; Publisher='O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'; Product='MICROSOFT® INTUNE™'; Binary='EPMSERVICESTUB.EXE'; Minimum='6.2411.82.2000' },
        [pscustomobject]@{ Key='Autopatch'; Id='5ce9d2df-3c05-477f-8ff6-867dee40a803'; Name='Windows Autopatch'; Publisher='O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'; Product='MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT'; Binary='MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT.EXE'; Minimum='1.2.2291.137' },
        [pscustomobject]@{ Key='AdobeInstaller'; Id='985c6777-1a4d-4d75-821e-3736407fca0f'; Name='Adobe Installer'; Publisher='O=ADOBE INC., L=SAN JOSE, S=CA, C=US'; Product='ADOBE INSTALLER'; Binary='ADOBE INSTALLER.EXE'; Minimum='5.11.0.522' },
        [pscustomobject]@{ Key='AdobeHelper'; Id='75d002f9-c2ca-4e06-a5ee-9679cc4e9d8f'; Name='Adobe Install Helper'; Publisher='O=ADOBE INC., L=SAN JOSE, S=CA, C=US'; Product='ADOBE INSTALL HELPER'; Binary='ADOBE INSTALL HELPER.EXE'; Minimum='5.11.0.522' },
        [pscustomobject]@{ Key='AdobeUpdate'; Id='5997a46b-86e7-4cd8-8e1b-ecfed397b636'; Name='Adobe Update Service'; Publisher='O=ADOBE INC., L=SAN JOSE, S=CA, C=US'; Product='ADOBE UPDATE SERVICE'; Binary='ADOBE UPDATE SERVICE.EXE'; Minimum='5.11.0.522' },
        [pscustomobject]@{ Key='GoogleUpdater'; Id='e581ea0f-3724-4ff3-9df4-19e0dcf543a7'; Name='Google Update Service'; Publisher='O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US'; Product='GOOGLE UPDATER (X86)'; Binary='GOOGLEUPDATE.EXE'; Minimum='143.0.7482.0' },
        [pscustomobject]@{ Key='AcrobatService'; Id='0366b147-3270-4155-bb87-fca4f47c49cc'; Name='Adobe Acrobat Update Service'; Publisher='O=ADOBE INC., L=SAN JOSE, S=CA, C=US'; Product='ACROBAT UPDATE SERVICE'; Binary='ARMSVC.EXE'; Minimum='1.824.460.1149' },
        [pscustomobject]@{ Key='AdobeARM'; Id='09c19128-234f-4176-a836-0b272fbc858f'; Name='Adobe Reader and Acrobat Manager'; Publisher='O=ADOBE INC., L=SAN JOSE, S=CA, C=US'; Product='ADOBE READER AND ACROBAT MANAGER'; Binary='ADOBEARM.EXE'; Minimum='1.824.460.1149' }
    )
}

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
    foreach($preset in Get-PresetDefinitions) {
        $path = Join-Path $policyRoot "Presets\$($preset.Key)"
        if(-not (Test-Path $path)) { continue }
        $config = Get-ItemProperty $path
        if([int]$config.Enabled -ne 1) { continue }
        $minimum = if([string]::IsNullOrWhiteSpace([string]$config.MinimumVersion)) { $preset.Minimum } else { [string]$config.MinimumVersion }
        if(-not (Test-VersionString $minimum)) { throw "Invalid minimum version for preset $($preset.Key)." }
        $product = if([string]::IsNullOrWhiteSpace([string]$config.ProductOverride)) { $preset.Product } else { [string]$config.ProductOverride }
        if($product.Contains('*')) { throw "Product override for $($preset.Key) contains a wildcard." }
        $rules.Add([pscustomobject]@{ Id=$preset.Id; Name=$preset.Name; Publisher=$preset.Publisher; Product=$product; Binary=$preset.Binary; Minimum=$minimum })
    }
    foreach($slotNumber in 1..20) {
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
    $knownIds = @((Get-PresetDefinitions).Id) + $dummyRuleIds
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
