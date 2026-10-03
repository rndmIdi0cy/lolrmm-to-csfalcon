#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a CrowdStrike Falcon custom IOA rule group that flags common RMM tool executables.
.DESCRIPTION
    Downloads the RMM tool catalog from lolrmm.io, generates one Windows Process custom IOA rule
    per tool that has at least one identifiable .exe pattern, packages the rule group as a
    Falcon-importable JSON/zip file, and optionally uploads it via the PSFalcon module.
.PARAMETER StartingRuleId
    The first instance_id assigned to generated rules. Each subsequent rule increments by 1.
.PARAMETER ZipFile
    Path to the zip archive that will contain the exported rule group JSON.
.PARAMETER EnableRules
    Create the rules themselves in an enabled state. Default is disabled.
.PARAMETER DisableRuleGroup
    Create the rule group in a disabled state. Default is enabled.
.PARAMETER Severity
    pattern_severity applied to every generated rule.
.PARAMETER ResponseType
    Disposition applied to every generated rule: monitor (10), detect (20, default), or block (30).
.PARAMETER RmmToolsUrl
    Source URL for the RMM tool catalog JSON.
.PARAMETER OutputJsonPath
    Local path for the intermediate rule group JSON file before compression.
.EXAMPLE
    ./Set-FalconRmmIOA.ps1 -StartingRuleId 60000 -ResponseType block -EnableRules
#>

[CmdletBinding()]
param(
    [int]$StartingRuleId = 50000,
    [string]$ZipFile = "rmm_tools.zip",
    [switch]$EnableRules,
    [switch]$DisableRuleGroup,
    [ValidateSet("informational", "low", "medium", "high", "critical")]
    [string]$Severity = "medium",
    [ValidateSet("monitor", "detect", "block")]
    [string]$ResponseType = "detect",
    [string]$RmmToolsUrl = "https://lolrmm.io/api/rmm_tools.json",
    [string]$OutputJsonPath = "IOAGroup.json"
)

#region Functions

function Write-LogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("warning", "error", "success", "info")]
        [string]$Level = "info"
    )

    $colorMap = @{ info = 'Cyan'; success = 'Green'; warning = 'Yellow'; error = 'Red' }
    $symbolMap = @{ info = '*'; success = '+'; warning = '?'; error = '!' }

    Write-Host "[$($symbolMap[$Level])] $(Get-Date -Format G) - $Message" -ForegroundColor $colorMap[$Level]
}

function ConvertTo-ExeNamePattern {
    # Escapes regex metacharacters generically (not just '.'), then restores '*' as a '.*' wildcard,
    # so filenames with parentheses/brackets/etc. from the feed don't break the generated regex.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path
    )
    process {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $escaped = [regex]::Escape($baseName) -replace '\\\*', '.*'
        $escaped -replace ' ', '\s+'
    }
}

function Get-RMMData {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    try {
        Invoke-RestMethod -Uri $Url
    }
    catch {
        Write-LogEntry -Message "Failed to retrieve or parse JSON data from $Url.`nError: $_" -Level error
        throw
    }
}

function Get-ExeFileNames {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory)]
        $Tool
    )

    $exeFileNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($path in @($Tool.Details.InstallationPaths)) {
        if ($path -match '\.exe$') {
            [void]$exeFileNames.Add((ConvertTo-ExeNamePattern -Path $path))
        }
    }

    $peExeFiles = @($Tool.Details.PEMetaData).Where({ $_.Filename -match '\.exe$' })
    foreach ($pe in $peExeFiles) {
        [void]$exeFileNames.Add((ConvertTo-ExeNamePattern -Path $pe.Filename))
    }

    foreach ($file in @($Tool.Artifacts.Disk.File)) {
        if ($file -match '\.exe$') {
            [void]$exeFileNames.Add((ConvertTo-ExeNamePattern -Path $file))
        }
    }

    return $exeFileNames
}

function Get-RuleGroupId {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    # 32 hex chars, same shape as the MD5 hash it replaces, without needing to dispose a crypto object.
    [guid]::NewGuid().ToString('N')
}

function New-RuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Tool,
        [Parameter(Mandatory)] [System.Collections.Generic.HashSet[string]]$ExeFileNames,
        [Parameter(Mandatory)] [string]$RuleId,
        [Parameter(Mandatory)] [string]$RuleGroupId,
        [Parameter(Mandatory)] [bool]$EnableRule,
        [Parameter(Mandatory)] [int]$ResponseAction,
        [Parameter(Mandatory)] [string]$Severity
    )

    $description = ($Tool.Description -replace '\\n', '' -replace ' More information will be added as it becomes available\.', '').Trim()
    $combinedExeFileNames = "(?i).*\\({0})\.exe" -f ($ExeFileNames -join '|')

    [PSCustomObject]@{
        instance_id      = $RuleId
        ruletype_id      = "1" # Windows Process
        comment          = ""
        enabled          = $EnableRule
        deleted          = $false
        rulegroup_id     = $RuleGroupId
        instance_version = 1
        name             = $Tool.Name
        description      = $description
        pattern_severity = $Severity
        disposition_id   = $ResponseAction # 10 = Monitor, 20 = Detect, 30 = Block Execution
        field_values     = @(
            [PSCustomObject]@{
                name   = "ImageFilename"
                value  = ""
                label  = "Image Filename"
                type   = "excludable"
                values = @(
                    [PSCustomObject]@{
                        label = "include"
                        value = $combinedExeFileNames
                    }
                )
            }
        )
    }
}

function Export-JsonAndCompress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $RuleGroupObject,
        [Parameter(Mandatory)] [string]$OutputJsonPath,
        [Parameter(Mandatory)] [string]$ZipFilePath
    )

    try {
        "[$($RuleGroupObject | ConvertTo-Json -Depth 10)]" | Set-Content -Path $OutputJsonPath -Encoding utf8
        Write-LogEntry -Message "Saved to $OutputJsonPath" -Level success

        if (Test-Path $ZipFilePath) { Remove-Item $ZipFilePath -Force }
        Compress-Archive -Path $OutputJsonPath -DestinationPath $ZipFilePath
        Write-LogEntry -Message "Compressed the JSON into $ZipFilePath" -Level success
    }
    catch {
        Write-LogEntry -Message "Failed to create the JSON file or compress it.`nError: $_" -Level error
        throw
    }
}

function Request-IOAUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ZipFilePath
    )

    Write-LogEntry -Message "Checking for PSFalcon module ..." -Level info
    if (-not (Get-Module -ListAvailable -Name PSFalcon)) {
        Write-LogEntry -Message "PSFalcon module is not installed. Skipping upload." -Level warning
        return
    }

    $userChoice = Read-Host "Do you want to upload $ZipFilePath now? (yes/no)"
    if ($userChoice -notmatch '^(y|yes)$') {
        Write-LogEntry -Message "Upload skipped. You can manually upload $ZipFilePath later using 'Import-FalconConfig' from the PSFalcon module." -Level info
        return
    }

    try {
        Request-FalconToken
        Write-LogEntry -Message "Falcon token obtained successfully." -Level success
        Write-LogEntry -Message "Importing Falcon configuration from $ZipFilePath ..." -Level success
        Import-FalconConfig -Path $ZipFilePath
        Write-LogEntry -Message "Falcon configuration import completed." -Level success
        Write-LogEntry -Message "Remember to apply the rule group to applicable prevention policies for it to take effect." -Level info
    }
    catch {
        Write-LogEntry -Message "Failed to upload the file to Falcon.`nError: $_" -Level error
    }
    finally {
        Revoke-FalconToken | Out-Null
    }
}

### MAIN

try {
    $rmmToolData = Get-RMMData -Url $RmmToolsUrl
}
catch {
    exit 1
}

$rules = [System.Collections.Generic.List[pscustomobject]]::new()
$ruleIds = [System.Collections.Generic.List[string]]::new()
$ruleCounter = $StartingRuleId
$ruleGroupId = Get-RuleGroupId
$isRuleEnabled = [bool]$EnableRules
$isRuleGroupEnabled = -not $DisableRuleGroup

$responseAction = switch ($ResponseType) {
    'monitor' { 10 }
    'block' { 30 }
    default { 20 } # detect
}

Write-LogEntry -Message "Starting Rule ID: $StartingRuleId" -Level info
Write-LogEntry -Message "Rule Group ID: $ruleGroupId" -Level info
Write-LogEntry -Message "Enable all rules: $isRuleEnabled" -Level info
Write-LogEntry -Message "Enable rule group: $isRuleGroupEnabled" -Level info

foreach ($tool in $rmmToolData) {
    try {
        $exeFileNames = Get-ExeFileNames -Tool $tool
        if ($exeFileNames.Count -ge 1) {
            $ruleId = $ruleCounter.ToString()
            $ruleIds.Add($ruleId)
            $rules.Add((New-RuleObject -Tool $tool -ExeFileNames $exeFileNames -RuleId $ruleId `
                        -RuleGroupId $ruleGroupId -EnableRule $isRuleEnabled -ResponseAction $responseAction `
                        -Severity $Severity))
            $ruleCounter++
        }
    }
    catch {
        Write-LogEntry -Message "Skipping '$($tool.Name)' - failed to build rule.`nError: $_" -Level warning
    }
}

$ruleSetObject = [PSCustomObject]@{
    id          = $ruleGroupId
    enabled     = $isRuleGroupEnabled
    name        = "LOLRMM Tools - Windows"
    description = "Process creation rules for common RMM tools based on lolrmm.io"
    platform    = "windows"
    deleted     = $false
    rules       = $rules
    rule_ids    = $ruleIds
    version     = 1
}

Export-JsonAndCompress -RuleGroupObject $ruleSetObject -OutputJsonPath $OutputJsonPath -ZipFilePath $ZipFile
Request-IOAUpload -ZipFilePath $ZipFile
