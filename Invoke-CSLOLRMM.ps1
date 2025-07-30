param(
    [int]$startingRuleId = 50000,
    [string]$zipFile = "rmm_tools.zip",
    [switch]$enableRules,
    [switch]$disableRuleGroup,
    [ValidateSet("informational", "low", "medium", "high", "critical")]
    [string]$severity = "medium",
    [ValidateSet("monitor", "detect", "block")]
    [string]$responseType
)

function Write-LogEntry {
    param(
        [string]$message,
        [ValidateSet("warning", "error", "success", "info")]
        [string]$level = "info"
    )

    $colorMap = @{
        info    = 'Cyan'
        success = 'Green'
        warning = 'Yellow'
        error   = 'Red'
    }

    $symbolMap = @{
        info    = '*'
        success = '+'
        warning = '?'
        error   = '!'
    }

    $currentTime = Get-Date -Format G
    $symbol = $symbolMap[$level]
    $color = $colorMap[$level]
    
    Write-Host "[$symbol] $currentTime - $message" -ForegroundColor $color
}

function Get-RMMData {
    param(
        [string]$url
    )

    try {
        return Invoke-RestMethod -uri $url
    }
    catch {
        Write-LogEntry -msg "Failed to retrieve or parse JSON data from $url.`nError: $_" -level error
        exit
    }
}

function Get-ExeFileNames {
    param($tool)
    $exeFileNames = New-Object System.Collections.Generic.HashSet[System.String]([System.StringComparer]::OrdinalIgnoreCase)

    if ($tool.Details.InstallationPaths -is [array]) {
        foreach ($path in $tool.Details.InstallationPaths) {
            if ($path -match "\.exe$") {
                $filename = $path -replace '^.*\\', ''
                $filename = $filename -replace '\.exe$', ''
                $filename = $filename -replace '\.', '\.'
                $filename = $filename -replace '\*', '.*'
                $filename = $filename -replace ' ', '\s+'
                $exeFileNames.Add($filename) | Out-Null
            }
        }
    }

    if ($tool.Details.PEMetaData -is [array]) {
        $peFileNames = $tool.Details.PEMetaData | 
        Where-Object { $_.Filename -match '\.exe$' } | 
        ForEach-Object { $_.Filename -replace '\.exe$', '' -replace '\*', ',*' -replace '\.', '\.' }

        $combinedPEFileNames = $peFileNames -join '|'
        $exeFileNames.Add($combinedPEFileNames) | Out-Null
    }

    if ($tool.Artifacts.Disk.File -is [array]) {
        foreach ($file in $tool.Artifacts.Disk.File) {
            if ($file -match '\.exe$') {
                $filename = $file -replace '^.*\\', ''
                $filename = $filename -replace '\.exe$', ''
                $filename = $filename -replace '\.', '\.'
                $filename = $filename -replace '\*', '.*'
                $filename = $filename -replace ' ', '\s+'
                $exeFileNames.Add($filename) | Out-Null
            }
        }
    }

    return $exeFileNames
}

function Get-RuleGroupId {
    $md5Provider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $hashBytes = $md5Provider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-Date).ToString()))
    return -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
}

function New-RuleObject {
    param(
        $tool,
        $exeFileNames,
        $ruleId,
        $ruleGroupId,
        $enableRule,
        $responseAction
    )

    $description = ($tool.Description -replace '\\n', '' -replace ' More information will be added as it becomes available.', '').Trim()
    $combinedExeFileNames = "(?i).*\\(" + ($exeFileNames -join '|') + ")\.exe"

    return [PSCustomObject]@{
        instance_id      = $ruleId
        ruletype_id      = "1" # Windows Process
        comment          = ""
        enabled          = $enableRule
        deleted          = $false
        rulegroup_id     = $ruleGroupId
        instance_version = 1
        name             = $tool.Name
        description      = $description
        pattern_severity = $Severity
        disposition_id   = $responseAction # 10 - Monitor, 20 - Detect, 30 - Block Execution
        field_values     = @(
            [PSCustomObject]@{
                name   = "ImageFilename"
                value  = $joinedExeFileNames
                label  = "Image Filename"
                type   = "excludable"
                values = @(
                    @{
                        label = "include"
                        value = $combinedExeFileNames
                    }
                )
            }
        )
    }
}

function Export-JsonAndCompress {
    param(
        $IOAGroupObject,
        [string]$outputJSON,
        [string]$zipfile
    )

    try {
        '[' + ($IOAGroupObject | ConvertTo-Json -Depth 10) + ']' | Set-Content -Path $outputJSON
        Write-LogEntry -msg "Saved to $outputJSON" -level success

        if (Test-Path $zipfile) { Remove-Item $zipfile -Force }
        Compress-Archive -Path $outputJSON -DestinationPath $zipfile
        Write-LogEntry -msg "Compressed the json, created $zipfile" -level success
    }
    catch {
        Write-LogEntry -msg "Failed to creat the json or compress the file.`nError: $_" -level error
        exit
    }
}

function Request-IOAUpload {
    param(
        [string]$zipfile
    )

    Write-LogEntry -msg "Checking for PSFalcon module ..." -level info
    if (-not (Get-Module -ListAvailable -Name PSFalcon)) {
        Write-LogEntry -msg "PSFalcon module is not installed. Skipping upload." -level warning
        return
    }

    $userChoice = Read-Host "Do you want to upload $zipfile now? (yes/no)"
    if ($userChoice -match "^(y|yes)$") {
        try {
            Request-FalconToken
            Write-LogEntry -msg "Falcon token obtained successfully." -level success
            Write-LogEntry -msg "Importing Falcon configuration from $zipfile ..." -level success
            Import-FalconConfig -Path $zipfile
            Write-LogEntry -msg "Falcon configuration import completed." -level success
            Write-LogEntry -msg "Remember to apply the rule group to applicable prevention policies to take effect." -level info
        }
        catch {
            Write-LogEntry -msg "Failed to upload the file to Falcon.`nError: $_" -level error
        }
    }
    else {
        Write-LogEntry -msg "Upload skipped. You can manually upload $zipfile later using 'Import-FalconConfig' from PSFaclon module" -level info
    }
}

### Main
$rmmToolData = Get-RMMData -url "https://lolrmm.io/api/rmm_tools.json"
$rules = New-Object System.Collections.Generic.List[pscustomobject]
$ruleIds = New-Object System.Collections.Generic.List[String]
$ruleCounter = $StartingRuleId
$ruleGroupId = Get-RuleGroupId
$isRuleEnabled = if ($enableRules) { $true } else { $false }
$isRuleGroupEnabled = if ($disableRuleGroup) { $false } else { $true }

switch ($ResponseType) {
    "Monitor" { $responseAction = 10 }
    "Detect" { $responseAction = 20 }
    "Block" { $responseAction = 30 }
    default { $responseAction = 20 }
}

Write-LogEntry -msg "Starting Rule ID: $startingRuleId" -level info
Write-LogEntry -msg "Rule Group ID: $ruleGroupId" -level info
Write-LogEntry -msg "Enable all rules: $isRuleEnabled" -level info
Write-LogEntry -msg "Enable rule group: $isRuleGroupEnabled" -level info

foreach ($tool in $rmmToolData) {
    $exeFileNames = Get-ExeFileNames -tool $tool
    if ($exeFileNames.Count -ge 1) {
        $ruleId = $ruleCounter.ToString()
        $ruleIds += $ruleId
        $rules += New-RuleObject -tool $tool -exeFileNames $exeFileNames -ruleId $ruleId -ruleGroupId $ruleGroupId -enableRule $isRuleEnabled -ResponseAction $responseAction
        $ruleCounter++
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

Export-JsonAndCompress -jsonObject $ruleSetObject -OutputJSON "IOAGroup.json" -zipFile $ZipFile
Request-IOAUpload -Zipfile $ZipFile

Write-LogEntry -msg "Clearing Falcon token" -level success
Revoke-FalconToken | Out-Null