param(
    [int]$StartingRuleId = 50000,
    [string]$ZipFile = "rmm_tools.zip",
    [switch]$EnableRules,
    [switch]$DisableRuleGroup,
    [ValidateSet("informational", "low", "medium", "high", "critical")]
    [string]$Severity = "medium",
    [ValidateSet("monitor", "detect", "block")]
    [string]$ResponseType = "detect"
)

function Write-LogEntry {
    param(
        [string]$msg,
        [ValidateSet("warning", "error", "success", "info")]
        [string]$level
    )

    $currentTime = Get-Date -Format G

    switch ($level) {
        "warning" { 
            write-host -ForegroundColor Yellow "[WARN] $($currentTime) - $($msg)"
            break
        }
        "error" { 
            write-host -ForegroundColor Red "[ERROR] $($currentTime) - $($msg)"
            break
        }
        "success" { 
            write-host -ForegroundColor Green "[OK] $($currentTime) - $($msg)"
            break
        }
        "info" { 
            write-host -ForegroundColor Cyan "[INFO] $($currentTime) - $($msg)"
            break
        }
        Default { 
            write-host "[INFO] $($currentTime) - $($msg)"
            break
        }
    }
}

function Get-RMMData {
    param(
        [string]$url
    )

    try {
        return Invoke-RestMethod -Uri $url
    }
    catch {
        Write-LogEntry -msg "Failed to retrieve or parse JSON data from $url. Error: $_" -level error
        exit 1
    }
}

function ConvertTo-ExeNameRegex {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if ([string]::IsNullOrWhiteSpace($name)) {
        return $null
    }

    $name = [regex]::Escape($name)
    $name = $name -replace '\\\*', '.*'
    $name = $name -replace '\\ ', '\s+'

    return $name
}

function ConvertTo-IoaFileNamePattern {
    param(
        [AllowNull()]
        [string]$FileName
    )

    if ([string]::IsNullOrWhiteSpace($FileName)) {
        return $null
    }

    $pattern = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    if ([string]::IsNullOrWhiteSpace($pattern)) {
        return $null
    }

    $pattern = [regex]::Escape($pattern)
    $pattern = $pattern -replace '\\\*', '.*'
    $pattern = $pattern -replace '\\ ', '\s+'

    return $pattern
}

function Get-ExeFileNames {
    param($tool)
    $exeFileNames = New-Object System.Collections.Generic.HashSet[System.String]([System.StringComparer]::OrdinalIgnoreCase)

    if ($tool.Details.InstallationPaths -is [array]) {
        foreach ($path in $tool.Details.InstallationPaths) {
            if ($path -match "\.exe$") {
                $fileName = ConvertTo-IoaFileNamePattern -FileName $path
                if ($fileName) {
                    $exeFileNames.Add($fileName) | Out-Null
                }
            }
        }
    }

    if ($tool.Details.PEMetaData) {
        foreach ($item in @($tool.Details.PEMetaData)) {
            if ($item.Filename -match '\.exe$') {
                $fileName = ConvertTo-IoaFileNamePattern -FileName $item.Filename
                if ($fileName) {
                    $exeFileNames.Add($fileName)
                }
            }
        }
    }

    if ($tool.Artifacts.Disk.File) {
        foreach ($file in $tool.Artifacts.Disk.File) {
            if ($file -match '\.exe$') {
                $fileName = ConvertTo-IoaFileNamePattern -FileName $file
                if ($fileName) {
                    $exeFileNames.Add($fileName)
                }
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

function Format-IoaDescription {
    param(
        [AllowNull()]
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Description)) {
        return ''
    }

    $safeDescription = $Description -replace '\\n|[\r\n\t]+', ' ' -replace ' More information will be added as it becomes available\.', ''
    @{
        [char]0x00A0 = ' '
        [char]0x00A9 = '(c)'
        [char]0x0130 = 'I'
        [char]0x015E = 'S'
        [char]0x015F = 's'
        [char]0x2013 = '-'
        [char]0x2014 = '-'
        [char]0x2018 = "'"
        [char]0x2019 = "'"
        [char]0x201C = '"'
        [char]0x201D = '"'
        [char]0x2026 = '...'
        [char]0x2192 = '->'
    }.GetEnumerator() | ForEach-Object {
        $safeDescription = $safeDescription.Replace([string]$_.Key, $_.Value)
    }

    return ($safeDescription -replace '[^\x20-\x7E]', '' -replace '\s+', ' ').Trim()
}

function Create-RuleObject {
    param(
        $tool,
        $exeFileNames,
        $ruleId,
        $ruleGroupId,
        $enableRule,
        $responseAction
    )

    $description = Format-IoaDescription -Description $tool.Description
    $joinedExeFileNames = "(?i).*\\(" + ($exeFileNames -join '|') + ")\.exe"

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
                        value = $joinedExeFileNames
                    }
                )
            }
        )
    }
}

function Export-JsonAndCompress {
    param(
        $jsonObject,
        [string]$outputJson,
        [string]$zipFile
    )

    try {
        @($jsonObject) |
        ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $outputJson -Encoding utf8
        Write-LogEntry -msg "Saved to $outputJson" -level success

        if (Test-Path $zipFile) { 
            Remove-Item -LiteralPath $zipFile -Force 
        }
        Compress-Archive -LiteralPath $outputJson -DestinationPath $zipFile -Force
        Write-LogEntry -msg "Compressed the json, created $zipFile" -level success
    }
    catch {
        Write-LogEntry -msg "Failed to create the json or compress the file. Error: $_" -level error
        exit 1
    }
}

function Write-PreviewSummary {
    param(
        [int]$TotalToolsFetched,
        [int]$RulesGenerated,
        [string[]]$SkippedTools,
        [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]$ExecutableToolMap
    )

    $duplicateExecutableNames = @(
        foreach ($entry in $ExecutableToolMap.GetEnumerator()) {
            if ($entry.Value.Count -gt 1) {
                [PSCustomObject]@{
                    Name  = $entry.Key
                    Tools = @($entry.Value)
                }
            }
        }
    )

    Write-LogEntry -msg "Preview summary before export:" -level info
    Write-LogEntry -msg "Total tools fetched: $TotalToolsFetched" -level info
    Write-LogEntry -msg "Rules generated: $RulesGenerated" -level info
    Write-LogEntry -msg "Skipped tools: $($SkippedTools.Count)" -level info
    Write-LogEntry -msg "Duplicate executable names: $($duplicateExecutableNames.Count)" -level info

    if ($SkippedTools.Count -gt 0) {
        Write-LogEntry -msg "Skipped tool names: $($SkippedTools -join ', ')" -level info
    }

    foreach ($duplicate in $duplicateExecutableNames | Sort-Object -Property Name) {
        Write-LogEntry -msg "Duplicate executable '$($duplicate.Name)' found in tools: $($duplicate.Tools -join ',')" -level warning
    }
}

function Prompt-IOAUpload {
    param(
        [string]$zipFile
    )

    Write-LogEntry -msg "Checking for PSFalcon module ..." -level info

    if (-not (Get-Module -ListAvailable -Name PSFalcon)) {
        Write-LogEntry -msg "PSFalcon module is not installed. Skipping upload." -level warning
        return
    }

    $choice = Read-Host "Do you want to upload $zipFile now? (yes/no)"
    if ($choice -match "^(y|yes)$") {
        try {
            Request-FalconToken
            Write-LogEntry -msg "Falcon token obtained successfully." -level success
            Write-LogEntry -msg "Importing Falcon configuraiton from $zipFile ..." -level success
            Import-FalconConfig -Path $zipFile
            Write-LogEntry -msg "Falcon configuration import completed." -level success
            Write-LogEntry -msg "Remember to apply the rule group to applicable prevention policies to take effect." -level info
        }
        catch {
            Write-LogEntry -msg "Failed to upload the file to Falcon. Error: $_" -level error
        }
    }
    else {
        Write-LogEntry -msg "Upload skipped. You can manually upload $zipFile later using 'Import-FalconConfig' from PSFalcon module" -level info
    }
}

### MAIN ####
try {
    $jsonData = Get-RMMData -url "https://lolrmm.io/api/rmm_tools.json"
    $rules = New-Object System.Collections.Generic.List[PSCustomObject]
    $ruleIds = New-Object System.Collections.Generic.List[String]
    $skippedTools = New-Object System.Collections.Generic.List[String]
    $executableToolMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]'([System.StringComparer]::OrdinalIgnoreCase)
    $ruleCounter = $StartingRuleId
    $ruleGroupId = Get-RuleGroupId
    $rulesEnabled = if ($EnableRules) { $true } else { $false }
    $groupDisabled = if ($DisableRuleGroup) { $false } else { $true }

    switch ($ResponseType) {
        "Monitor" { $responseAction = 10 }
        "Detect" { $responseAction = 20 }
        "Block" { $responseAction = 30 }
        default { $responseAction = 20 }
    }

    Write-LogEntry -msg "LOLRMM Falon IOA Rule Generator" -level info
    Write-LogEntry -msg "Source: https://lolrmm.io/api/rmm_tools.json" -level info
    Write-LogEntry -msg "Mode: $ResponseType | Severity: $Severity | Rules enabled: $enableRules | Rule Group ID: $ruleGroupId" -level info

    foreach ($tool in $jsonData) {
        $exeFileNames = Get-ExeFileNames -tool $tool
        if ($exeFileNames.Count -ge 1) {
            foreach ($exeFileName in $exeFileNames) {
                if ([string]::IsNullOrWhiteSpace($exeFileName)) {
                    continue
                }

                if (-not $executableToolMap.ContainsKey($exeFileName)) {
                    $executableToolMap[$exeFileName] = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                }

                $executableTOolMap[$exeFileName].Add($tool.Name) | Out-Null
            }

            $ruleId = $ruleCounter.ToString()
            $ruleIds += $ruleId
            $rules += Create-RuleObject -tool $tool -exeFileNames $exeFileNames -ruleId $ruleId -ruleGroupId $ruleGroupId -enableRule $rulesEnabled -ResponseAction $responseAction
            $ruleCounter++
        }
        else {
            $skippedTools.Add($tool.Name) | Out-Null
        }
    }

    $ruleSetObject = [PSCustomObject]@{
        id          = $ruleGroupId
        enabled     = $groupDisabled
        name        = "LOLRMM Tools - Windows"
        description = "Process creation rules for common RMM tools based on lolrmm.io"
        platform    = "windows"
        deleted     = $false
        rules       = $rules
        rule_ids    = $ruleIds
        version     = 1
    }

    Write-PreviewSummary -TotalToolsFetched @($jsonData).Count -RulesGenerated $rules.Count -SkippedTools $skippedTools -ExecutableToolMap $executableToolMap

    Export-JsonAndCompress -jsonObject $ruleSetObject -outputJson "IoaGroup.json" -zipFile $ZipFile
    Prompt-IOAUpload -zipFile $ZipFile

    Write-LogEntry -msg "Clearing Falcon Token" -level success
    Revoke-FalconToken | Out-Null
}
catch {
    Write-LogEntry -msg $_.Exception.Message -level error
}
