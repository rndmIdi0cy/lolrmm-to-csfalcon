# LOLRMM to CrowdStrike Falcon Custom IOA

Download the [LOLRMM JSON feed](https://lolrmm.io/api/rmm_tools.json), extract Windows executable names, and generate a CrowdStrike Falcon custom Indicators of Attack (IOA) rule group. The script exports JSON and a ZIP archive, then optionally imports the configuration through [PSFalcon](https://github.com/CrowdStrike/psfalcon).

Use it to build filename-based monitoring, detection, or execution-blocking rules for remote monitoring and management (RMM) tools.

> **Defaults:** Detect action, Medium severity, individual rules disabled, and rule group enabled. Use `-ResponseType monitor` to select Monitor explicitly. Review the implementation notes below before importing generated rules.

## Installation / Setup

For Falcon import, install and load PSFalcon:

   ```powershell
   Install-Module -Name PSFalcon -Scope CurrentUser
   Import-Module PSFalcon
   ```
## Usage / Examples

### Basic execution

```powershell
./Invoke-CSLOLRMM.ps1
```

Downloads the feed and generates a configuration using Detect, Medium severity, disabled rules, and an enabled group. It then offers an upload prompt if PSFalcon is installed.

### Generate a Monitor configuration for review

```powershell
./Invoke-CSLOLRMM.ps1 -ResponseType monitor -DisableRuleGroup
```

Individual rules remain disabled, and the group is also disabled. Answer `no` at the upload prompt to keep the files for review.

### Generate enabled Monitor rules

```powershell
./Invoke-CSLOLRMM.ps1 -ResponseType monitor -EnableRules
```

Sets generated rules and the group to enabled. Policy assignment in Falcon is still required.

### Generate enabled Detect rules

```powershell
./Invoke-CSLOLRMM.ps1 -ResponseType detect -EnableRules -Severity medium
```

### Generate enabled Block rules with a custom archive

```powershell
$settings = @{
    StartingRuleId = 60000
    ZipFile        = './lolrmm-block.zip'
    ResponseType   = 'block'
    Severity       = 'high'
    EnableRules    = $true
}
./Invoke-CSLOLRMM.ps1 @settings
```

Use Block only after reviewing matches, business dependencies, and documented exclusions in a pilot population. Changing the starting ID does not provide synchronization with existing Falcon rules.

### Import later

After authenticating with PSFalcon for your tenant and cloud:

```powershell
Import-FalconConfig -Path ./rmm_tools.zip
```

During script execution, answering `yes` or `y` to the upload prompt invokes `Request-FalconToken` and then `Import-FalconConfig`. Other responses skip import. The script does **not** assign the group to prevention policies; complete that step in Falcon and verify endpoint policy assignment.

## Parameters Reference

All script parameters are optional.

| Parameter | Default | Description |
| --- | --- | --- |
| `StartingRuleId` | `50000` | First generated rule instance ID. Increments for each rule; assignments depend on feed order. |
| `ZipFile` | `rmm_tools.zip` | Output ZIP path. An existing file at this path is deleted before compression. Ensure its parent directory exists. |
| `EnableRules` | `$false` | Enables all generated rules. Without this switch, individual rules are disabled. |
| `DisableRuleGroup` | `$false` | Disables the generated group. Without this switch, the group is enabled. |
| `Severity` | `medium` | Severity for all rules: `informational`, `low`, `medium`, `high`, or `critical`. |
| `ResponseType` | `detect` | Action for all rules: `monitor` (disposition `10`), `detect` (`20`), or `block` (`30`, block execution). |

Action selection does not enable rules, enable a disabled group, or assign a prevention policy. There are no upload, exclusion, scheduling, source-URL, or JSON-output-path parameters.

### RMM approvals and coverage

LOLRMM lists tools that can have legitimate business uses. Inventory your tools, identify those with a business need, and create formal, documented exclusions with an owner, justification, scope, approval, and review date. Manage those exclusions through your supported Falcon workflow; the script does not implement them.

The generated rules match Windows executable image filenames. They do not create hash, signer, domain, IP, or command-line rules, and a match alone does not establish malicious activity. Pilot in Monitor, validate outcomes, and then choose Detect or Block according to your organization's requirements.
