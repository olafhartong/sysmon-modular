#Requires -Version 5.1
<#
.SYNOPSIS
    SysmonConfigManager - Intelligent Sysmon XML Configuration Manager

.DESCRIPTION
    A PowerShell tool for security professionals to manage Microsoft Sysmon XML
    configuration files. Paste real Sysmon log events, analyze whether they'd be
    captured or filtered, and generate precise include/exclude rules to maintain
    an optimal signal-to-noise ratio.

    Workflow:
      1. Load your sysmon XML config
      2. Import a sample sysmon event (paste XML, read from Event Log, or file)
      3. See exactly which rules match and whether it's included or excluded
      4. Generate an exclude rule to silence noise, or an include rule to capture it
      5. Apply the rule to your config and export

.EXAMPLE
    # Interactive mode - menu-driven workflow
    .\SysmonConfigManager.ps1

.EXAMPLE
    # Scripted: load config, import event, add exclusion, export
    . .\SysmonConfigManager.ps1
    $cfg = Import-SysmonConfig -Path .\sysmonconfig.xml
    $evt = Import-SysmonEvent -XmlString '<Event>...</Event>'
    $rule = New-SysmonExcludeRule -Event $evt -Fields Image,CommandLine
    Add-SysmonRule -Config $cfg -Rule $rule
    Export-SysmonConfig -Config $cfg -Path .\sysmonconfig-tuned.xml

.NOTES
    Version: 1.0.0
    Requires: PowerShell 5.1+ or PowerShell 7+
#>

# ============================================================================
# GLOBAL MAPPINGS
# ============================================================================

$Script:EventIdToType = @{
    1  = 'ProcessCreate'
    2  = 'FileCreateTime'
    3  = 'NetworkConnect'
    5  = 'ProcessTerminate'
    6  = 'DriverLoad'
    7  = 'ImageLoad'
    8  = 'CreateRemoteThread'
    9  = 'RawAccessRead'
    10 = 'ProcessAccess'
    11 = 'FileCreate'
    12 = 'RegistryEvent'
    13 = 'RegistryEvent'
    14 = 'RegistryEvent'
    15 = 'FileCreateStreamHash'
    17 = 'PipeEvent'
    18 = 'PipeEvent'
    19 = 'WmiEvent'
    20 = 'WmiEvent'
    21 = 'WmiEvent'
    22 = 'DnsQuery'
    23 = 'FileDelete'
    24 = 'ClipboardChange'
    25 = 'ProcessTampering'
    26 = 'FileDeleteDetected'
}

$Script:TypeToEventId = @{
    'ProcessCreate'        = 1
    'FileCreateTime'       = 2
    'NetworkConnect'       = 3
    'ProcessTerminate'     = 5
    'DriverLoad'           = 6
    'ImageLoad'            = 7
    'CreateRemoteThread'   = 8
    'RawAccessRead'        = 9
    'ProcessAccess'        = 10
    'FileCreate'           = 11
    'RegistryEvent'        = 12
    'FileCreateStreamHash' = 15
    'PipeEvent'            = 17
    'WmiEvent'             = 19
    'DnsQuery'             = 22
    'FileDelete'           = 23
    'ClipboardChange'      = 24
    'ProcessTampering'     = 25
    'FileDeleteDetected'   = 26
}

# Fields useful for building filter rules (excludes transient GUIDs, timestamps, PIDs)
$Script:FilterableFields = @{
    'ProcessCreate'        = @('Image','OriginalFileName','CommandLine','ParentImage','ParentCommandLine','User','IntegrityLevel','CurrentDirectory','Company','Product','Description')
    'FileCreateTime'       = @('Image','TargetFilename','User')
    'NetworkConnect'       = @('Image','DestinationIp','DestinationPort','DestinationHostname','SourcePort','Protocol','Initiated','User')
    'ProcessTerminate'     = @('Image','User')
    'DriverLoad'           = @('ImageLoaded','Signature','Signed','SignatureStatus')
    'ImageLoad'            = @('Image','ImageLoaded','Signature','Signed','OriginalFileName','SignatureStatus','Company','Product','Description')
    'CreateRemoteThread'   = @('SourceImage','TargetImage','StartModule','StartFunction')
    'RawAccessRead'        = @('Image','Device','User')
    'ProcessAccess'        = @('SourceImage','TargetImage','GrantedAccess','CallTrace')
    'FileCreate'           = @('Image','TargetFilename','User')
    'RegistryEvent'        = @('Image','TargetObject','Details','EventType','User')
    'FileCreateStreamHash' = @('Image','TargetFilename','Contents','User')
    'PipeEvent'            = @('Image','PipeName','EventType','User')
    'WmiEvent'             = @('Operation','EventNamespace','Name','Query','Type','Destination','Consumer','Filter')
    'DnsQuery'             = @('Image','QueryName','QueryStatus','User')
    'FileDelete'           = @('Image','TargetFilename','IsExecutable','User')
    'ClipboardChange'      = @('Image','Session','User')
    'ProcessTampering'     = @('Image','Type','User')
    'FileDeleteDetected'   = @('Image','TargetFilename','IsExecutable','User')
}

# Sysmon condition operators
$Script:ValidConditions = @(
    'is', 'is not', 'contains', 'contains any', 'contains all',
    'excludes', 'excludes any', 'excludes all',
    'begin with', 'end with', 'not begin with', 'not end with',
    'less than', 'more than', 'image'
)

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

function Import-SysmonConfig {
    <#
    .SYNOPSIS
        Loads a Sysmon XML configuration file into a manageable object.
    .PARAMETER Path
        Path to the sysmonconfig.xml file.
    .OUTPUTS
        PSCustomObject with .Xml (the XmlDocument) and .Path properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }

    $resolvedPath = (Resolve-Path $Path).ProviderPath
    $doc = [xml]::new()
    $doc.Load($resolvedPath)

    # Validate it looks like a sysmon config
    $root = $doc.DocumentElement
    if ($root.LocalName -ne 'Sysmon') {
        throw "Not a valid Sysmon config - root element is '$($root.LocalName)', expected 'Sysmon'"
    }

    $eventFiltering = $doc.SelectSingleNode('//Sysmon/EventFiltering')
    if (-not $eventFiltering) {
        throw "No EventFiltering element found in config"
    }

    [PSCustomObject]@{
        Xml          = $doc
        Path         = $resolvedPath
        SchemaVersion = $root.GetAttribute('schemaversion')
    }
}

function Import-SysmonEvent {
    <#
    .SYNOPSIS
        Parses a Sysmon event from XML text, file, or the Windows Event Log.
    .DESCRIPTION
        Accepts Sysmon event XML in multiple formats:
        - Raw XML string (from Export or copy-paste)
        - Path to an XML file containing one or more events
        - Directly from the Windows Event Log (requires admin on a Windows box)
    .PARAMETER XmlString
        Raw XML string of a Sysmon event.
    .PARAMETER Path
        Path to an XML file containing Sysmon event(s).
    .PARAMETER FromEventLog
        Pull the most recent N events from the local Sysmon event log.
    .PARAMETER Count
        Number of events to pull from the event log (default 10).
    .PARAMETER EventId
        Filter event log queries to a specific Sysmon Event ID.
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromString')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromString', Position = 0)]
        [string]$XmlString,

        [Parameter(Mandatory, ParameterSetName = 'FromFile')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'FromEventLog')]
        [switch]$FromEventLog,

        [Parameter(ParameterSetName = 'FromEventLog')]
        [int]$Count = 10,

        [Parameter(ParameterSetName = 'FromEventLog')]
        [int]$EventId
    )

    $events = @()

    switch ($PSCmdlet.ParameterSetName) {
        'FromString' {
            $events += ConvertFrom-SysmonEventXml -XmlString $XmlString.Trim()
        }
        'FromFile' {
            if (-not (Test-Path $Path)) {
                throw "Event file not found: $Path"
            }
            $content = Get-Content -Path $Path -Raw
            # Handle files with multiple <Event> elements
            if ($content -match '<Events>') {
                $doc = [xml]$content
                foreach ($eventNode in $doc.Events.Event) {
                    $events += ConvertFrom-SysmonEventXml -XmlString $eventNode.OuterXml
                }
            }
            else {
                # Try as single event or multiple events without wrapper
                $xmlMatches = [regex]::Matches($content, '<Event\b[^>]*>[\s\S]*?</Event>')
                foreach ($m in $xmlMatches) {
                    $events += ConvertFrom-SysmonEventXml -XmlString $m.Value
                }
            }
        }
        'FromEventLog' {
            if ($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows) {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational' }
                if ($EventId) { $filter['Id'] = $EventId }
                try {
                    $logEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction Stop
                    foreach ($le in $logEvents) {
                        $events += ConvertFrom-SysmonEventXml -XmlString $le.ToXml()
                    }
                }
                catch {
                    throw "Failed to read Sysmon event log: $_. Run as Administrator and ensure Sysmon is installed."
                }
            }
            else {
                throw "Event Log reading is only supported on Windows."
            }
        }
    }

    if ($events.Count -eq 0) {
        throw "No valid Sysmon events could be parsed from the input."
    }

    return $events
}

function ConvertFrom-SysmonEventXml {
    <#
    .SYNOPSIS
        Internal: parses a single Sysmon event XML string into a structured object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$XmlString
    )

    try {
        # Strip namespace to simplify XPath
        $cleaned = $XmlString -replace 'xmlns="[^"]*"', ''
        $doc = [xml]$cleaned
    }
    catch {
        throw "Failed to parse event XML: $_"
    }

    $eventIdNode = $doc.SelectSingleNode('//EventID')
    if (-not $eventIdNode) {
        throw "No EventID found in event XML. Ensure this is a valid Sysmon event."
    }

    $eventId = [int]$eventIdNode.InnerText
    $eventType = $Script:EventIdToType[$eventId]
    if (-not $eventType) {
        throw "Unsupported Sysmon Event ID: $eventId"
    }

    # Extract all EventData fields
    $fields = [ordered]@{}
    $dataNodes = $doc.SelectNodes('//EventData/Data')
    foreach ($node in $dataNodes) {
        $name = $node.GetAttribute('Name')
        if ($name) {
            $fields[$name] = $node.InnerText
        }
    }

    # Extract system metadata
    $computer = $doc.SelectSingleNode('//Computer')
    $timeCreated = $doc.SelectSingleNode('//TimeCreated')

    [PSCustomObject]@{
        EventId   = $eventId
        EventType = $eventType
        Fields    = $fields
        Computer  = if ($computer) { $computer.InnerText } else { '' }
        TimeStamp = if ($timeCreated) { $timeCreated.GetAttribute('SystemTime') } else { '' }
        RawXml    = $XmlString
    }
}

function Test-SysmonEvent {
    <#
    .SYNOPSIS
        Tests whether a Sysmon event would be logged or filtered by the current config.
    .DESCRIPTION
        Evaluates the event against all include and exclude rules for its event type
        and reports which rules match, whether it would be logged, and why.
    .PARAMETER Config
        The config object from Import-SysmonConfig.
    .PARAMETER Event
        One or more event objects from Import-SysmonEvent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory, ValueFromPipeline)]
        $Event
    )

    process {
        foreach ($evt in @($Event)) {
            $eventType = $evt.EventType
            $fields = $evt.Fields

            # Find all RuleGroups for this event type
            $includeNodes = $Config.Xml.SelectNodes("//RuleGroup/$eventType[@onmatch='include']")
            $excludeNodes = $Config.Xml.SelectNodes("//RuleGroup/$eventType[@onmatch='exclude']")

            $includeMatches = @()
            $excludeMatches = @()

            # Test include rules
            foreach ($node in $includeNodes) {
                $matches = Test-RuleNode -RuleNode $node -Fields $fields
                $includeMatches += $matches
            }

            # Test exclude rules
            foreach ($node in $excludeNodes) {
                $matches = Test-RuleNode -RuleNode $node -Fields $fields
                $excludeMatches += $matches
            }

            $hasIncludeRules = ($includeNodes.Count -gt 0)
            $hasExcludeRules = ($excludeNodes.Count -gt 0)
            $matchedInclude = ($includeMatches.Count -gt 0)
            $matchedExclude = ($excludeMatches.Count -gt 0)

            # Determine final verdict:
            # - If include rules exist and event matches include -> logged (unless also excluded)
            # - If exclude rules exist and event matches exclude -> filtered out
            # - If only include rules exist and no match -> filtered out
            # - If only exclude rules exist and no match -> logged
            # - Sysmon evaluates include first, then exclude can override
            if ($matchedExclude) {
                $verdict = 'EXCLUDED'
                $reason = "Matched $($excludeMatches.Count) exclude rule(s)"
            }
            elseif ($matchedInclude) {
                $verdict = 'INCLUDED'
                $reason = "Matched $($includeMatches.Count) include rule(s)"
            }
            elseif ($hasIncludeRules -and -not $hasExcludeRules) {
                $verdict = 'NOT LOGGED'
                $reason = "Include rules exist but none matched"
            }
            elseif ($hasExcludeRules -and -not $hasIncludeRules) {
                $verdict = 'LOGGED'
                $reason = "Exclude rules exist but none matched (event passes through)"
            }
            else {
                $verdict = 'NOT LOGGED'
                $reason = "Include rules exist but none matched"
            }

            [PSCustomObject]@{
                EventId        = $evt.EventId
                EventType      = $eventType
                Verdict        = $verdict
                Reason         = $reason
                IncludeMatches = $includeMatches
                ExcludeMatches = $excludeMatches
                Event          = $evt
            }
        }
    }
}

function Test-RuleNode {
    <#
    .SYNOPSIS
        Internal: tests a single rule node (include or exclude block) against event fields.
        Returns an array of matching rule descriptions.
    #>
    [CmdletBinding()]
    param(
        [System.Xml.XmlElement]$RuleNode,
        [System.Collections.Specialized.OrderedDictionary]$Fields
    )

    $matches = @()

    foreach ($child in $RuleNode.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }

        if ($child.LocalName -eq 'Rule') {
            # Compound rule with groupRelation
            $groupRelation = $child.GetAttribute('groupRelation')
            $ruleName = $child.GetAttribute('name')
            $subResults = @()

            foreach ($subChild in $child.ChildNodes) {
                if ($subChild.NodeType -ne 'Element') { continue }
                $subResults += Test-SingleCondition -ConditionNode $subChild -Fields $Fields
            }

            if ($groupRelation -eq 'and') {
                if ($subResults.Count -gt 0 -and ($subResults | Where-Object { $_ -eq $true }).Count -eq $subResults.Count) {
                    $matches += "Rule '$ruleName' (AND group - all conditions matched)"
                }
            }
            else {
                if ($subResults -contains $true) {
                    $matches += "Rule '$ruleName' (OR group - at least one condition matched)"
                }
            }
        }
        else {
            # Direct filter condition
            if (Test-SingleCondition -ConditionNode $child -Fields $Fields) {
                $fieldName = $child.LocalName
                $condition = $child.GetAttribute('condition')
                $value = $child.InnerText
                $ruleName = $child.GetAttribute('name')
                $desc = "$fieldName $condition '$value'"
                if ($ruleName) { $desc += " [$ruleName]" }
                $matches += $desc
            }
        }
    }

    return $matches
}

function Test-SingleCondition {
    <#
    .SYNOPSIS
        Internal: evaluates a single filter condition against event field values.
    #>
    [CmdletBinding()]
    param(
        [System.Xml.XmlElement]$ConditionNode,
        [System.Collections.Specialized.OrderedDictionary]$Fields
    )

    $fieldName = $ConditionNode.LocalName
    $condition = $ConditionNode.GetAttribute('condition')
    $filterValue = $ConditionNode.InnerText
    $eventValue = $Fields[$fieldName]

    if (-not $condition) { $condition = 'is' }
    if ($null -eq $eventValue) { $eventValue = '' }

    switch ($condition.ToLower()) {
        'is'             { return $eventValue -ieq $filterValue }
        'is not'         { return $eventValue -ine $filterValue }
        'contains'       { return $eventValue -ilike "*$filterValue*" }
        'contains any'   {
            foreach ($part in ($filterValue -split ';')) {
                if ($eventValue -ilike "*$($part.Trim())*") { return $true }
            }
            return $false
        }
        'contains all'   {
            foreach ($part in ($filterValue -split ';')) {
                if ($eventValue -inotlike "*$($part.Trim())*") { return $false }
            }
            return $true
        }
        'excludes'       { return $eventValue -inotlike "*$filterValue*" }
        'excludes any'   {
            foreach ($part in ($filterValue -split ';')) {
                if ($eventValue -inotlike "*$($part.Trim())*") { return $true }
            }
            return $false
        }
        'excludes all'   {
            foreach ($part in ($filterValue -split ';')) {
                if ($eventValue -ilike "*$($part.Trim())*") { return $false }
            }
            return $true
        }
        'begin with'     { return $eventValue -ilike "$filterValue*" }
        'end with'       { return $eventValue -ilike "*$filterValue" }
        'not begin with' { return $eventValue -inotlike "$filterValue*" }
        'not end with'   { return $eventValue -inotlike "*$filterValue" }
        'less than'      { return [int64]$eventValue -lt [int64]$filterValue }
        'more than'      { return [int64]$eventValue -gt [int64]$filterValue }
        'image'          {
            # 'image' matches just the filename portion (like "cmd.exe")
            $imageName = [System.IO.Path]::GetFileName($eventValue)
            return $imageName -ieq $filterValue
        }
        default          { return $false }
    }
}

function New-SysmonExcludeRule {
    <#
    .SYNOPSIS
        Generates an XML exclude rule from a Sysmon event to filter out noise.
    .DESCRIPTION
        Takes a parsed Sysmon event and the fields you want to match on, then
        builds the XML exclude rule element. Picks the smartest condition type
        automatically (e.g. 'is' for exact paths, 'image' for process names,
        'end with' for file extensions).
    .PARAMETER Event
        A parsed Sysmon event from Import-SysmonEvent.
    .PARAMETER Fields
        Which event fields to build conditions for. If omitted, recommends fields.
    .PARAMETER Condition
        Override the auto-detected condition type for all fields.
    .PARAMETER GroupRelation
        'and' requires all conditions to match; 'or' requires any (default: and).
    .PARAMETER RuleName
        Optional name/label for the rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Event,

        [string[]]$Fields,

        [ValidateSet('is', 'is not', 'contains', 'contains any', 'contains all',
                     'excludes', 'begin with', 'end with', 'image')]
        [string]$Condition,

        [ValidateSet('and', 'or')]
        [string]$GroupRelation = 'and',

        [string]$RuleName
    )

    return New-SysmonRuleInternal -Event $Event -MatchType 'exclude' -Fields $Fields `
        -Condition $Condition -GroupRelation $GroupRelation -RuleName $RuleName
}

function New-SysmonIncludeRule {
    <#
    .SYNOPSIS
        Generates an XML include rule from a Sysmon event to capture specific activity.
    .PARAMETER Event
        A parsed Sysmon event from Import-SysmonEvent.
    .PARAMETER Fields
        Which event fields to build conditions for.
    .PARAMETER Condition
        Override the auto-detected condition type.
    .PARAMETER GroupRelation
        'and' or 'or' (default: and).
    .PARAMETER RuleName
        Optional name/label for the rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Event,

        [string[]]$Fields,

        [ValidateSet('is', 'is not', 'contains', 'contains any', 'contains all',
                     'excludes', 'begin with', 'end with', 'image')]
        [string]$Condition,

        [ValidateSet('and', 'or')]
        [string]$GroupRelation = 'and',

        [string]$RuleName
    )

    return New-SysmonRuleInternal -Event $Event -MatchType 'include' -Fields $Fields `
        -Condition $Condition -GroupRelation $GroupRelation -RuleName $RuleName
}

function New-SysmonRuleInternal {
    <#
    .SYNOPSIS
        Internal: builds a rule object from event data.
    #>
    [CmdletBinding()]
    param(
        $Event,
        [string]$MatchType,
        [string[]]$Fields,
        [string]$Condition,
        [string]$GroupRelation = 'and',
        [string]$RuleName
    )

    $eventType = $Event.EventType

    # If no fields specified, use recommended filterable fields that have values
    if (-not $Fields -or $Fields.Count -eq 0) {
        $available = $Script:FilterableFields[$eventType]
        if (-not $available) {
            throw "Unknown event type: $eventType"
        }
        $Fields = $available | Where-Object { $Event.Fields[$_] }
        if ($Fields.Count -eq 0) {
            throw "No filterable fields with values found in this event."
        }
    }

    # Build conditions
    $conditions = @()
    foreach ($field in $Fields) {
        $value = $Event.Fields[$field]
        if (-not $value) {
            Write-Warning "Field '$field' has no value in this event, skipping."
            continue
        }

        # Auto-detect best condition if not overridden
        $cond = $Condition
        if (-not $cond) {
            $cond = Get-SmartCondition -FieldName $field -Value $value
        }

        $conditions += [PSCustomObject]@{
            Field     = $field
            Condition = $cond
            Value     = $value
        }
    }

    if ($conditions.Count -eq 0) {
        throw "No valid conditions could be built."
    }

    [PSCustomObject]@{
        EventType     = $eventType
        MatchType     = $matchType
        GroupRelation = $GroupRelation
        RuleName      = $RuleName
        Conditions    = $conditions
    }
}

function Get-SmartCondition {
    <#
    .SYNOPSIS
        Internal: picks the best condition operator based on field name and value.
    #>
    [CmdletBinding()]
    param(
        [string]$FieldName,
        [string]$Value
    )

    # Image/process fields: use 'image' condition (matches just filename)
    if ($FieldName -in @('Image', 'ParentImage', 'SourceImage', 'TargetImage') -and
        $Value -match '^[A-Z]:\\') {
        return 'image'
    }

    # Full path fields: use 'is' for exact match
    if ($Value -match '^[A-Z]:\\' -and $FieldName -in @('CommandLine', 'ParentCommandLine')) {
        return 'is'
    }

    # Target filenames/registry: use 'begin with' for path prefix matching
    if ($FieldName -in @('TargetFilename', 'TargetObject') -and $Value -match '^[A-Z]:\\|^HK') {
        return 'begin with'
    }

    # DNS queries: use 'end with' for domain suffix matching
    if ($FieldName -eq 'QueryName' -and $Value -match '\.') {
        # Use the last two parts as a domain suffix
        return 'end with'
    }

    # IP addresses: exact match
    if ($FieldName -match 'Ip$') {
        return 'is'
    }

    # Port numbers: exact match
    if ($FieldName -match 'Port$') {
        return 'is'
    }

    # Boolean fields
    if ($FieldName -in @('Signed', 'Initiated', 'IsExecutable')) {
        return 'is'
    }

    # Default to 'is' for exact match
    return 'is'
}

function Add-SysmonRule {
    <#
    .SYNOPSIS
        Inserts a generated rule into the Sysmon config XML.
    .DESCRIPTION
        Takes a rule object from New-SysmonExcludeRule or New-SysmonIncludeRule and
        inserts it into the appropriate RuleGroup in the config. Creates the RuleGroup
        if it doesn't exist.
    .PARAMETER Config
        The config object from Import-SysmonConfig.
    .PARAMETER Rule
        The rule object from New-SysmonExcludeRule or New-SysmonIncludeRule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        $Rule
    )

    $doc = $Config.Xml
    $eventType = $Rule.EventType
    $matchType = $Rule.MatchType

    # Find existing node for this event type and match type
    $existing = $doc.SelectSingleNode("//RuleGroup/$eventType[@onmatch='$matchType']")

    if (-not $existing) {
        # Create new RuleGroup
        $eventFiltering = $doc.SelectSingleNode('//Sysmon/EventFiltering')
        $ruleGroup = $doc.CreateElement('RuleGroup')
        $ruleGroup.SetAttribute('name', '')
        $ruleGroup.SetAttribute('groupRelation', 'or')

        $eventNode = $doc.CreateElement($eventType)
        $eventNode.SetAttribute('onmatch', $matchType)
        $null = $ruleGroup.AppendChild($eventNode)
        $null = $eventFiltering.AppendChild($ruleGroup)
        $existing = $eventNode
    }

    if ($Rule.Conditions.Count -eq 1) {
        # Single condition: add directly
        $c = $Rule.Conditions[0]
        $elem = $doc.CreateElement($c.Field)
        $elem.SetAttribute('condition', $c.Condition)
        $elem.InnerText = $c.Value
        if ($Rule.RuleName) {
            $elem.SetAttribute('name', $Rule.RuleName)
        }
        $null = $existing.AppendChild($elem)
    }
    else {
        # Multiple conditions: wrap in a <Rule> element
        $ruleElem = $doc.CreateElement('Rule')
        $ruleElem.SetAttribute('groupRelation', $Rule.GroupRelation)
        if ($Rule.RuleName) {
            $ruleElem.SetAttribute('name', $Rule.RuleName)
        }
        foreach ($c in $Rule.Conditions) {
            $elem = $doc.CreateElement($c.Field)
            $elem.SetAttribute('condition', $c.Condition)
            $elem.InnerText = $c.Value
            $null = $ruleElem.AppendChild($elem)
        }
        $null = $existing.AppendChild($ruleElem)
    }

    Write-Host "[+] Added $matchType rule for $eventType" -ForegroundColor Green
    return $Config
}

function Remove-SysmonRule {
    <#
    .SYNOPSIS
        Removes rules matching specific criteria from the config.
    .PARAMETER Config
        The config object from Import-SysmonConfig.
    .PARAMETER EventType
        The Sysmon event type (e.g., ProcessCreate, NetworkConnect).
    .PARAMETER MatchType
        'include' or 'exclude'.
    .PARAMETER FieldName
        Field name to search for in rules.
    .PARAMETER Value
        Value to match (rules containing this value will be removed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [string]$EventType,

        [Parameter(Mandatory)]
        [ValidateSet('include', 'exclude')]
        [string]$MatchType,

        [Parameter(Mandatory)]
        [string]$FieldName,

        [string]$Value
    )

    $doc = $Config.Xml
    $nodes = $doc.SelectNodes("//RuleGroup/$EventType[@onmatch='$MatchType']/$FieldName")
    $removed = 0

    foreach ($node in $nodes) {
        if (-not $Value -or $node.InnerText -ieq $Value) {
            $null = $node.ParentNode.RemoveChild($node)
            $removed++
        }
    }

    # Also check inside <Rule> elements
    $ruleNodes = $doc.SelectNodes("//RuleGroup/$EventType[@onmatch='$MatchType']/Rule/$FieldName")
    foreach ($node in $ruleNodes) {
        if (-not $Value -or $node.InnerText -ieq $Value) {
            $ruleParent = $node.ParentNode  # The <Rule> element
            $null = $ruleParent.ParentNode.RemoveChild($ruleParent)
            $removed++
        }
    }

    if ($removed -gt 0) {
        Write-Host "[+] Removed $removed rule(s) matching $FieldName='$Value' from $EventType $MatchType" -ForegroundColor Yellow
    }
    else {
        Write-Host "[-] No matching rules found." -ForegroundColor Red
    }

    return $Config
}

function Get-SysmonConfigStats {
    <#
    .SYNOPSIS
        Shows statistics about the current Sysmon configuration.
    .DESCRIPTION
        Counts rules per event type, shows include vs exclude balance,
        and highlights event types with no coverage.
    .PARAMETER Config
        The config object from Import-SysmonConfig.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $doc = $Config.Xml
    $stats = @()

    foreach ($eventType in $Script:TypeToEventId.Keys | Sort-Object) {
        $eid = $Script:TypeToEventId[$eventType]
        $includeNodes = $doc.SelectNodes("//RuleGroup/$eventType[@onmatch='include']")
        $excludeNodes = $doc.SelectNodes("//RuleGroup/$eventType[@onmatch='exclude']")

        $includeCount = 0
        $excludeCount = 0

        foreach ($node in $includeNodes) {
            $includeCount += $node.ChildNodes.Count
        }
        foreach ($node in $excludeNodes) {
            $excludeCount += $node.ChildNodes.Count
        }

        $mode = if ($includeCount -gt 0 -and $excludeCount -gt 0) { 'Both' }
                elseif ($includeCount -gt 0) { 'Include-only' }
                elseif ($excludeCount -gt 0) { 'Exclude-only' }
                else { 'NO RULES' }

        $stats += [PSCustomObject]@{
            EventType    = $eventType
            EventId      = $eid
            IncludeRules = $includeCount
            ExcludeRules = $excludeCount
            TotalRules   = $includeCount + $excludeCount
            Mode         = $mode
        }
    }

    return $stats
}

function Find-NoisyEvents {
    <#
    .SYNOPSIS
        Analyzes Sysmon events from the Windows Event Log and identifies noisy sources.
    .DESCRIPTION
        Reads recent Sysmon events, groups them by event type and key fields, and
        reports which processes/paths are generating the most volume. Suggests
        exclusion rules for the top noise generators.
    .PARAMETER Count
        Number of recent events to analyze (default 500).
    .PARAMETER TopN
        How many top noisy sources to report (default 10).
    .PARAMETER EventId
        Optional: focus analysis on a specific Event ID.
    #>
    [CmdletBinding()]
    param(
        [int]$Count = 500,
        [int]$TopN = 10,
        [int]$EventId
    )

    if (-not ($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows)) {
        throw "Event log analysis is only available on Windows."
    }

    Write-Host "`n[*] Reading $Count events from Sysmon event log..." -ForegroundColor Cyan
    $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational' }
    if ($EventId) { $filter['Id'] = $EventId }

    try {
        $logEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction Stop
    }
    catch {
        throw "Failed to read Sysmon event log: $_"
    }

    $parsed = @()
    foreach ($le in $logEvents) {
        try {
            $parsed += Import-SysmonEvent -XmlString $le.ToXml()
        }
        catch {
            # Skip unparseable events
        }
    }

    Write-Host "[*] Parsed $($parsed.Count) events. Analyzing..." -ForegroundColor Cyan

    # Group by event type
    $byType = $parsed | Group-Object -Property EventType | Sort-Object Count -Descending

    Write-Host "`n=== EVENT VOLUME BY TYPE ===" -ForegroundColor White
    foreach ($group in $byType) {
        $pct = [math]::Round(($group.Count / $parsed.Count) * 100, 1)
        $bar = '#' * [math]::Min(50, [math]::Ceiling($pct / 2))
        Write-Host ("  {0,-25} {1,5} ({2,5}%)  {3}" -f $group.Name, $group.Count, $pct, $bar) -ForegroundColor Gray
    }

    # For each event type, find the noisiest Image values
    Write-Host "`n=== TOP NOISY SOURCES ===" -ForegroundColor White
    $suggestions = @()

    foreach ($group in $byType) {
        $events = $group.Group
        $imageGroups = $events | Where-Object { $_.Fields['Image'] } |
            Group-Object { $_.Fields['Image'] } |
            Sort-Object Count -Descending |
            Select-Object -First $TopN

        foreach ($ig in $imageGroups) {
            $pct = [math]::Round(($ig.Count / $events.Count) * 100, 1)
            if ($ig.Count -ge 3) {
                $suggestions += [PSCustomObject]@{
                    EventType = $group.Name
                    Field     = 'Image'
                    Value     = $ig.Name
                    Count     = $ig.Count
                    Percent   = $pct
                }
            }
        }
    }

    $suggestions | Sort-Object Count -Descending | Select-Object -First $TopN |
        Format-Table EventType, Field, Value, Count, @{N='%';E={$_.Percent}} -AutoSize

    return $suggestions
}

function Export-SysmonConfig {
    <#
    .SYNOPSIS
        Exports the modified Sysmon config to a file.
    .DESCRIPTION
        Writes the config XML to disk. Creates a timestamped backup of the
        destination file if it already exists.
    .PARAMETER Config
        The config object from Import-SysmonConfig.
    .PARAMETER Path
        Output file path. Defaults to a '-tuned' suffixed version of the original.
    .PARAMETER NoBackup
        Skip creating a backup of the existing file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [string]$Path,

        [switch]$NoBackup
    )

    if (-not $Path) {
        $dir = [System.IO.Path]::GetDirectoryName($Config.Path)
        $name = [System.IO.Path]::GetFileNameWithoutExtension($Config.Path)
        $Path = Join-Path $dir "$name-tuned.xml"
    }

    # Backup existing file
    if ((Test-Path $Path) -and -not $NoBackup) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = "$Path.backup-$timestamp"
        Copy-Item -Path $Path -Destination $backupPath
        Write-Host "[*] Backed up existing file to: $backupPath" -ForegroundColor Cyan
    }

    # Write with proper formatting
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.IndentChars = '    '
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)

    try {
        $writer = [System.Xml.XmlWriter]::Create($Path, $settings)
        $Config.Xml.WriteTo($writer)
        $writer.Flush()
    }
    finally {
        if ($writer) { $writer.Dispose() }
    }

    Write-Host "[+] Config exported to: $Path" -ForegroundColor Green
    return $Path
}

function Show-SysmonEvent {
    <#
    .SYNOPSIS
        Displays a parsed Sysmon event in a readable format.
    .PARAMETER Event
        A parsed event object from Import-SysmonEvent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Event
    )

    process {
        foreach ($evt in @($Event)) {
            $eid = $evt.EventId
            $type = $evt.EventType

            Write-Host "`n=====================================" -ForegroundColor Cyan
            Write-Host "  Sysmon Event ID $eid - $type" -ForegroundColor White
            Write-Host "  Computer: $($evt.Computer)  Time: $($evt.TimeStamp)" -ForegroundColor Gray
            Write-Host "=====================================" -ForegroundColor Cyan

            $filterable = $Script:FilterableFields[$type]

            foreach ($key in $evt.Fields.Keys) {
                $value = $evt.Fields[$key]
                if ($filterable -and $key -in $filterable) {
                    Write-Host ("  {0,-25} " -f $key) -NoNewline -ForegroundColor Yellow
                    Write-Host $value
                }
                else {
                    Write-Host ("  {0,-25} {1}" -f $key, $value) -ForegroundColor DarkGray
                }
            }
            Write-Host ""
            if ($filterable) {
                Write-Host "  (Yellow = recommended filter fields)" -ForegroundColor DarkGray
            }
        }
    }
}

function Format-SysmonRule {
    <#
    .SYNOPSIS
        Renders a rule object as formatted XML text for review before applying.
    .PARAMETER Rule
        A rule object from New-SysmonExcludeRule or New-SysmonIncludeRule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule
    )

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("<RuleGroup name=`"`" groupRelation=`"or`">")
    $null = $sb.AppendLine("    <$($Rule.EventType) onmatch=`"$($Rule.MatchType)`">")

    if ($Rule.Conditions.Count -eq 1) {
        $c = $Rule.Conditions[0]
        $nameAttr = if ($Rule.RuleName) { " name=`"$($Rule.RuleName)`"" } else { "" }
        $null = $sb.AppendLine("        <$($c.Field)$nameAttr condition=`"$($c.Condition)`">$([System.Security.SecurityElement]::Escape($c.Value))</$($c.Field)>")
    }
    else {
        $nameAttr = if ($Rule.RuleName) { " name=`"$($Rule.RuleName)`"" } else { "" }
        $null = $sb.AppendLine("        <Rule$nameAttr groupRelation=`"$($Rule.GroupRelation)`">")
        foreach ($c in $Rule.Conditions) {
            $null = $sb.AppendLine("            <$($c.Field) condition=`"$($c.Condition)`">$([System.Security.SecurityElement]::Escape($c.Value))</$($c.Field)>")
        }
        $null = $sb.AppendLine("        </Rule>")
    }

    $null = $sb.AppendLine("    </$($Rule.EventType)>")
    $null = $sb.AppendLine("</RuleGroup>")

    return $sb.ToString()
}

function New-SysmonRuleFromInput {
    <#
    .SYNOPSIS
        Creates a rule manually by specifying field, condition, and value directly.
    .PARAMETER EventType
        The Sysmon event type (e.g., ProcessCreate, DnsQuery).
    .PARAMETER MatchType
        'include' or 'exclude'.
    .PARAMETER FieldName
        The field to filter on (e.g., Image, CommandLine, QueryName).
    .PARAMETER Condition
        The condition operator (e.g., 'is', 'contains', 'end with').
    .PARAMETER Value
        The value to match.
    .PARAMETER RuleName
        Optional label for the rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EventType,

        [Parameter(Mandatory)]
        [ValidateSet('include', 'exclude')]
        [string]$MatchType,

        [Parameter(Mandatory)]
        [string]$FieldName,

        [Parameter(Mandatory)]
        [string]$Condition,

        [Parameter(Mandatory)]
        [string]$Value,

        [string]$RuleName
    )

    if ($Condition -notin $Script:ValidConditions) {
        throw "Invalid condition '$Condition'. Valid: $($Script:ValidConditions -join ', ')"
    }

    [PSCustomObject]@{
        EventType     = $EventType
        MatchType     = $MatchType
        GroupRelation = 'or'
        RuleName      = $RuleName
        Conditions    = @(
            [PSCustomObject]@{
                Field     = $FieldName
                Condition = $Condition
                Value     = $Value
            }
        )
    }
}

# ============================================================================
# INTERACTIVE MODE
# ============================================================================

function Start-SysmonConfigManager {
    <#
    .SYNOPSIS
        Launches the interactive menu-driven Sysmon Config Manager.
    .DESCRIPTION
        Provides a guided workflow for loading configs, analyzing events,
        and building rules. Designed for security teams who want a reliable,
        no-manual-XML-editing experience.
    .PARAMETER ConfigPath
        Optional path to auto-load a config on startup.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )

    $config = $null
    $currentEvents = @()

    Write-Host @"

  ============================================================
   Sysmon Config Manager v1.0
   Intelligent XML Configuration Tuning for Security Teams
  ============================================================
   Workflow: Load Config -> Import Events -> Analyze -> Tune
  ============================================================

"@ -ForegroundColor Cyan

    if ($ConfigPath) {
        try {
            $config = Import-SysmonConfig -Path $ConfigPath
            Write-Host "[+] Loaded config: $ConfigPath (schema $($config.SchemaVersion))" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to load config: $_" -ForegroundColor Red
        }
    }

    while ($true) {
        Write-Host "`n--- Main Menu ---" -ForegroundColor White
        Write-Host "  1. Load/reload Sysmon config" -ForegroundColor Gray
        Write-Host "  2. Import Sysmon event (paste XML)" -ForegroundColor Gray
        Write-Host "  3. Import Sysmon event (from file)" -ForegroundColor Gray
        Write-Host "  4. Import events from Windows Event Log" -ForegroundColor Gray
        Write-Host "  5. Show imported events" -ForegroundColor Gray
        Write-Host "  6. Test events against config" -ForegroundColor Gray
        Write-Host "  7. Generate EXCLUDE rule (reduce noise)" -ForegroundColor Gray
        Write-Host "  8. Generate INCLUDE rule (add detection)" -ForegroundColor Gray
        Write-Host "  9. Create rule manually (field/condition/value)" -ForegroundColor Gray
        Write-Host " 10. Show config statistics" -ForegroundColor Gray
        Write-Host " 11. Find noisy events (Event Log analysis)" -ForegroundColor Gray
        Write-Host " 12. Export config to file" -ForegroundColor Gray
        Write-Host " 13. Remove a rule from config" -ForegroundColor Gray
        Write-Host "  Q. Quit" -ForegroundColor Gray

        $cfgStatus = if ($config) { "[$($config.SchemaVersion)]" } else { "[none loaded]" }
        $evtStatus = "$($currentEvents.Count) event(s) loaded"
        Write-Host "`n  Config: $cfgStatus  |  Events: $evtStatus" -ForegroundColor DarkCyan

        $choice = Read-Host "`nSelect"

        switch ($choice.Trim()) {
            '1' {
                $path = Read-Host "Path to sysmonconfig.xml"
                if ($path) {
                    try {
                        $config = Import-SysmonConfig -Path $path.Trim('"', "'")
                        Write-Host "[+] Loaded: schema $($config.SchemaVersion), path: $($config.Path)" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[!] Error: $_" -ForegroundColor Red
                    }
                }
            }
            '2' {
                Write-Host "Paste Sysmon event XML below (paste all lines, then enter a blank line):" -ForegroundColor Yellow
                $lines = @()
                while ($true) {
                    $line = Read-Host
                    if ([string]::IsNullOrWhiteSpace($line) -and $lines.Count -gt 0) { break }
                    $lines += $line
                }
                $xmlText = $lines -join "`n"
                try {
                    $newEvents = Import-SysmonEvent -XmlString $xmlText
                    $currentEvents += $newEvents
                    Write-Host "[+] Imported $($newEvents.Count) event(s)" -ForegroundColor Green
                    $newEvents | Show-SysmonEvent
                }
                catch {
                    Write-Host "[!] Parse error: $_" -ForegroundColor Red
                }
            }
            '3' {
                $path = Read-Host "Path to event XML file"
                if ($path) {
                    try {
                        $newEvents = Import-SysmonEvent -Path $path.Trim('"', "'")
                        $currentEvents += $newEvents
                        Write-Host "[+] Imported $($newEvents.Count) event(s)" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[!] Error: $_" -ForegroundColor Red
                    }
                }
            }
            '4' {
                $count = Read-Host "How many recent events? (default 10)"
                if (-not $count) { $count = 10 }
                $eidFilter = Read-Host "Filter by Event ID? (blank for all)"
                try {
                    $params = @{ FromEventLog = $true; Count = [int]$count }
                    if ($eidFilter) { $params['EventId'] = [int]$eidFilter }
                    $newEvents = Import-SysmonEvent @params
                    $currentEvents += $newEvents
                    Write-Host "[+] Imported $($newEvents.Count) event(s) from Event Log" -ForegroundColor Green
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '5' {
                if ($currentEvents.Count -eq 0) {
                    Write-Host "[-] No events loaded." -ForegroundColor Yellow
                }
                else {
                    for ($i = 0; $i -lt $currentEvents.Count; $i++) {
                        Write-Host "`n--- Event #$($i + 1) ---" -ForegroundColor White
                        $currentEvents[$i] | Show-SysmonEvent
                    }
                }
            }
            '6' {
                if (-not $config) {
                    Write-Host "[!] Load a config first (option 1)." -ForegroundColor Red
                    continue
                }
                if ($currentEvents.Count -eq 0) {
                    Write-Host "[!] Import events first (options 2-4)." -ForegroundColor Red
                    continue
                }
                foreach ($evt in $currentEvents) {
                    $result = Test-SysmonEvent -Config $config -Event $evt
                    $color = switch ($result.Verdict) {
                        'INCLUDED'   { 'Green' }
                        'EXCLUDED'   { 'Red' }
                        'LOGGED'     { 'Green' }
                        'NOT LOGGED' { 'DarkGray' }
                    }
                    Write-Host "`n  Event ID $($result.EventId) ($($result.EventType)): " -NoNewline
                    Write-Host $result.Verdict -ForegroundColor $color -NoNewline
                    Write-Host " - $($result.Reason)"

                    if ($result.IncludeMatches.Count -gt 0) {
                        Write-Host "    Include matches:" -ForegroundColor Green
                        foreach ($m in $result.IncludeMatches) {
                            Write-Host "      + $m" -ForegroundColor Green
                        }
                    }
                    if ($result.ExcludeMatches.Count -gt 0) {
                        Write-Host "    Exclude matches:" -ForegroundColor Red
                        foreach ($m in $result.ExcludeMatches) {
                            Write-Host "      - $m" -ForegroundColor Red
                        }
                    }
                }
            }
            '7' {
                if ($currentEvents.Count -eq 0) {
                    Write-Host "[!] Import events first." -ForegroundColor Red
                    continue
                }
                $idx = 0
                if ($currentEvents.Count -gt 1) {
                    for ($i = 0; $i -lt $currentEvents.Count; $i++) {
                        Write-Host "  $($i + 1). Event ID $($currentEvents[$i].EventId) - $($currentEvents[$i].EventType)" -ForegroundColor Gray
                    }
                    $idx = [int](Read-Host "Which event #?") - 1
                }
                $evt = $currentEvents[$idx]
                Write-Host "`nAvailable fields with values:" -ForegroundColor Yellow
                $filterable = $Script:FilterableFields[$evt.EventType]
                $fieldChoices = @()
                $fi = 1
                foreach ($f in $filterable) {
                    if ($evt.Fields[$f]) {
                        Write-Host "  $fi. $f = $($evt.Fields[$f])" -ForegroundColor Gray
                        $fieldChoices += $f
                        $fi++
                    }
                }
                $selection = Read-Host "Select fields (comma-separated numbers, or 'all')"
                $selectedFields = @()
                if ($selection -ieq 'all') {
                    $selectedFields = $fieldChoices
                }
                else {
                    foreach ($s in ($selection -split ',')) {
                        $si = [int]$s.Trim() - 1
                        if ($si -ge 0 -and $si -lt $fieldChoices.Count) {
                            $selectedFields += $fieldChoices[$si]
                        }
                    }
                }
                if ($selectedFields.Count -eq 0) {
                    Write-Host "[!] No fields selected." -ForegroundColor Red
                    continue
                }
                $ruleName = Read-Host "Rule name/label (optional, press Enter to skip)"
                try {
                    $rule = New-SysmonExcludeRule -Event $evt -Fields $selectedFields -RuleName $ruleName
                    Write-Host "`n--- Generated Rule XML ---" -ForegroundColor Cyan
                    Write-Host (Format-SysmonRule -Rule $rule) -ForegroundColor White
                    if ($config) {
                        $apply = Read-Host "Apply to loaded config? (y/n)"
                        if ($apply -ieq 'y') {
                            $config = Add-SysmonRule -Config $config -Rule $rule
                        }
                    }
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '8' {
                if ($currentEvents.Count -eq 0) {
                    Write-Host "[!] Import events first." -ForegroundColor Red
                    continue
                }
                $idx = 0
                if ($currentEvents.Count -gt 1) {
                    for ($i = 0; $i -lt $currentEvents.Count; $i++) {
                        Write-Host "  $($i + 1). Event ID $($currentEvents[$i].EventId) - $($currentEvents[$i].EventType)" -ForegroundColor Gray
                    }
                    $idx = [int](Read-Host "Which event #?") - 1
                }
                $evt = $currentEvents[$idx]
                Write-Host "`nAvailable fields with values:" -ForegroundColor Yellow
                $filterable = $Script:FilterableFields[$evt.EventType]
                $fieldChoices = @()
                $fi = 1
                foreach ($f in $filterable) {
                    if ($evt.Fields[$f]) {
                        Write-Host "  $fi. $f = $($evt.Fields[$f])" -ForegroundColor Gray
                        $fieldChoices += $f
                        $fi++
                    }
                }
                $selection = Read-Host "Select fields (comma-separated numbers, or 'all')"
                $selectedFields = @()
                if ($selection -ieq 'all') {
                    $selectedFields = $fieldChoices
                }
                else {
                    foreach ($s in ($selection -split ',')) {
                        $si = [int]$s.Trim() - 1
                        if ($si -ge 0 -and $si -lt $fieldChoices.Count) {
                            $selectedFields += $fieldChoices[$si]
                        }
                    }
                }
                if ($selectedFields.Count -eq 0) {
                    Write-Host "[!] No fields selected." -ForegroundColor Red
                    continue
                }
                $ruleName = Read-Host "Rule name/label (optional, press Enter to skip)"
                try {
                    $rule = New-SysmonIncludeRule -Event $evt -Fields $selectedFields -RuleName $ruleName
                    Write-Host "`n--- Generated Rule XML ---" -ForegroundColor Cyan
                    Write-Host (Format-SysmonRule -Rule $rule) -ForegroundColor White
                    if ($config) {
                        $apply = Read-Host "Apply to loaded config? (y/n)"
                        if ($apply -ieq 'y') {
                            $config = Add-SysmonRule -Config $config -Rule $rule
                        }
                    }
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '9' {
                Write-Host "`nEvent types: ProcessCreate, FileCreateTime, NetworkConnect, ProcessTerminate," -ForegroundColor Gray
                Write-Host "  DriverLoad, ImageLoad, CreateRemoteThread, RawAccessRead, ProcessAccess," -ForegroundColor Gray
                Write-Host "  FileCreate, RegistryEvent, FileCreateStreamHash, PipeEvent, WmiEvent," -ForegroundColor Gray
                Write-Host "  DnsQuery, FileDelete, ClipboardChange, ProcessTampering, FileDeleteDetected" -ForegroundColor Gray
                $et = Read-Host "Event type"
                $mt = Read-Host "Match type (include/exclude)"
                $fn = Read-Host "Field name (e.g., Image, CommandLine, QueryName)"
                Write-Host "Conditions: $($Script:ValidConditions -join ', ')" -ForegroundColor Gray
                $cond = Read-Host "Condition"
                $val = Read-Host "Value"
                $rn = Read-Host "Rule name (optional)"
                try {
                    $rule = New-SysmonRuleFromInput -EventType $et -MatchType $mt -FieldName $fn -Condition $cond -Value $val -RuleName $rn
                    Write-Host "`n--- Generated Rule XML ---" -ForegroundColor Cyan
                    Write-Host (Format-SysmonRule -Rule $rule) -ForegroundColor White
                    if ($config) {
                        $apply = Read-Host "Apply to loaded config? (y/n)"
                        if ($apply -ieq 'y') {
                            $config = Add-SysmonRule -Config $config -Rule $rule
                        }
                    }
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '10' {
                if (-not $config) {
                    Write-Host "[!] Load a config first." -ForegroundColor Red
                    continue
                }
                $stats = Get-SysmonConfigStats -Config $config
                Write-Host "`n=== CONFIG STATISTICS ===" -ForegroundColor White
                Write-Host ("  Schema Version: {0}" -f $config.SchemaVersion) -ForegroundColor Cyan
                Write-Host ("  Source: {0}" -f $config.Path) -ForegroundColor Cyan
                Write-Host ""
                $stats | Format-Table EventType, EventId, IncludeRules, ExcludeRules, TotalRules, Mode -AutoSize
                $total = ($stats | Measure-Object -Property TotalRules -Sum).Sum
                Write-Host "  Total rules across all event types: $total" -ForegroundColor White
            }
            '11' {
                try {
                    $count = Read-Host "How many events to analyze? (default 500)"
                    if (-not $count) { $count = 500 }
                    Find-NoisyEvents -Count ([int]$count)
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '12' {
                if (-not $config) {
                    Write-Host "[!] Load a config first." -ForegroundColor Red
                    continue
                }
                $path = Read-Host "Output path (Enter for default: sysmonconfig-tuned.xml)"
                try {
                    if ($path) {
                        Export-SysmonConfig -Config $config -Path $path.Trim('"', "'")
                    }
                    else {
                        Export-SysmonConfig -Config $config
                    }
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            '13' {
                if (-not $config) {
                    Write-Host "[!] Load a config first." -ForegroundColor Red
                    continue
                }
                $et = Read-Host "Event type (e.g., ProcessCreate)"
                $mt = Read-Host "Match type (include/exclude)"
                $fn = Read-Host "Field name to search for"
                $val = Read-Host "Value to match (blank = remove all with that field name)"
                try {
                    $config = Remove-SysmonRule -Config $config -EventType $et -MatchType $mt -FieldName $fn -Value $val
                }
                catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            { $_ -in 'q', 'Q', 'quit', 'exit' } {
                Write-Host "`nExiting. Stay vigilant." -ForegroundColor Cyan
                return
            }
            default {
                Write-Host "[!] Invalid selection." -ForegroundColor Red
            }
        }
    }
}

# ============================================================================
# AUTO-LAUNCH: if script is run directly (not dot-sourced), start interactive mode
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    $defaultConfig = Join-Path $PSScriptRoot 'sysmonconfig.xml'
    if (Test-Path $defaultConfig) {
        Start-SysmonConfigManager -ConfigPath $defaultConfig
    }
    else {
        Start-SysmonConfigManager
    }
}
