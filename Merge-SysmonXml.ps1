function Merge-AllSysmonXml
{
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('FullName')]
        [string[]]$Path,

        [switch]$AsString,

        [switch]$PreserveComments
    )

    begin {
        $XmlDocs = @()
    }

    process{
        foreach($FilePath in $Path){
            $doc = [xml]::new()
            Write-Verbose "Loading doc from '$FilePath'..."
            $doc.Load($(Resolve-Path $FilePath))
            if(-not $PreserveComments){
                Write-Verbose "Stripping comments for '$FilePath'"
                $commentNodes = $doc.SelectNodes('//comment()')
                foreach($commentNode in $commentNodes){
                    $null = $commentNode.ParentNode.RemoveChild($commentNode)
                }
            }
            $XmlDocs += $doc
        }
    }

    end{
        if($XmlDocs.Count -lt 2){
            throw 'At least 2 sysmon configs expected'
            return
        }

        $newDoc = $XmlDocs[0]
        for($i = 1; $i -lt $XmlDocs.Count; $i++){
            $newDoc = Merge-SysmonXml -Source $newDoc -Diff $XmlDocs[$i]
        }

        if($AsString){
            try{
                $sw = [System.IO.StringWriter]::new()
                $xw = [System.Xml.XmlTextWriter]::new($sw)
                $xw.Formatting = 'Indented'
                $newDoc.WriteContentTo($xw)
                return $sw.ToString()
            }
            finally{
                $xw.Dispose()
                $sw.Dispose()
            }
        }
        else {
            return $newDoc
        }
    }
}

function Merge-SysmonXml
{
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'FromXmlDoc')]
        [xml]$Source,

        [Parameter(Mandatory = $true, ParameterSetName = 'FromXmlDoc')]
        [xml]$Diff,

        [switch]$AsString
    )

    $Rules = @{
        ProcessCreate = @{
            include = @()
            exclude = @()
        }
        FileCreateTime = @{
            include = @()
            exclude = @()
        }
        NetworkConnect = @{
            include = @()
            exclude = @()
        }
        ProcessTerminate = @{
            include = @()
            exclude = @()
        }
        DriverLoad = @{
            include = @()
            exclude = @()
        }
        ImageLoad = @{
            include = @()
            exclude = @()
        }
        CreateRemoteThread = @{
            include = @()
            exclude = @()
        }
        RawAccessRead = @{
            include = @()
            exclude = @()
        }
        ProcessAccess = @{
            include = @()
            exclude = @()
        }
        FileCreate = @{
            include = @()
            exclude = @()
        }
        RegistryEvent = @{
            include = @()
            exclude = @()
        }
        FileCreateStreamHash = @{
            include = @()
            exclude = @()
        }
        PipeEvent = @{
            include = @()
            exclude = @()
        }
        WmiEvent = @{
            include = @()
            exclude = @()
        }
        DnsQuery = @{
            include = @()
            exclude = @()
        }
    }

    $newDoc = [xml]@'
<Sysmon schemaversion="4.22">
<!-- Capture all hashes -->
<HashAlgorithms>*</HashAlgorithms>
<CheckRevocation/>
<EventFiltering>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 1 == Process Creation. -->
        <ProcessCreate onmatch="include"/>
        <!-- Event ID 2 == File Creation Time. -->
        <FileCreateTime onmatch="include"/>
        <!-- Event ID 3 == Network Connection. -->
        <NetworkConnect onmatch="include"/>
        <!-- Event ID 5 == Process Terminated. -->
        <ProcessTerminate onmatch="include"/>
        <!-- Event ID 6 == Driver Loaded. -->
        <DriverLoad onmatch="include"/>
        <!-- Event ID 7 == Image Loaded. -->
        <ImageLoad onmatch="include"/>
        <!-- Event ID 8 == CreateRemoteThread. -->
        <CreateRemoteThread onmatch="include"/>
        <!-- Event ID 9 == RawAccessRead. -->
        <RawAccessRead onmatch="include"/>
        <!-- Event ID 10 == ProcessAccess. -->
        <ProcessAccess onmatch="include"/>
        <!-- Event ID 11 == FileCreate. -->
        <FileCreate onmatch="include"/>
        <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed. -->
        <RegistryEvent onmatch="include"/>
        <!-- Event ID 15 == FileStream Created. -->
        <FileCreateStreamHash onmatch="include"/>
        <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected -->
        <PipeEvent onmatch="exclude"/>
        <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity-->
        <WmiEvent onmatch="include"/>
    </RuleGroup>
</EventFiltering>
</Sysmon>
'@

$mainRuleGroup = $newDoc.SelectSingleNode('//EventFiltering/RuleGroup')

    foreach($key in $Rules.Keys){
        foreach($config in $Source,$Diff){
            foreach($rule in $config.SelectNodes("//RuleGroup/$Key"))
            {
                $clone = $rule.CloneNode($true)
                $onmatch = ([System.Xml.XmlElement]$clone).GetAttribute('onmatch')
                if(-not $onmatch){
                    $onmatch = 'include'
                }

                $Rules[$key][$onmatch] += $clone
            }
        }

        foreach($matchType in 'include','exclude'){
            foreach($rule in $Rules[$key][$matchType]){
                if($existing = $mainRuleGroup.SelectSingleNode("$key[@onmatch = '$matchType']")){
                    foreach($child in $rule.ChildNodes){
                        $newNode = $newDoc.ImportNode($child, $true)
                        $null = $existing.AppendChild($newNode)
                    }
                }
                else{
                    $newNode = $newDoc.ImportNode($rule, $true)
                    $null = $mainRuleGroup.AppendChild($newNode)
                }
            }
        }
    }

    if($AsString){
        try{
            $sw = [System.IO.StringWriter]::new()
            $xw = [System.Xml.XmlTextWriter]::new($sw)
            $xw.Formatting = 'Indented'
            $newDoc.WriteContentTo($xw)
            return $sw.ToString()
        }
        finally{
            $xw.Dispose()
            $sw.Dispose()
        }
    }
    else {
        return $newDoc
    }
}