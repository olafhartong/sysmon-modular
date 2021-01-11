function Merge-AllSysmonXml
{
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ByPath')]
        [string[]]$Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ByLiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [switch]$AsString,

        [switch]$PreserveComments
    )

    begin {
        $FilePaths = @()
        $XmlDocs = @()
    }

    process{
        if($PSCmdlet.ParameterSetName -eq 'ByPath'){
            foreach($P in $Path){
                $FilePaths += (Resolve-Path -Path:$P).ProviderPath
            }
        }
        else{
            foreach($LP in $LiteralPath){
                $FilePaths += (Resolve-Path -LiteralPath:$LP).ProviderPath
            }
        }
    }

    end{
        foreach($FilePath in $FilePaths){
            $doc = [xml]::new()
            Write-Verbose "Loading doc from '$FilePath'..."
            $doc.Load($FilePath)
            if(-not $PreserveComments){
                Write-Verbose "Stripping comments for '$FilePath'"
                $commentNodes = $doc.SelectNodes('//comment()')
                foreach($commentNode in $commentNodes){
                    $null = $commentNode.ParentNode.RemoveChild($commentNode)
                }
            }
            $XmlDocs += $doc
        }
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

    $Rules = [ordered]@{
        ProcessCreate = [ordered]@{
            include = @()
            exclude = @()
        }
        FileCreateTime = [ordered]@{
            include = @()
            exclude = @()
        }
        NetworkConnect = [ordered]@{
            include = @()
            exclude = @()
        }
        ProcessTerminate = [ordered]@{
            include = @()
            exclude = @()
        }
        DriverLoad = [ordered]@{
            include = @()
            exclude = @()
        }
        ImageLoad = [ordered]@{
            include = @()
            exclude = @()
        }
        CreateRemoteThread = [ordered]@{
            include = @()
            exclude = @()
        }
        RawAccessRead = [ordered]@{
            include = @()
            exclude = @()
        }
        ProcessAccess = [ordered]@{
            include = @()
            exclude = @()
        }
        FileCreate = [ordered]@{
            include = @()
            exclude = @()
        }
        RegistryEvent = [ordered]@{
            include = @()
            exclude = @()
        }
        FileCreateStreamHash = [ordered]@{
            include = @()
            exclude = @()
        }
        PipeEvent = [ordered]@{
            include = @()
            exclude = @()
        }
        WmiEvent = [ordered]@{
            include = @()
            exclude = @()
        }
        DnsQuery = [ordered]@{
            include = @()
            exclude = @()
        }
        FileDelete = [ordered]@{
            include = @()
            exclude = @()
        } 
        ClipboardChange = [ordered]@{
            include = @()
            exclude = @()
        }
        ProcessTampering = [ordered]@{
            include = @()
            exclude = @()
        }                        
    }

    $newDoc = [xml]@'
<Sysmon schemaversion="4.50">
<HashAlgorithms>*</HashAlgorithms> <!-- This now also determines the file names of the files preserved (String) -->
<CheckRevocation/>
<DnsLookup>False</DnsLookup> <!-- Disables lookup behavior, default is True (Boolean) -->
<ArchiveDirectory>Sysmon</ArchiveDirectory><!-- Sets the name of the directory in the C:\ root where preserved files will be saved (String)-->
<CaptureClipboard /><!--This enables capturing the Clipboard changes-->
<EventFiltering>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 1 == Process Creation. -->
        <ProcessCreate onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 2 == File Creation Time. -->
        <FileCreateTime onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 3 == Network Connection. -->
        <NetworkConnect onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 5 == Process Terminated. -->
        <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 6 == Driver Loaded. -->
        <DriverLoad onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 7 == Image Loaded. -->
        <ImageLoad onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 8 == CreateRemoteThread. -->
        <!--Default to log all and exclude a few common processes-->
        <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 9 == RawAccessRead. -->
        <RawAccessRead onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 10 == ProcessAccess. -->
        <ProcessAccess onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 11 == FileCreate. -->
        <FileCreate onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed. -->
        <RegistryEvent onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 15 == FileStream Created. -->
        <FileCreateStreamHash onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected -->
        <PipeEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity -->
        <WmiEvent onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 22 == DNS Queries and their results-->
        <!--Default to log all and exclude a few common processes-->        
        <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 23 == File Delete and overwrite events-->
        <FileDelete onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 24 == Clipboard change events, only captures text, not files -->
        <!-- Default set to disabled due to privacy implications and potential data you leave for attackers, enable with care!-->
        <ClipboardChange onmatch="include"/>
    </RuleGroup> 
    <RuleGroup name="" groupRelation="or">
        <!-- Event ID 25 == Process tampering events -->
        <ProcessTampering onmatch="exclude"/>
    </RuleGroup>                
</EventFiltering>
</Sysmon>
'@

    $EventFilteringRoot = $newDoc.SelectSingleNode('//Sysmon/EventFiltering')

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
            Write-Verbose "About to merge ${key}:${matchType}"
            foreach($rule in $Rules[$key][$matchType]){
                if($existing = $newDoc.SelectSingleNode("//RuleGroup/$key[@onmatch = '$matchType']")){
                    foreach($child in $rule.ChildNodes){
                        $newNode = $newDoc.ImportNode($child, $true)
                        $null = $existing.AppendChild($newNode)
                    }
                }
                else{
                    $newRuleGroup = $newDoc.CreateElement('RuleGroup')
                    $newRuleGroup.SetAttribute('groupRelation','or')
                    $newNode = $newDoc.ImportNode($rule, $true)
                    $null = $newRuleGroup.AppendChild($newNode)
                    $null = $EventFilteringRoot.AppendChild($newRuleGroup)
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