$ASCII = @('
   //**                  ***//
  ///#(**               **%(///
  ((&&&**               **&&&((
   (&&&**   ,(((((((.   **&&&(
   ((&&**(((((//(((((((/**&&((      _____                                                            __      __
    (&&///((////(((((((///&&(      / ___/__  ___________ ___  ____  ____        ____ ___  ____  ____/ /_  __/ /___ ______
     &////(/////(((((/(////&       \__ \/ / / / ___/ __ `__ \/ __ \/ __ \______/ __ `__ \/ __ \/ __  / / / / / __ `/ ___/
     ((//  /////(/////  /(((      ___/ / /_/ (__  ) / / / / / /_/ / / / /_____/ / / / / / /_/ / /_/ / /_/ / / /_/ / /
    &(((((#.///////// #(((((&    /____/\__, /____/_/ /_/ /_/\____/_/ /_/     /_/ /_/ /_/\____/\__,_/\__,_/_/\__,_/_/
     &&&&((#///////((#((&&&&          /____/
       &&&&(#/***//(#(&&&&
         &&&&****///&&&&                                                                            by Olaf Hartong
            (&    ,&.
             .*&&*.
')

$ASCII
function Merge-AllSysmonXml
{
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ByPath')]
        [string[]]$Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ByLiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [parameter(Mandatory=$true, ValueFromPipeline = $true,ParameterSetName = 'ByBasePath')][ValidateScript({Test-Path $_})]
        [String]$BasePath,

        [switch]$AsString,

        [switch]$PreserveComments,

        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})]
        [String]$IncludeList,

        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})]
        [String]$ExcludeList
    )

    begin {
        $FilePaths = @()
        $XmlDocs = @()
        $InclusionFullPaths = @()
        $ExclusionFullPaths = @()
        $FilePathsWithoutExclusions = @()
    }

    process{
        if($PSCmdlet.ParameterSetName -eq 'ByBasePath'){
            $RuleList = Find-RulesInBasePath -BasePath $BasePath
            foreach($R in $RuleList){
                $FilePaths += (Resolve-Path -Path:$R).ProviderPath
            }
        }
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

        if($IncludeList){
            if(!$BasePath){
                throw "BasePath Required For Inclusion List."
                return
    }

            $Inclusions = Get-Content -Path $IncludeList
            foreach($Inclusion in $Inclusions){
                $Inclusion = $Inclusion.TrimStart('\')
                $Inclusion = Join-Path -Path $BasePath -ChildPath $Inclusion
                if($Inclusion -like '*.xml'){
                    if(Test-Path -Path $Inclusion){
                        $InclusionFullPaths += $Inclusion
                    }
                    else{
                        Write-Error "Referenced Rule Inclusion Not Found: $Inclusion"
                    }
                }
            }

            if($InclusionFullPaths){
                Write-Verbose "Rule Inclusions:"
                $FilePaths = $InclusionFullPaths | Sort-Object
                Write-Verbose "$FilePaths"
            }
        }

        if($ExcludeList){
            if(!$BasePath){
                throw "BasePath Required For Exclusions List."
                return
            }

            $Exclusions = Get-Content -Path $ExcludeList
            foreach($Exclusion in $Exclusions){
                $Exclusion = $Exclusion.TrimStart('\')
                $Exclusion = Join-Path -Path $BasePath -ChildPath $Exclusion
                if($Exclusion -like '*.xml'){
                    if(Test-Path -Path $Exclusion){
                        $ExclusionFullPaths += $Exclusion
                    }
                    else{
                        Write-Error "Referenced Rule Exclusion Not Found: $Exclusion"
                    }
                }
            }

            if($ExclusionFullPaths){
                $ExclusionFullPaths = $ExclusionFullPaths | Sort-Object
                Write-Verbose "Rule Exclusions:"
                Write-Verbose "$ExclusionFullPaths"
                foreach($FilePath in $FilePaths){
                    if($FilePath -notin $ExclusionFullPaths){
                        $FilePathsWithoutExclusions += $FilePath
                    }
                }
                $FilePaths = $FilePathsWithoutExclusions
                Write-Verbose "Processing Rules:"
                Write-Verbose "$FilePaths"
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
        FileDeleteDetected = [ordered]@{
            include = @()
            exclude = @()
        }                                
    }

    $newDoc = [xml]@'
<Sysmon schemaversion="4.60">
<HashAlgorithms>*</HashAlgorithms> <!-- This now also determines the file names of the files preserved (String) -->
<CheckRevocation/>
<DnsLookup>False</DnsLookup> <!-- Disables lookup behavior, default is True (Boolean) -->
<ArchiveDirectory>Sysmon</ArchiveDirectory><!-- Sets the name of the directory in the C:\ root where preserved files will be saved (String)-->
<EventFiltering>
    <RuleGroup groupRelation="or">
        <!-- Event ID 1 == Process Creation - Includes -->
        <ProcessCreate onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 1 == Process Creation - Excludes -->
        <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 2 == File Creation Time - Includes -->
        <FileCreateTime onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 2 == File Creation Time - Excludes -->
        <FileCreateTime onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 3 == Network Connection - Includes -->
        <NetworkConnect onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 3 == Network Connection - Excludes -->
        <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 5 == Process Terminated - Includes -->
        <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 6 == Driver Loaded - Excludes -->
        <!--Default to log all and exclude only valid signed Microsoft or Intel drivers-->
        <DriverLoad onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 7 == Image Loaded - Includes -->
        <ImageLoad onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 7 == Image Loaded - Excludes -->
        <ImageLoad onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 8 == CreateRemoteThread - Excludes -->
        <!--Default to log all and exclude a few common processes-->
        <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 9 == RawAccessRead - Includes -->
        <RawAccessRead onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 10 == ProcessAccess - Includes -->
        <ProcessAccess onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 10 == ProcessAccess - Excludes -->
        <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 11 == FileCreate - Includes -->
        <FileCreate onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
    <!-- Event ID 11 == FileCreate - Excludes -->
    <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Includes -->
        <RegistryEvent onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Excludes -->
        <RegistryEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 15 == FileStream Created - Includes -->
        <FileCreateStreamHash onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Includes -->
        <PipeEvent onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
    <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Excludes -->
    <PipeEvent onmatch="exclude"/>
    </RuleGroup>    
    <RuleGroup groupRelation="or">
        <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity - Includes -->
        <WmiEvent onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 22 == DNS Queries and their results Excludes -->
        <!--Default to log all and exclude a few common processes-->        
        <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 23 == File Delete and overwrite events which saves a copy to the archivedir - Includes -->
        <FileDelete onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 23 == File Delete and overwrite events - Excludes -->
        <FileDelete onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 24 == Clipboard change events, only captures text, not files - Includes -->
        <!-- Default set to disabled due to privacy implications and potential data you leave for attackers, enable with care!-->
        <ClipboardChange onmatch="include"/>
    </RuleGroup> 
    <RuleGroup groupRelation="or">
        <!-- Event ID 25 == Process tampering events - Excludes -->
        <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 26 == File Delete and overwrite events, does NOT save the file - Includes -->
        <FileDeleteDetected onmatch="include"/>
    </RuleGroup>
    <RuleGroup groupRelation="or">
        <!-- Event ID 26 == File Delete and overwrite events - Excludes -->
        <FileDeleteDetected onmatch="exclude"/>
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

function Find-RulesInBasePath
{
    param(
        [parameter(Mandatory=$true, ValueFromPipeline = $true,ParameterSetName = 'ByBasePath')][ValidateScript({Test-Path $_})]
        [String]$BasePath,

        [switch]$OutputRules
    )

    begin {
        $RuleList = @()
    }

    process{
        if($PSCmdlet.ParameterSetName -eq 'ByBasePath'){
            $JoinPath = Join-Path -Path $BasePath -ChildPath '[0-9]*\*.xml'
            $RuleList = Get-ChildItem -Path $JoinPath

            foreach($Rule in $RuleList){
                $BaseRule = $Rule.FullName.Replace($BasePath,'')
                $BaseRule = $BaseRule.TrimStart('\')
                $Rule | Add-Member -MemberType NoteProperty -Name Rule -value $BaseRule
            }

            $RuleList = $RuleList | Sort-Object

            if($OutputRules){
                return $RuleList.Rule
            }
            else{
                return $RuleList
            }
        }
    }
}