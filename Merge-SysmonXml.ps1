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

        [switch]$VerboseLogging,

        [switch]$MDEaugment,

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
                $InclusionFragment = $Inclusion
                $Inclusion = Join-Path -Path $BasePath -ChildPath $Inclusion
                if($Inclusion -like '*.xml'){
                    if(Test-Path -Path $Inclusion){
                        $InclusionFullPaths += $Inclusion
                    }
                    else{
                        Write-Error "Referenced Rule Inclusion Not Found: $Inclusion"
                    }
                }
                elseif((Test-Path $Inclusion) -and ($InclusionFolder = Get-ChildItem -Path $BasePath -Directory -Name $InclusionFragment ))
                {
                    foreach($Inclusion in Get-ChildItem -Path $InclusionFolder -File -Filter "*.xml")
                    {
                        $InclusionFullPaths += $Inclusion.FullName
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

#        $newDoc = $XmlDocs[0]
#        for($i = 1; $i -lt $XmlDocs.Count; $i++){
#            $newDoc = Merge-SysmonXml -Source $newDoc -Diff $XmlDocs[$i]
#        }
        if($VerboseLogging){
            $newDoc = $XmlDocs[0]
            for($i = 1; $i -lt $XmlDocs.Count; $i++){
                $newDoc = Merge-SysmonXml -Source $newDoc -Diff $XmlDocs[$i] -VerboseLogging
            }
        }
        else{
            $newDoc = $XmlDocs[0]
            for($i = 1; $i -lt $XmlDocs.Count; $i++){
                $newDoc = Merge-SysmonXml -Source $newDoc -Diff $XmlDocs[$i]
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
}

function Merge-SysmonXml
{
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'FromXmlDoc')]
        [xml]$Source,

        [Parameter(Mandatory = $true, ParameterSetName = 'FromXmlDoc')]
        [xml]$Diff,

        [switch]$AsString,

        [switch]$VerboseLogging
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

    $general = [xml]@'
<!--                       NOTICE : This is a balanced generated output of Sysmon-modular with medium verbosity                  -->
<!--                        due to the balanced nature of this configuration there will be potential blind spots                 -->
<!--                        for more information go to https://github.com/olafhartong/sysmon-modular/wiki                        -->
<!--                                                                                                                             -->
<!--  //**                  ***//                                                                                                -->
<!-- ///#(**               **%(///                                                                                               -->
<!-- ((&&&**               **&&&((                                                                                               -->
<!--  (&&&**   ,(((((((.   **&&&(                                                                                                -->
<!--  ((&&**(((((//(((((((/**&&((      _____                                                            __      __               -->
<!--   (&&///((////(((((((///&&(      / ___/__  ___________ ___  ____  ____        ____ ___  ____  ____/ /_  __/ /___ ______     -->
<!--    &////(/////(((((/(////&       \__ \/ / / / ___/ __ `__ \/ __ \/ __ \______/ __ `__ \/ __ \/ __  / / / / / __ `/ ___/     -->
<!--    ((//  /////(/////  /(((      ___/ / /_/ (__  ) / / / / / /_/ / / / /_____/ / / / / / /_/ / /_/ / /_/ / / /_/ / /         -->
<!--   &(((((#.///////// #(((((&    /____/\__, /____/_/ /_/ /_/\____/_/ /_/     /_/ /_/ /_/\____/\__,_/\__,_/_/\__,_/_/          -->
<!--    &&&&((#///////((#((&&&&          /____/                                                                                  -->
<!--      &&&&(#/***//(#(&&&&                                                                                                    -->
<!--        &&&&****///&&&&                                                                            by Olaf Hartong           -->
<!--           (&    ,&.                                                                                                         -->
<!--            .*&&*.                                                                                                           -->
<!--                                                                                                                             -->
<Sysmon schemaversion="4.60">
<HashAlgorithms>*</HashAlgorithms> <!-- This now also determines the file names of the files preserved (String) -->
<CheckRevocation>False</CheckRevocation> <!-- Setting this to true might impact performance -->
<DnsLookup>False</DnsLookup> <!-- Disables lookup behavior, default is True (Boolean) -->
<ArchiveDirectory>Sysmon</ArchiveDirectory><!-- Sets the name of the directory in the C:\ root where preserved files will be saved (String)-->
<EventFiltering>
    <!-- Event ID 1 == Process Creation - Includes -->
    <RuleGroup groupRelation="or">
        <ProcessCreate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 1 == Process Creation - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 2 == File Creation Time - Includes -->
    <RuleGroup groupRelation="or">
        <FileCreateTime onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 2 == File Creation Time - Excludes -->
    <RuleGroup groupRelation="or">
        <FileCreateTime onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection - Includes -->
    <RuleGroup groupRelation="or">
        <NetworkConnect onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection - Excludes -->
    <RuleGroup groupRelation="or">
        <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == Process Terminated - Includes -->
    <RuleGroup groupRelation="or">
        <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 6 == Driver Loaded - Excludes -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude only valid signed Microsoft or Intel drivers-->
        <DriverLoad onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 7 == Image Loaded - Includes -->
    <RuleGroup groupRelation="or">
        <ImageLoad onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 7 == Image Loaded - Excludes -->
    <RuleGroup groupRelation="or">
        <ImageLoad onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 8 == CreateRemoteThread - Excludes -->
    <RuleGroup groupRelation="or">
         <!--Default to log all and exclude a few common processes-->
        <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead - Includes -->
    <RuleGroup groupRelation="or">
        <RawAccessRead onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess - Includes -->
    <RuleGroup groupRelation="or">
        <ProcessAccess onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate - Includes -->
    <RuleGroup groupRelation="or">
        <FileCreate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate - Excludes -->
    <RuleGroup groupRelation="or">
    <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Includes -->
    <RuleGroup groupRelation="or">
        <RegistryEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Excludes -->
    <RuleGroup groupRelation="or">
        <RegistryEvent onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 15 == FileStream Created - Includes -->
    <RuleGroup groupRelation="or">
        <FileCreateStreamHash onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Includes -->
    <RuleGroup groupRelation="or">
        <PipeEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Excludes -->
    <RuleGroup groupRelation="or">
    <PipeEvent onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity - Includes -->
    <RuleGroup groupRelation="or">
        <WmiEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 22 == DNS Queries and their results Excludes -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude a few common processes-->
        <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 23 == File Delete and overwrite events which saves a copy to the archivedir - Includes -->
    <!-- Default set to disabled due to disk space implications, enable with care!-->
    <RuleGroup groupRelation="or">
        <FileDelete onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 24 == Clipboard change events, only captures text, not files - Includes -->
    <!-- Default set to disabled due to privacy implications and potential data you leave for attackers, enable with care!-->
    <RuleGroup groupRelation="or">
        <ClipboardChange onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 25 == Process tampering events - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 26 == File Delete and overwrite events, does NOT save the file - Includes -->
    <RuleGroup groupRelation="or">
        <FileDeleteDetected onmatch="include"/>
    </RuleGroup>
        <!-- Event ID 26 == File Delete and overwrite events - Excludes -->
    <RuleGroup groupRelation="or">
        <FileDeleteDetected onmatch="exclude"/>
    </RuleGroup>
</EventFiltering>
</Sysmon>
'@

    $fulllog = [xml]@'
<!--                        NOTICE : This is a custom generated output of Sysmon-modular with higher verbosity                   -->
<!--                    The log volume expected from this file is significantly larger than a more balanced log                  -->
<!--                                the blind spots for this config are to be significantly less                                 -->
<!--                        for more information go to https://github.com/olafhartong/sysmon-modular/wiki                        -->
<!--                                                                                                                             -->
<!--  //**                  ***//                                                                                                -->
<!-- ///#(**               **%(///                                                                                               -->
<!-- ((&&&**               **&&&((                                                                                               -->
<!--  (&&&**   ,(((((((.   **&&&(                                                                                                -->
<!--  ((&&**(((((//(((((((/**&&((      _____                                                            __      __               -->
<!--   (&&///((////(((((((///&&(      / ___/__  ___________ ___  ____  ____        ____ ___  ____  ____/ /_  __/ /___ ______     -->
<!--    &////(/////(((((/(////&       \__ \/ / / / ___/ __ `__ \/ __ \/ __ \______/ __ `__ \/ __ \/ __  / / / / / __ `/ ___/     -->
<!--    ((//  /////(/////  /(((      ___/ / /_/ (__  ) / / / / / /_/ / / / /_____/ / / / / / /_/ / /_/ / /_/ / / /_/ / /         -->
<!--   &(((((#.///////// #(((((&    /____/\__, /____/_/ /_/ /_/\____/_/ /_/     /_/ /_/ /_/\____/\__,_/\__,_/_/\__,_/_/          -->
<!--    &&&&((#///////((#((&&&&          /____/                                                                                  -->
<!--      &&&&(#/***//(#(&&&&                                                                                                    -->
<!--        &&&&****///&&&&                                                                            by Olaf Hartong           -->
<!--           (&    ,&.                                                                                                         -->
<!--            .*&&*.                                                                                                           -->
<!--                                                                                                                             -->
<Sysmon schemaversion="4.60">
<HashAlgorithms>*</HashAlgorithms> <!-- This now also determines the file names of the files preserved (String) -->
<CheckRevocation>False</CheckRevocation> <!-- Setting this to true might impact performance -->
<DnsLookup>False</DnsLookup> <!-- Disables lookup behavior, default is True (Boolean) -->
<ArchiveDirectory>Sysmon</ArchiveDirectory><!-- Sets the name of the directory in the C:\ root where preserved files will be saved (String)-->
<EventFiltering>
    <!-- Event ID 1 == Process Creation - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 2 == File Creation Time - Excludes -->
    <RuleGroup groupRelation="or">
        <FileCreateTime onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection - Excludes -->
    <RuleGroup groupRelation="or">
        <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == Process Terminated - Includes -->
    <RuleGroup groupRelation="or">
        <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 6 == Driver Loaded - Excludes -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude only valid signed Microsoft or Intel drivers-->
        <DriverLoad onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 7 == Image Loaded - Excludes -->
    <RuleGroup groupRelation="or">
        <ImageLoad onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 8 == CreateRemoteThread - Excludes -->
    <RuleGroup groupRelation="or">
         <!--Default to log all and exclude a few common processes-->
        <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead - Includes -->
    <RuleGroup groupRelation="or">
        <RawAccessRead onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate - Excludes -->
    <RuleGroup groupRelation="or">
    <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Excludes -->
    <RuleGroup groupRelation="or">
        <RegistryEvent onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 15 == FileStream Created - Excludes -->
    <RuleGroup groupRelation="or">
        <FileCreateStreamHash onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Excludes -->
    <RuleGroup groupRelation="or">
    <PipeEvent onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity - Excludes -->
    <RuleGroup groupRelation="or">
        <WmiEvent onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 22 == DNS Queries and their results Excludes -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude a few common processes-->
        <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 23 == File Delete and overwrite events which saves a copy to the archivedir - Includes -->
    <RuleGroup groupRelation="or">
        <FileDelete onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 23 == File Delete and overwrite events - Excludes -->
    <RuleGroup groupRelation="or">
        <FileDelete onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 24 == Clipboard change events, only captures text, not files - Includes -->
    <RuleGroup groupRelation="or">
        <!-- Default set to disabled due to privacy implications and potential data you leave for attackers, enable with care!-->
        <ClipboardChange onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 25 == Process tampering events - Excludes -->
    <RuleGroup groupRelation="or">
        <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
        <!-- Event ID 26 == File Delete and overwrite events - Excludes -->
    <RuleGroup groupRelation="or">
        <FileDeleteDetected onmatch="exclude"/>
    </RuleGroup>
</EventFiltering>
</Sysmon>
'@

$mdeaugmentlog = [xml]@'
<!--                        NOTICE : This is a custom generated output of Sysmon-modular to fill in the gaps of                  -->
<!--                       Microsoft Defender for Endpoint (MDE). This is based on a balanced generated output of                -->
<!--                              Sysmon-modular with medium verbosity due to the balanced nature of this                        -->
<!--                                        configuration there will be potential blind spots.                                   -->
<!--                                                                                                                             -->
<!--        Alternatively, in the benefit of IR, consider using the excludes only config and only ingest the enriching events.   -->
<!--                                                                                                                             -->
<!--  //**                  ***//                                                                                                -->
<!-- ///#(**               **%(///                                                                                               -->
<!-- ((&&&**               **&&&((                                                                                               -->
<!--  (&&&**   ,(((((((.   **&&&(                                                                                                -->
<!--  ((&&**(((((//(((((((/**&&((      _____                                                            __      __               -->
<!--   (&&///((////(((((((///&&(      / ___/__  ___________ ___  ____  ____        ____ ___  ____  ____/ /_  __/ /___ ______     -->
<!--    &////(/////(((((/(////&       \__ \/ / / / ___/ __ `__ \/ __ \/ __ \______/ __ `__ \/ __ \/ __  / / / / / __ `/ ___/     -->
<!--    ((//  /////(/////  /(((      ___/ / /_/ (__  ) / / / / / /_/ / / / /_____/ / / / / / /_/ / /_/ / /_/ / / /_/ / /         -->
<!--   &(((((#.///////// #(((((&    /____/\__, /____/_/ /_/ /_/\____/_/ /_/     /_/ /_/ /_/\____/\__,_/\__,_/_/\__,_/_/          -->
<!--    &&&&((#///////((#((&&&&          /____/                                                                                  -->
<!--      &&&&(#/***//(#(&&&&                                                                                                    -->
<!--        &&&&****///&&&&                                                                            by Olaf Hartong           -->
<!--           (&    ,&.                                                                                                         -->
<!--            .*&&*.                                                                                                           -->
<!--                                                                                                                             -->
<Sysmon schemaversion="4.60">
<HashAlgorithms>*</HashAlgorithms> <!-- This now also determines the file names of the files preserved (String) -->
<CheckRevocation>False</CheckRevocation> <!-- Setting this to true might impact performance -->
<DnsLookup>False</DnsLookup> <!-- Disables lookup behavior, default is True (Boolean) -->
<ArchiveDirectory>Sysmon</ArchiveDirectory><!-- Sets the name of the directory in the C:\ root where preserved files will be saved (String)-->
<EventFiltering>
    <!-- Event ID 1 == Process Creation - Sysmon will not provide notable additional visibility over MDE. -->
    <!-- The biggest improvement there would be the per process GUIDs for easier correlation. -->
    <!-- Additionally, the IMPHASH can provide additional insight at the expense of generating process creation events. -->
    <RuleGroup groupRelation="or">
        <ProcessCreate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 2 == File Creation Time - Sysmon will not provide notable additional visibility over MDE. -->
    <RuleGroup groupRelation="or">
        <FileCreateTime onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection - Sysmon will provide way more visibility here, since there is no cap restriction. -->
    <RuleGroup groupRelation="or">
        <NetworkConnect onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection - Excludes. -->
    <RuleGroup groupRelation="or">
        <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == Process Terminated - Sysmon will provide way more visibility here, MDE does not record this. -->
    <RuleGroup groupRelation="or">
        <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 6 == Driver Loaded - Sysmon will not provide notable additional visibility over MDE. -->
    <RuleGroup groupRelation="or">
        <DriverLoad onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 7 == Image Loaded - Sysmon will provide way more visibility here, since there is no cap restriction. -->
    <RuleGroup groupRelation="or">
        <ImageLoad onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 7 == Image Loaded - Excludes. -->
    <RuleGroup groupRelation="or">
        <ImageLoad onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 8 == CreateRemoteThread - Sysmon will not provide notable additional visibility over MDE. -->
    <RuleGroup groupRelation="or">
        <CreateRemoteThread onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead - Disabled -->
    <RuleGroup groupRelation="or">
        <RawAccessRead onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess - Sysmon will provide way more visibility here, since there is no cap and process restriction. -->
    <RuleGroup groupRelation="or">
        <ProcessAccess onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess - Excludes. -->
    <RuleGroup groupRelation="or">
        <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate - Sysmon will not provide notable additional visibility over MDE in the most common folders. Enable for your company specific folders. -->
    <RuleGroup groupRelation="or">
    <FileCreate onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 12,13,14 == RegObject added/deleted, RegValue Set, RegObject Renamed - Sysmon will not provide notable additional visibility over MDE. Enable for your company specific keys. -->
    <RuleGroup groupRelation="or">
        <RegistryEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 15 == FileStream Created - Sysmon will provide way more visibility here, the current equivalent in MDE is unreliable. -->
    <RuleGroup groupRelation="or">
        <FileCreateStreamHash onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 15 == FileStream Created - Excludes. -->
    <RuleGroup groupRelation="or">
        <FileCreateStreamHash onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 17,18 == PipeEvent. Log Named pipe created & Named pipe connected - Sysmon will not provide notable additional visibility over MDE for most users. -->
    <RuleGroup groupRelation="or">
    <PipeEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 19,20,21, == WmiEvent. Log all WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter activity - Sysmon will not provide notable additional visibility over MDE. -->
    <RuleGroup groupRelation="or">
        <WmiEvent onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 22 == DNS Queries and their results - Sysmon will provide way more visibility here. MDE only records responses to successful requests and less query types. -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude a few common processes-->
        <DnsQuery onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 22 == DNS Queries and their results - Excludes. -->
    <RuleGroup groupRelation="or">
        <!--Default to log all and exclude a few common processes-->
        <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 23 == File Delete and overwrite events which saves a copy to the archivedir - Only use in IR -->
    <RuleGroup groupRelation="or">
        <FileDelete onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 24 == Clipboard change events, only captures text, not files - Only use in IR -->
    <RuleGroup groupRelation="or">
        <!-- Default set to disabled due to privacy implications and potential data you leave for attackers, enable with care!-->
        <ClipboardChange onmatch="include"/>
    </RuleGroup>
    <!-- Event ID 25 == Process tampering events - Sysmon will provide some more visibility here. MDE records this behavior but does not expose the telemetry (yet) -->
    <RuleGroup groupRelation="or">
        <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
        <!-- Event ID 26 == File Delete and overwrite events - Sysmon will not provide notable additional visibility over MDE in the most common folders. Enable for your company specific folders. -->
    <RuleGroup groupRelation="or">
        <FileDeleteDetected onmatch="include"/>
    </RuleGroup>
</EventFiltering>
</Sysmon>
'@

    if($VerboseLogging){
        $newDoc = $fulllog
    }
    elseif ($MDEaugment) {
        $newDoc = $mdeaugmentlog
    }
    else {
        $newDoc = $general
    }

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
