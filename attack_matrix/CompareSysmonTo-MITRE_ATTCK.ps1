<#
.Synopsis
    Description: For Sysmon Modular MITRE ATT&CK Management!
.DESCRIPTION
    Requirements: PowerShell 7+ and Windows 10
    This script is useful for checking your Sysmon config for invalid and valid MITRE ATT&CK TTPs. ModularConfig Path is used for recursively looking for all include_* files.  CompiledConfigPath is good for a single .xml file. 
    It also provides a good reference for the latest MITRE ATT&CK and what is found in your Sysmon Config.
    Lastly, there is a built in integration to ingest MITRE ATT&CK Tactics and Techniques into Elasticsearch as an index called mitre_attck.

.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1
    .\CompareSysmonTo-MITRE_ATTCK.ps1 -ModularConfigPath "C:\Users\blu3teamer\Downloads\sysmon-modular-master" -CompiledConfigPath "C:\Users\blu3teamer\Downloads\sysmon-modular-master\sysmonconfig.xml"
#>

[CmdletBinding()]
[Alias()]
Param
(
    # The location of the Sysmon modular config directory.
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
    $ModularConfigPath,
    # The location of the Sysmon compiled config file.
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
    $CompiledConfigPath
)

if($null -eq $ModularConfigPath -and $null -eq $CompiledConfigPath){
    $runTimePath = Read-Host -Prompt "Please enter the path of a modular directory or merged xml file" 
    if($runTimePath -match ".xml"){
        Write-Host "This is an XMl file." -ForegroundColor Yellow
        $CompiledConfigPath = $runTimePath
    }else{
        Write-Host "Assuming this is a directory since your path did not contain .xml. Recursivley looking for include_*.xml files in your path: $runTimePath." -ForegroundColor Yellow
        $ModularConfigPath = $runTimePath
    }
}

$latestMITRE = Read-Host "Would you like to load the latest MITRE ATT&CK from GitHub? (Requires Internet Connectivity) (y or n)"
if($latestMITRE -eq "y"){
    #Get latest copy of Mitre ATT&CK Framework
    Write-Host "Getting latest MITRE ATT&CK Framework!" -Foreground Green
    $mitreURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    $mitre = Invoke-RestMethod $mitreURL
    if($mitre){
        Write-Host "Latest MITRE ATT&CK Framework loaded and ready for use!" -Foreground Blue
    }else{
        Write-Host "Could not download latest MITRE ATT&CK Framework check your internet connection. Exiting."
        exit
    }
}elseif($latestMITRE -eq "n"){
    $mitreLocalFile = Read-Host "Please enter the full path of the enterprise-attck.json file from MITRE's GitHub repo"
    $mitre = Get-Content $mitreLocalFile | ConvertFrom-Json
    if($mitre){
        Write-Host "Local MITRE ATT&CK Framework loaded and ready for use!" -Foreground Blue
    }else{
        Write-Host "Could not load local MITRE ATT*CK json. Exiting."
        exit
    }
}else{
    Write-Host "Not a valid option - Please rerun the script with a valid option. Exiting."
    exit
}

$sysmon = [xml]''
$sysmonAll = [xml]''

#TTP Regex 
$ttp_technique = 'tactic_id=(.*),tactic_name=(.*),technique_id=(.*),technique_name=(.*),subtechnique_id=(.*),subtechnique_name=(.*)|tactic_id=(.*),tactic_name=(.*),technique_id=(.*),technique_name=(.*)|technique_id=(.*),technique_name=(.*)'

############################################################################################################## MITRE ATT&CK ##############################################################################################################
# All of the below commented is for testing and future concepts.

#Tactics
#$mitre.objects | Where-Object {$_.type -eq "x-mitre-tactic"} | Select-Object -Property name, type, modified, created | Out-GridView
#$tactics = $mitre.objects | Where-Object {$_.type -eq "x-mitre-tactic"}

#Techniques (Attack Patterns)
#$mitre.objects | Where-Object {$_.type -eq "attack-pattern"} | Select-Object -Property name, type, external_references, modified, created | Out-GridView

#Techniques (Attack Patterns)
#$mitre.objects | Where-Object {$_.external_references.source_name -eq "mitre-attack"} | Select-Object -Property external_references, name, kill_chain_phases | Out-GridView


$global:techniquesTable = @()
$global:techniquesTableObject = @()
$tacticName = @()
$tacticId = @()
function getLatestTechniques {
    $techniques = $mitre.objects | Where-Object {$_.external_references.source_name -eq "mitre-attack" -and $_.type -eq "attack-pattern" -and  $null -ne $_.kill_chain_phases.phase_name } | Select-Object -Property external_references, name, kill_chain_phases, x_mitre_is_subtechnique, created, modified, x_mitre_version
    $tactics = $mitre.objects | Where-Object {$_.type -eq "x-mitre-tactic" } | Select-Object -Property external_references, name, x_mitre_shortname
    $techniques | ForEach-Object {
        $tacticName = $(if($_.kill_chain_phases.phase_name){$_.kill_chain_phases.phase_name | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($($_))}}else{}).Replace("-", " ")
        $tacticId = $tactics | Where-Object -Property name -In $tacticName
        $techniqueID = $($_.external_references | Where-Object {$null -ne $_.external_id} | Select-Object -Property external_id).external_id.split('.')[0]
        $techniqueName = $(if($null -eq $_.x_mitre_is_subtechnique){$_.name}else{$techniques | Where-Object {$_.external_references.external_id -eq $techniqueID} | Select-Object name}).name
        $techniqueReference = if($null -eq $_.x_mitre_is_subtechnique){$($_.external_references | Where-Object -property source_name -eq "mitre-attack").url}else{$($($techniques | Where-Object {$_.external_references.external_id -eq $techniqueID} | Select-Object external_references).external_references | Where-Object -Property external_id -eq $techniqueId).url}
        $subtechniqueID = if($_.x_mitre_is_subtechnique -eq $true){$($_.external_references | Where-Object {$null -ne $_.external_id} | Select-Object -Property external_id).external_id}else{}
        $subtechniqueName = if($_.x_mitre_is_subtechnique -eq $true){$_.name}else{}
        $subtechniqueReference = if($_.x_mitre_is_subtechnique -eq $true){$($_.external_references | Where-Object -property source_name -eq "mitre-attack").url}else{}
        $eventIngestTime = $(Get-Date -AsUTC -Format "o")
        #Create object for Elastic Ingest (multiple sub objects)
        $global:techniquesTableObject += [PSCustomObject]@{
            event = [PSCustomObject]@{
                ingested = $eventIngestTime
            }
            threat = [PSCustomObject]@{
                framework = "MITRE ATT&CK"
                tactic = [PSCustomObject]@{
                    name = $tacticName
                    id = $tacticId.external_references.external_id
                    reference = $tacticId.external_references.url
                }
                technique = [PSCustomObject]@{
                    name = $techniqueName
                    id = $techniqueID
                    reference = $techniqueReference
                    subtechnique = [PSCustomObject]@{
                        name = $subtechniqueName
                        id = $subtechniqueID
                        reference = $subtechniqueReference
                    }
                }
            }
            mitre = [PSCustomObject]@{
                created_at = $_.created
                modified_at = $_.modified
                rule_version = $_.x_mitre_version
            }
        }

        #Create simple object for high level view (out-gridview)
        $global:techniquesTable += [PSCustomObject]@{
            tactic_name = $tacticName
            tactic_id = $tacticId.external_references.external_id
            tactic_reference = $tacticId.external_references.url
            technique_name = $techniqueName
            technique_id =  $techniqueID
            technique_reference = $techniqueReference
            subtechnique_name =  $subtechniqueName
            subtechinique_id = $subtechniqueID
            subtechinique_reference = $subtechniqueReference
            created_at = $_.created
            modified_at = $_.modified
            rule_version = $_.x_mitre_version
        }

    }
}

############################################################################################################## MITRE ATT&CK ##############################################################################################################


function extractTTPsFromRule($ruleDetails) {
    #Get TTPs from Regex hits
    $global:tacticIDMatch = ''
    $global:tacticNameMatch = ''
    $global:techniqueIDMatch = ''
    $global:techniqueNameMatch = ''
    $global:subtechniqueIDMatch = ''
    $global:subtechniqueNameMatch = ''
    $ttpsMatch =  $ruleDetails[0] | Select-String -Pattern $ttp_technique
    if($ttpsMatch){
        $global:tacticIDMatch = if($ttpsMatch.Matches.Groups[1].Value){$ttpsMatch.Matches.Groups[1].Value}elseif($ttpsMatch.Matches.Groups[7].Value){$ttpsMatch.Matches.Groups[7].Value}
        $global:tacticNameMatch = if($ttpsMatch.Matches.Groups[2].Value){$ttpsMatch.Matches.Groups[2].Value}elseif($ttpsMatch.Matches.Groups[8].Value){$ttpsMatch.Matches.Groups[8].Value}
        $global:techniqueIDMatch = if($ttpsMatch.Matches.Groups[3].Value){$ttpsMatch.Matches.Groups[3].Value}elseif($ttpsMatch.Matches.Groups[9].Value){$ttpsMatch.Matches.Groups[9].Value}elseif($ttpsMatch.Matches.Groups[11].Value){$ttpsMatch.Matches.Groups[11].Value}
        $global:techniqueNameMatch = if($ttpsMatch.Matches.Groups[4].Value){$ttpsMatch.Matches.Groups[4].Value}elseif($ttpsMatch.Matches.Groups[10].Value){$ttpsMatch.Matches.Groups[10].Value}elseif($ttpsMatch.Matches.Groups[12].Value){$ttpsMatch.Matches.Groups[12].Value}
        $global:subtechniqueIDMatch = $ttpsMatch.Matches.Groups[5].Value
        $global:subtechniqueNameMatch = $ttpsMatch.Matches.Groups[6].Value
    }

    #Build custom object with all of the needed details
    $global:sysmonEventToMitre += [PSCustomObject]@{
        event_id = $ruleDetails[1] # Example: 1
        event_name = $ruleDetails[2] #Example: Process Create
        sysmon_rule = $ruleDetails[3] #Example: Parent Image
        sysmon_condition = $_.condition
        sysmon_text = $_.'#text'
        tactic_id = $tacticIDMatch
        tactic_name = $tacticNameMatch
        technique_id = $techniqueIDMatch
        technique_name = $techniqueNameMatch
        sub_technique_id = $subtechniqueIDMatch
        sub_technique_name = $subtechniqueNameMatch
        config_file_name = $configFileName
    }
}

$global:sysmonEventToMitre = @()

function extractMitreTechniques($sysmonAndFileName) {
    $sysmon = $sysmonAndFilename[0]
    $configFileName = $sysmonAndFilename[1]
    #Event ID 1: Process creation
    $eventId = "1"
    $ruleType = "ProcessCreate"
    $subRuleType = "ParentImage"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.$ruleType.$subRuleType | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Original FileName"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.OriginalFileName | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType ="Command Line"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.CommandLine | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType ="Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 2: A process changed a file creation time
    $eventId = "2"
    $ruleType = "File Create"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.TargetFilename | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 3: Network connection
    $eventId = "3"
    $ruleType = "Network Connect"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.NetworkConnect.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Destination Port"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.DestinationPort | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 4: Sysmon service state changed - Skipped #TODO

    #Event ID 5: Process terminated
    $eventId = "5"
    $ruleType = "Process Terminate"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessTerminate.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 6: Driver loaded - Skipped no Mitre #TODO

    #Event ID 7: Image loaded
    $eventId = "7"
    $ruleType = "Image Loaded"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.ImageLoaded | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Original FileName"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.OriginalFileName | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.Rule.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Image Loaded"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.Rule.ImageLoaded | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 8: CreateRemoteThread - Skipped No Mitre #TODO

    #Event ID 9: RawAccessRead - Skipped No Mitre #TODO

    #Event ID 10: ProcessAccess
    $eventId = "10"
    $ruleType = "Process Access"
    $subRuleType = "Call Trace"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.$ruleType.$subRuleType | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType ="Granted Access"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.GrantedAccess | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType ="Source Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.SourceImage | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Target Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.Rule.TargetImage | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Granted Access"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.Rule.GrantedAccess | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 11: FileCreate
    $eventId = "11"
    $ruleType = "File Create"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.TargetFilename | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.Image | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 12: RegistryEvent (Object create and delete) + Event ID 13: RegistryEvent (Value Set) + Event ID 14: RegistryEvent (Key and Value Rename)
    $eventId = "12, 13, 14"
    $ruleType = "Registry Event"
    $subRuleType = "Target Object"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.RegistryEvent.TargetObject | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }


    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.RegistryEvent.Rule.TargetObject | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 15:FileCreateStreamHash
    $eventId = "15"
    $ruleType = "File Create Stream Hash"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreateStreamHash.TargetFilename | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 16: ServiceConfigurationChange - Skipped

    #Event ID 17: PipeEvent (Pipe Created) + Event ID 18: PipeEvent (Pipe Connected) - Skipped no Mitre #TODO

    #Event ID 19: WmiEvent (WmiEventFilter activity detected) + Event ID 20: WmiEvent (WmiEventConsumer activity detected) + Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
    $eventId = "19, 20, 21"
    $ruleType = "Wmi Event"
    $subRuleType = "Operation"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.WmiEvent.Operation | Where-Object {$_.name -match "technique"}
    if($eventDetail){ 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name,$eventId,$ruleType,$subRuleType)
        }
    }

    #Event ID 22: DNSEvent (DNS query) - Skipped no Mitre #TODO

    #Event ID 23: FileDelete (A file delete was detected) - Skipped no Mitre #TODO


}

function ingestMitreIntoElastic {
    #Ingest MITRE object by object into Elasticsearch
    $ask = Read-Host "Would you like to ingest into Elasticsearch? (y or n)"
    if($ask -eq "y"){

        $elasticSearchURL = Read-Host "Please enter your Elasticsearch URL. Example : https://localhost:9200"
        Write-Host "What are your credentials user/pass for Elasticsearch to authenticate?"
        $creds = Get-Credential
        $global:techniquesTableObject | ForEach-Object {
            $body = $_ | ConvertTo-Json -Depth 5
            Invoke-RestMethod -URI "$elasticSearchURL/mitre_attck/_doc" -Method Post -Credential $creds -Body $body -AllowUnencryptedAuthentication -ContentType "application/json"
        }
    }else{
        Write-Host "Not ingesting to Elasticsearch, moving along!"
    }
}

#Use the compiled file
if($CompiledConfigPath){
    #Get the Latest Techniques from MITRE
    getLatestTechniques

    #Ask user if they wish to send the MITRE data into Elasticsearch
    ingestMitreIntoElastic

    #Get file name of single xml file
    $xmlFiles = Get-ChildItem $CompiledConfigPath

    #Load single xml file and pass the path name to the function to add the column for what file the TTP was found in.
    Write-Host "Using the file: $xmlFiles for analysis." -ForegroundColor Green
    $sysmon.load($CompiledConfigPath)
    Write-Host "Extracting MITRE ATT&CK Tactics, Techniques, and Subtechniques from your defined SysMon file!"
    extractMitreTechniques $sysmon,$($xmlFiles.Name)
}

#Use the modular files
if($ModularConfigPath){
    #Get the Latest Techniques from MITRE
    getLatestTechniques

    #Ask user if they wish to send the MITRE data into Elasticsearch
    ingestMitreIntoElastic

    #Grab all xml files in the directory of your choosing. This is recursive!
    $xmlFiles = Get-ChildItem $ModularConfigPath -Recurse | Where-Object {
        $_.Name -match "include_" -and $_.Name -match ".xml"
    }
    $arrayCounter = 0
    if($xmlFiles){
            $xmlFiles.FullName | ForEach-Object {
            #Check for valid XML files and let the user know if the file is not valid XML.
            try{
                $sysmonAll.load($_)
            }catch{
                Write-Host "Not a valid XML file detected. Possibly due to commented out text. Check this file out: $($xmlFiles.FullName[$arrayCounter])" -ForegroundColor DarkRed
            }
            extractMitreTechniques $sysmonAll,$_
            $arrayCounter++
        }
    }else{
        Write-Host "No Sysmon config files starting with include_ have been found. Displaying MITRE ATT&CK Windows Only." -ForegroundColor Yellow
    }
}

#Validate Mitre Lookups to ATT&CK
Write-Host "Checking for valid MITRE in Sysmon rule names." -ForegroundColor Blue
$global:sysmonEventToMitre | ForEach-Object {
    #Check for valid Tactic IDs
    #Find multiple Tactics and split accordingly
    if($_.tactic_id -match ","){
        if(($_ | ForEach-Object {$_.tactic_id.split(",") }) | ForEach-Object {$_ -In $global:techniquesTable.tactic_id}){
            #Match Found
            $_ | Add-Member -NotePropertyMembers @{ValidMitreTactic="True"} -Force
        }else{
            #No Match Found - Invalid
            $_ | Add-Member -NotePropertyMembers @{ValidMitreTactic="False"} -Force
        }
    }elseif($_.tactic_id -notmatch ","){
        if($_.tactic_id -In $global:techniquesTable.tactic_id){
            #Match Found
            $_ | Add-Member -NotePropertyMembers @{ValidMitreTactic="True"} -Force
        }else{
            #No Match Found - Invalid
            $_ | Add-Member -NotePropertyMembers @{ValidMitreTactic="False"} -Force
        }
    }else{
        #No Match Found - Invalid
        $_ | Add-Member -NotePropertyMembers @{ValidMitreTactic="False"} -Force
    }
    
    #Check for valid Technique IDs
    if($_.technique_id -in $global:techniquesTable.technique_id){
        #Match Found
        $_ | Add-Member -NotePropertyMembers @{ValidMitreTechnique="True"} -Force
    }elseif($_.technique_id -notin $global:techniquesTable.technique_id){
        #No Match Found - Invalid
        $_ | Add-Member -NotePropertyMembers @{ValidMitreTechnique="False"} -Force
    }

    #Check for valid Subtechnique IDs
    if($_.subtechnique_id -in $global:techniquesTable.subtechnique_id){
        #Match Found
        $_ | Add-Member -NotePropertyMembers @{ValidMitreSubTechnique="True"} -Force
    }elseif($_.subtechnique_id -notin $global:techniquesTable.subtechnique_id){
        #No Match Found - Invalid
        $_ | Add-Member -NotePropertyMembers @{ValidMitreSubTechnique="False"} -Force
    }
}

#Validate MITRE ATT&CK found in Sysmon Config
Write-Host "Checking to see if the MITRE ATT&CK Tactic/Techniques exist in the Sysmon configuration you provided." -ForegroundColor Blue
$global:techniquesTable | ForEach-Object {
    if($_.technique_id -in $global:sysmonEventToMitre.technique_id){
        #Match Found
        $_ | Add-Member -NotePropertyMembers @{FoundInSysmonConfig="True"} -Force
    }else{
        #No Match Found - Invalid
        $_ | Add-Member -NotePropertyMembers @{FoundInSysmonConfig="False"} -Force
    }
}

function exportForMatrix {
    #MITRE ATT&CK Matrix Generator
    #Template to add known techniques to:
    $mitreAttckTemplateObject = @()
    $mitreAttckTemplateObject = [PSCustomObject]@{
        name = "Sysmon-modular"
        versions =  [PSCustomObject]@{
            attack = "8"
            navigator = "4.2"
            layer = "4.1"
        }
        domain = "enterprise-attack"
        description = ""
        filters = [PSCustomObject]@{
            platforms = @("Windows")
        }
        sorting = "0"
        layout = [PSCustomObject]@{
            layout = "side"
            showID = "false"
            showName = "true"
        }
        hideDisabled = "false"
        techniques = @()
        gradient = [PSCustomObject]@{
            colors =  @("#ff6666", "#ffe766", "#8ec843")
            minValue = "0"
            maxValue = "100"
        }
        legendItems = @()
        metadata = @()
        showTacticRowBackground = "false"
        tacticRowBackground = "#dddddd"
        selectTechniquesAcrossTactics = "true"
        selectSubtechniquesWithParent = "false"
    }

    $global:sysmonEventToMitre | Where-Object {$_.ValidMitreTechnique -eq "true"} | ForEach-Object {
        #Iterate through all tactics as each tactic must be in its own object when exporting to the attack tool for visualizing. Deuplicates may exist when rules are found to hit the same technique multiple times.
        if($_.tactic_name){
            Write-Host "Tactic name found! Cleaning up and conforming to ATT&CK naming standard and adding to Attack Navigator file!"
            $splitTactics = $_.tactic_name.Split(", ")
        }else{
            Write-Host "Tactic not found, this is likely because the Sysmon config does not contain that tactic name."
        }
        
        for ($i = 0; $i -lt $splitTactics.count; $i++) {
            $mitreAttckTemplateObject.techniques += New-Object -TypeName PSobject -Property @{
                "techniqueID" = if($_.sub_technique_id){$_.sub_technique_id}else{$_.technique_id}; 
                "tactic" = $splitTactics[$i].ToLower().Replace(" ", "-");
                "color" = "#fd8d3c";
                "comment" = "";
                "enabled" = "true";
                "metadata" = @();
                "showSubtechniques" = "true";
            }
        }
    }

    #Export attack matrix to JSON!
    Write-Host "Exporting MITRE ATT&CK JSON (Sysmon-modular.json) for use in the Attack Navigator found here: https://mitre-attack.github.io/attack-navigator/" -ForegroundColor Blue
    $mitreAttckTemplateObject | ConvertTo-Json -Depth 6 | Out-File "Sysmon-modular.json"

}

$exportForNavigater = Read-Host "Would you like to export all of the MITRE ATT&CK mappings for the Attack Navigator? (y or n)"
if($exportForNavigater -eq "y"){
    #Get latest copy of Mitre ATT&CK Framework
    exportForMatrix
}else{
    Write-Host "Not exporting the JSON file, moving on."
}

#Print out the results!
Write-Host "Printing out tables on screen for analysis. Thanks for using this tool!" -ForegroundColor Green
$global:sysmonEventToMitre | Out-GridView -Title "SysMon Events that map to MITRE"
$global:techniquesTable | Out-GridView -Title "MITRE ATT&CK Table with Tactics, Techniques, and Subtechniques"
