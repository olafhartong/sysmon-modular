# Generate-Sysmon-config.ps1
#
# This will move the existing sysmonconfig.xml to a backup version and generate the new configuration
#
# Note!
# The following error is expected, since the sysmonconfig.xml is empty at the time of checking by the script
# Merge-SysmonXMLConfiguration : The schema version of C:\sysmon-modular\sysmonconfig.xml () does not match that of the reference configuration: C:\sysmon-modular\baseconfig.xml (4.10) At line:1 
#

## Import "PSSysmonTools"
## Import-Module .\PSSysmonTools.psm1

$now=Get-Date -format "dd-MMM-yyyy-HH-mm"

If((Test-Path .\sysmonconfig.xml)) {
  Write-Host "Existing sysmonconfig found, backing up."
  Move-Item .\sysmonconfig.xml -Destination sysmonconfig-$now.xml -Force
} Else {
  Write-Host "No config found."
}

## Filter Output and Backup Files
#sysmonconfig-16-Nov-2018-09-21.xml
#sysmonconfig-\d{2}-\w{3}-\d{4}-\d{2}-\d{2}.xml
#sysmonconfig.xml

Write-Host "Generating new configuration..."
Get-ChildItem -Path . -Filter *.xml -Recurse -ErrorAction SilentlyContinue | Where {$_.Name -NotMatch "sysmonconfig(?:-\d{2}-\w{3}-\d{4}-\d{2}-\d{2})?.xml"} | Merge-SysmonXMLConfiguration -ReferencePolicyPath .\baseconfig.xml | Out-File sysmonconfig.xml -Encoding UTF8 