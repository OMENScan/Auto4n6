#################################################################################
# This script forms the bridge between AChoir(X) and Velociraptor               #
#  AChoir(X) uses CSV files, and Velociraptor uses JSON. This script converts   #
#  and reformats Velociraptor JSON files into CSV Files so that TriageReport    #
#  can read them.  For this to work, please ensure that the JSON files are      #
#  reformatted into the CSV columns that TriageReport expects.  This can be     #
#  done using the following general syntax:                                     #
#                                                                               #
#   Get-Content <Input JSON File Name> | ConvertFrom-Json |                     #
#   Select-Object <colname>, <colname>, <etc..> | Export-Csv <output CSV File>  #
#   -NoTypeInformation                                                          #
#                                                                               #
#################################################################################
Write-Host "[+] This Powershell script Converts the Velociraptor JSON Files to AChoirX CSV Format."
#$VeloDir = Read-Host -Prompt 'Which Directory should we Convert: '
$VeloDir = $args[0]
Write-Host "[+] Converting AutoRuns..."
New-Item -ItemType Directory -Force -Path $Velodir\Triage\Arn | out-null
Get-Content $Velodir\Triage\Windows.Sysinternals.Autoruns.json | ConvertFrom-Json | Export-Csv $Velodir\Triage\Arn\Autorun.dat -NoTypeInformation
Write-Host "[+] Converting Chrome History..."
New-Item -ItemType Directory -Force -Path $Velodir\Triage\Brw | out-null
Get-Content $Velodir\Triage\Windows.Applications.Chrome.History.json | ConvertFrom-Json | Select-Object visited_url, title, last_visit_time, visit_count, Mtime, typed_count, FullPath, User | Export-Csv $Velodir\Triage\Brw\BrowseHist.csv -NoTypeInformation
Write-Host "[+] Converting Network Connections..."
New-Item -ItemType Directory -Force -Path $Velodir\Triage\Sys | out-null
Get-Content $Velodir\Triage\Windows.Network.NetstatEnriched\Netstat.json | ConvertFrom-Json | Select-Object Name, Pid, Type, Laddr.Port, Family, Laddr.IP, Raddr.Port, Ppid, Raddr.IP, Username, Status, CommandLine | Export-Csv $Velodir\Triage\Sys\Cports.csv -NoTypeInformation
Write-Host "[+] Converting DNS Cache..."
Get-Content $Velodir\Triage\Windows.System.DNSCache.json | ConvertFrom-Json | Export-Csv $Velodir\Triage\Sys\DNSCache.csv -NoTypeInformation
Write-Host "[+] Converting Logon Data..."
Get-Content $Velodir\Triage\Custom.Windows.Sysinternals.PSLoggedOn.json | ConvertFrom-Json | Export-Csv $Velodir\Triage\Sys\Logon.dat -NoTypeInformation
Write-Host "[+] Converting PSInfo Data..."
Get-Content $Velodir\Triage\Custom.Windows.Sysinternals.PSInfo.json | ConvertFrom-Json | Export-Csv $Velodir\Triage\Info.dat -NoTypeInformation
Write-Host "[+] Conversion Completed...  Exiting..."
