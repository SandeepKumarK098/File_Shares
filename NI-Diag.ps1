param([Parameter(Mandatory)][ValidateSet('Before','After')][string]$Stage)

$out = "C:\NI-Diag\$Stage"
New-Item -ItemType Directory -Force $out | Out-Null
$wsKey = 'HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'

reg export $wsKey "$out\WinSock2_Parameters.reg" /y | Out-Null
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' /v PendingFileRenameOperations 2>&1 | Out-File "$out\PendingFileRename.txt"
reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' /s 2>&1 | Out-File "$out\RunOnce64.txt"
reg query 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' /s 2>&1 | Out-File "$out\RunOnce32.txt"
Get-Acl "Registry::$wsKey\NameSpace_Catalog5\Catalog_Entries" 2>&1 | Format-List | Out-File "$out\Catalog_Entries_ACL.txt"
Get-Service nimDNSResponder, niSvcLoc -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize | Out-File "$out\NIServices.txt"
& "$env:WINDIR\SysWOW64\netsh.exe" winsock show catalog 2>&1 | Out-File "$out\netsh_32bit.txt"
& "$env:WINDIR\System32\netsh.exe" winsock show catalog 2>&1 | Out-File "$out\netsh_64bit.txt"

if ($Stage -eq 'After') {
    foreach ($log in 'System', 'Application', 'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-Windows Defender/Operational') {
        wevtutil epl $log "$out\$($log -replace '[/ ]', '_').evtx" /ow:true 2>&1 | Out-Null
    }
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState | Out-File "$out\SecurityProducts.txt"
}

Compress-Archive -Path $out -DestinationPath "C:\NI-Diag\NI-Diag-$Stage.zip" -Force
Write-Host "Done: C:\NI-Diag\NI-Diag-$Stage.zip"
