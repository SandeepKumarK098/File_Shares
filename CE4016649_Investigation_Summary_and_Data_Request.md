# CE 4016649 – NILM VLM checkout fails on Win11 24H2 (nimdnsNSP / 32-bit Winsock 11003)

- **Escalation:** [Customer Escalation 4016649](https://dev.azure.com/ni/DevCentral/_workitems/edit/4016649)
- **Case:** Support App Ref 069VU00000yFpffYAC / Request #04570753
- **Customer:** Sven Kröger – BBZ Segeberg (back from vacation end of October 2026)
- **Status of this document:** Investigation summary + data request (2026-10-13)

Contents:

1. [Part A – Summary for the engineer](#part-a--summary-for-the-engineer)
2. [Part B – Message to the customer (via TSE)](#part-b--message-to-the-customer-via-tse)
3. [Part C – Diagnostic script (NI-Diag.ps1)](#part-c--diagnostic-script-ni-diagps1)
4. [Part D – How to analyze the returned data](#part-d--how-to-analyze-the-returned-data)

---

## Part A – Summary for the engineer

### A.1 Key finding

Comparing the customer's `netsh winsock show catalog` dumps from the 2026-09-24 controlled reproduction (before install / after install / after reboot):

| Namespace providers listed | Before NI install | After install, before reboot | After first reboot |
|---|---|---|---|
| 64-bit catalog | 5 Microsoft entries | 5 + nimdnsNSP | 5 + nimdnsNSP (healthy) |
| 32-bit catalog, as seen by 64-bit netsh ("(32)" entries) | 5 Microsoft entries | 5 + nimdnsNSP | **none at all** |
| 32-bit catalog, as seen by 32-bit netsh | 5 Microsoft entries | 5 + nimdnsNSP | **error 11003, section missing** |

- After the first reboot, the **entire 32-bit namespace catalog** is unreadable – including Microsoft's own TCP/IP, NTDS, NLA, Bluetooth and e-mail providers – not just the nimdnsNSP entry.
- The 32-bit **protocol** catalog and the whole 64-bit side are unaffected.
- `nimdnsNSP.dll` files are not deleted or modified: present, validly signed, and loadable in both bitnesses (customer verified).
- Conclusion: the defect is in the registry data under
  `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5` (`Catalog_Entries` = 32-bit catalog).

### A.2 Why every symptom follows from this

- 32-bit `WSAStartup` fails with `WSANO_RECOVERY (11003)` → every 32-bit networking process fails:
  - `SysWOW64\ping.exe` – "Windows Sockets interface could not be initialized"
  - `SysWOW64\nslookup.exe` – "Server: UnKnown / Address: NULL"
  - 32-bit .NET – `Socket.InitializeSockets()` throws "A nonrecoverable database lookup error occurred"
  - `NILicenseManager.exe` (32-bit) – `Dns.GetHostName()` throws; `Core.ServerSendData failed [10096]`; nothing reaches `lmgrd`
  - `NIWebServerConfigurationCmd.exe install defaults` – same exception → MSI 1603
- `WSCUnInstallNameSpace32` (11003), 32-bit `nimdnsNSPTool` (10022) and `netsh winsock reset` cannot repair it – they all must **read** the catalog first.
- 64-bit `NilmCompatibilityServer.exe` still talks to the VLM server – it uses the separate 64-bit catalog.

### A.3 Working theory (to be proven with the requested data)

During shutdown or early boot after the CDS install, something modifies the 32-bit namespace catalog **directly in the registry** (not via the Winsock API) – e.g. removes the nimdnsNSP entry without updating the entry count – leaving the catalog inconsistent. Windows then rejects the whole 32-bit catalog.

Candidate actors (most to least likely):

1. Security / EDR / Defender remediation of a "suspicious" Winsock namespace provider (Winsock providers are a known persistence technique).
2. Image / write-filter / reset tooling (UWF, Deep Freeze-like, school management agents) persisting only part of the registry.
3. Windows build-specific behavior at boot (LTSC 2024, build 26100.8875).
4. An NI component on first boot (32-bit `nimDNSResponder` service, `niSvcLoc`, reboot-time file replacement).

Supporting signal: NI could **not** reproduce on a clean Win11 24H2 Hyper-V VM (Cristian, Sandeep), so the trigger is NI's NSP registration, but the corrupting actor is likely environment-specific.

> Note: the CDS reboot itself is not the cause – it is the moment the damage happens. The 32-bit mDNS MSI always requests a reboot, which is why the failure always appears "after the first reboot".

### A.4 Corrections to the earlier escalation summary

| Earlier claim | What the evidence says |
|---|---|
| "Win11 24H2 LSA enforcement breaks the 32-bit catalog entry" | LSASS is 64-bit and loads only the 64-bit NSP, which stays healthy. The 14.3.3 repro showed **no** LSA warning. LSA is a red herring. |
| "Only the 32-bit nimdnsNSP entry breaks" | The **entire** 32-bit namespace catalog is unreadable, including Microsoft entries. |
| Interim workaround: IP address in `servers.ini` | Won't work: socket initialization itself fails. Customer already tested IP (first email) without success. |
| "NILM fails resolving the VLM hostname" | NILM log shows `Dns.GetHostName()` (local name) and every socket call failing – process-wide Winsock failure. |
| Fix = install/repair System Configuration 2025 Q2+ | The 14.3.3 repro already had `ni-mdnsresponder 25.8.0` / `nimdnsNSP 216.0.2f0`. That fix targeted the LSA warning, a different issue. |
| STS `WimgUtility.cs` deletes `nimdnsNSP.dll` | Ruled out (Selva); DLL is present and loads. |
| Customer: "`nimdnsResponder.dll` missing from mDNS Responder folder" | Expected location is `System32` / `SysWOW64`, not the mDNS Responder folder. |

### A.5 Installer facts (from source)

Source: ADO repo `Users/sagrahar-exp`, path `/syscfg/src/system_config/syscfg_runtimed/mDNSResponderi` (WiX + nipkg instructions). Service / NSP / NSPTool source is still in Perforce (`mDNSResponderd`).

- Each MSI (`mDNSResponder.msi` x86, `mDNSResponder_W64.msi` x64) registers its NSP via a deferred custom action:
  `nimdnsNSPTool.exe -install "nimdnsNSP" "981DF75B-898E-4c0c-B01C-5F181F817889" "<path>\nimdnsNSP.dll"`
  → official `WSCInstallNameSpace` API; the MSIs do not write the catalog registry keys directly.
- Register/unregister custom actions use `Return="ignore"` – registration failures are silent.
- The 32-bit MSI has an unconditional `ScheduleReboot` → always returns 3010 (seen in NIPM log; x64 MSI returns 0).
- The 32-bit MSI installs the `nimDNSResponder` service (32-bit exe, auto-start, depends on `niSvcLoc`).

### A.6 Engineer action items

1. **Try out the diagnostic procedure (Part B + Part C) on an internal VM first** – confirm the script runs cleanly on Win11 24H2 / LTSC 2024 and the Procmon steps are accurate, before the TSE sends it.
2. **Matching internal repro** – Windows Enterprise LTSC 2024, build 26100.8875, domain-joined, CDS 14.3.3 offline ISO **only** (no LabVIEW first), one normal reboot. If possible, add a common EDR / Defender ASR configuration.
3. **Review NI service / NSP source** in Perforce (`mDNSResponderd`) for any code touching the Winsock catalog on startup (e.g. self-registration, `WSCInstallNameSpace*`, `DllRegisterServer`).
4. **Draft a manual 32-bit catalog repair** and validate it on a failed VM (fix entry count vs subkeys / restore healthy export). Answers TSE question "Is there a procedure to repair the 32-bit catalog?".
5. **Analyze returned customer data** per Part D.
6. **Later (NILM diagnosability):** detect 11003 during socket initialization and log an actionable message pointing to a KB article.

### A.7 Suggested answers to the open TSE questions (current state)

| TSE question | Current answer |
|---|---|
| Known issue with ni-mdnsresponder 25.x on Win11 24H2? | Not reproduced internally on clean Win11 24H2. NI's NSP registration is the trigger; the component that corrupts the catalog at reboot is not yet identified. |
| Supported repair procedure for the 32-bit catalog? | `netsh winsock reset` cannot repair it. A registry-level repair is being prepared/validated. |
| Why does SysConfig repair not reinstall ni-mdnsresponder? | Pending – not the root cause; revisit after catalog root cause. |
| Way to install CDS 14.3.3 without nimdnsNSP? | No supported option today. |
| Hold CDS 14.3.1/14.3.3 on Win11 24H2? | Not indicated by current evidence (not reproducible on clean 24H2); depends on root cause. |

---

## Part B – Message to the customer (via TSE)

> Dear Mr. Kröger,
>
> Thank you again for the very detailed reproduction – your catalog exports were key to the analysis.
>
> **What we found so far:** After the first reboot, the Windows 32-bit Winsock *name-service* catalog in the registry can no longer be read – all of its entries, not only the NI mDNS entry. That is why every 32-bit program fails to start networking while 64-bit programs still work. The NI mDNS files themselves are intact. Something changes this registry data during the reboot, and we now need to see exactly *what* changes and *which process* changes it.
>
> When you are back, could you please collect the following on your **preserved VM checkpoint "after CDS 14.3.3 installation, before first reboot"**? No new reproduction from scratch is needed.
>
> **Preparation**
>
> 1. Restore the checkpoint *after installation / before reboot* and log in as local administrator.
> 2. Download Process Monitor from Microsoft: <https://learn.microsoft.com/sysinternals/downloads/procmon> and extract it to `C:\NI-Diag\`.
> 3. Save the attached script as `C:\NI-Diag\NI-Diag.ps1`.
>
> **Before reboot**
>
> 4. Open an **administrator** PowerShell and run:
>    ```
>    powershell -ExecutionPolicy Bypass -File C:\NI-Diag\NI-Diag.ps1 -Stage Before
>    ```
> 5. Start `C:\NI-Diag\Procmon64.exe` as administrator → **Options → Enable Boot Logging** → OK (leave "Generate thread profiling events" unchecked) → close Process Monitor.
>
> **Reboot**
>
> 6. Restart Windows normally. Please do not start any NI software.
> 7. Log in and confirm the failure as before, e.g. `C:\Windows\SysWOW64\ping.exe Lazarus`.
>
> **After reboot**
>
> 8. Start `Procmon64.exe` as administrator again. When asked to save the boot log, choose **Yes** and save it as `C:\NI-Diag\bootlog.pml`.
> 9. After the log has loaded: **Filter → Filter…** → `Path` `contains` `WinSock2` → **Include** → **Add** → **OK**.
>    Then **File → Save… → "Events displayed using current filter"**, format **PML**, file `C:\NI-Diag\bootlog_winsock.pml`.
> 10. In the administrator PowerShell, run:
>     ```
>     powershell -ExecutionPolicy Bypass -File C:\NI-Diag\NI-Diag.ps1 -Stage After
>     ```
>
> **Please send us**
>
> - `C:\NI-Diag\NI-Diag-Before.zip` and `C:\NI-Diag\NI-Diag-After.zip`
> - `C:\NI-Diag\bootlog_winsock.pml` (please keep the full `bootlog.pml` in case we need it)
> - Short answers about the test image:
>   - a) Which antivirus / endpoint security product is installed (including Defender ASR rules)?
>   - b) Is any write filter or reset software used (e.g. UWF, Deep Freeze or similar)?
>   - c) Are any software/device management agents or domain group policies applied to this VM?
>
> **Optional quick test (separate run):** restore the same *before-reboot* checkpoint again, run `sc config nimDNSResponder start= disabled` in an administrator command prompt, restart, and tell us whether `C:\Windows\SysWOW64\ping.exe Lazarus` still fails.
>
> Thank you very much for your support.

---

## Part C – Diagnostic script (NI-Diag.ps1)

Run from an **elevated 64-bit** PowerShell with `-Stage Before` (before reboot) and `-Stage After` (after reboot).

```powershell
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
```

| Output | Purpose |
|---|---|
| `WinSock2_Parameters.reg` | Full protocol + namespace catalogs – diff Before vs After to see exactly what changed |
| `PendingFileRename.txt`, `RunOnce64/32.txt` | Anything scheduled to run / replace files at reboot |
| `Catalog_Entries_ACL.txt` | Detects permission changes on the 32-bit namespace catalog key |
| `NIServices.txt` | State of `nimDNSResponder` / `niSvcLoc` |
| `netsh_32bit.txt`, `netsh_64bit.txt` | Same view as the customer's earlier dumps, for consistency |
| `*.evtx` (After only) | System / Application / CodeIntegrity / Defender events around the reboot |
| `SecurityProducts.txt` (After only) | Registered antivirus / security products |

> The script has not been executed yet – validate it on an internal VM before sending (Action item A.6-1).

---

## Part D – How to analyze the returned data

### D.1 Registry diff (`Before\WinSock2_Parameters.reg` vs `After\WinSock2_Parameters.reg`)

Focus on `...\Parameters\NameSpace_Catalog5`:

- Does `Num_Catalog_Entries` still match the number of subkeys under `Catalog_Entries`?
- Is a numbered subkey missing / is there a gap in numbering?
- Is any value malformed or empty (`LibraryPath`, `DisplayString`, `ProviderId`, `SupportedNameSpace`, `Enabled`, `Version`)?
- Did `Catalog_Entries64` change at all (expected: no)?
- Compare `Catalog_Entries_ACL.txt` Before vs After for permission changes.

### D.2 Process Monitor boot log (`bootlog_winsock.pml`)

- Filter Operation is `RegDeleteKey`, `RegDeleteValue`, `RegSetValue`, `RegCreateKey` and Path contains `NameSpace_Catalog5`.
- Record: **process name, PID, user, command line, time, and call stack** (Event Properties → Stack).
- Check whether the write happens early in boot (services start) or later (logon / agents).
- **If there is no write in the boot log but the After export differs**, the change happened during **shutdown** (boot logging does not cover shutdown) → request a second capture that covers shutdown.

### D.3 Decision table

| Process Monitor shows writer = | Likely root cause | Next step |
|---|---|---|
| AV / EDR / Defender process (`MsMpEng.exe`, vendor agent) | Security remediation of NSP | Check product logs; exclusion / allow-list for `nimdnsNSP.dll`; consider engaging vendor; KB for customers |
| Write-filter / reset / management agent | Partial registry persistence | Customer-side configuration (commit/exclusion); KB |
| `svchost.exe` / Windows component | Windows behavior on this build | Engage Microsoft; check build-specific changes |
| `nimdnsResponder.exe` / `nimdnsNSPTool.exe` / other NI process | NI defect | File bug against NI mDNS Responder / System Configuration team |
| Nothing in boot log | Change at shutdown | Second capture covering shutdown |

### D.4 Optional quick test result

- 32-bit networking **works** after reboot with `nimDNSResponder` disabled → NI service involved at startup.
- Still **fails** → NI service not involved; focus on other actors.
