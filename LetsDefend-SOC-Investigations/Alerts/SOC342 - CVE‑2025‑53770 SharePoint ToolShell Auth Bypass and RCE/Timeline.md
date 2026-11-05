# SOC342 - Investigation Timeline

**Incident:** CVE-2025-53770 SharePoint ToolShell Authentication Bypass and Remote Code Execution  
**Hostname:** `SharePoint01`  
**Source IP:** `107.191.58.76`  
**Destination IP:** `172.16.20.17`  
**Date:** 22 July 2025

## Timeline

| Time | Activity | Evidence | Significance |
|---|---|---|---|
| 13:07:10 | Suspicious SharePoint HTTP request | HTTP `POST` to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx`. Source IP: `107.191.58.76`. Destination IP: `172.16.20.17`. Content-Length: `7699`. Referer: `/_layouts/SignOut.aspx`. | The request was flagged as suspicious and indicative of possible CVE-2025-53770 exploitation. This alert alone does not prove successful exploitation. |
| 13:07:24 | Hidden PowerShell execution | PowerShell launched with `-nop -w hidden -e` and a Base64-encoded payload. Decoded content used .NET reflection to access `System.Web.Configuration.MachineKeySection` and retrieve `ValidationKey`, `DecryptionKey`, and `CompatibilityMode`. | Indicates suspicious command execution and attempted access to ASP.NET machine-key configuration. |
| 13:07:27 | C# compilation command | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs` | Indicates an attempt to compile C# source code into an executable payload. Successful compilation or execution is not independently confirmed. |
| 13:07:29 | ASPX file creation | `cmd.exe` used to write `spinstall0.aspx` to `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx`. The recorded content referenced `http://107.191.58.76/payload.exe`. | Confirms creation of a suspicious ASPX file in the SharePoint layouts directory. The file's subsequent execution and the remote executable's retrieval are not confirmed. |
| 13:07:34 | Further PowerShell execution | `powershell.exe -Command "[System.Web.Configuration.MachineKeySection]::GetApplicationConfig()"` | Further supports suspicious access to ASP.NET machine-key configuration. |

## Event Correlation

The endpoint activity occurred within seconds of the suspicious SharePoint request.

The sequence of events was:

1. A suspicious HTTP POST request targeted the SharePoint ToolPane endpoint.
2. Hidden PowerShell executed shortly afterward.
3. The PowerShell payload accessed ASP.NET machine-key configuration.
4. A C# compiler command attempted to generate an executable.
5. A suspicious ASPX file was created in the SharePoint layouts directory.
6. The ASPX content referenced an executable hosted at the attacker's source IP.

The close timing and relationship between the web request and endpoint commands strongly support that these activities were connected.

## Final Classification

**Classification: True Positive**

The investigation confirmed suspicious endpoint command execution and creation of the `spinstall0.aspx` file following the suspicious SharePoint request.

However, the available evidence does not independently confirm:

- Successful execution of `payload.exe`.
- Successful download of the remote executable.
- Execution of `spinstall0.aspx` as a web shell.
- The full extent of compromise or data exposure.

## Recommended Follow-up

- Inspect `spinstall0.aspx` and preserve a copy for analysis.
- Check whether `payload.cs` and `payload.exe` exist and calculate their hashes.
- Review network logs for connections to `107.191.58.76`, especially requests for `/payload.exe`.
- Investigate whether the suspicious ASPX file was accessed after creation.
- Assess possible exposure of ASP.NET machine-key values and rotate affected secrets if exposure is confirmed.
- Check for additional suspicious files, processes, and web requests on the SharePoint server.

---

*This timeline records the activity observed during the investigation. It distinguishes confirmed actions from activity that still requires verification.*