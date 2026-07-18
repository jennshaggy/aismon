# Home Lab Demonstration

This workflow validates `aismon` against live Windows Sysmon Event ID 1 telemetry and sends the corrected JSON result to Splunk.

Use a test endpoint and a deliberately fake value. Do not place a live credential in a process command line.

## Components

- Windows 11 test endpoint
- Microsoft Sysmon
- macOS or Linux analysis host with `aismon`
- Splunk Enterprise

## 1. Install Sysmon

Open PowerShell as Administrator on the Windows endpoint:

```powershell
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
cd $env:TEMP\Sysmon
.\Sysmon64.exe -accepteula -i
```

Verify the service and recent process-creation events:

```powershell
Get-Service Sysmon64
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 3 | Select-Object TimeCreated, Id
```

## 2. Generate safe test activity

The following command only echoes text. It does not contact the listed API:

```powershell
cmd.exe /c "echo OPENAI_API_KEY=sk-demo-00000000000000000000 https://api.openai.com"
```

The fake value tests output redaction. The endpoint reference tests rule `AI-025`.

## 3. Export Event ID 1 XML

```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" /rd:true /f:xml /c:25 > C:\Users\Public\aismon-lab.xml
```

Move the XML to the analysis host through an authenticated channel. Keep the raw telemetry outside the Git repository.

Remove any temporary share or transfer copy after confirming receipt.

## 4. Normalize the export

A PowerShell redirection may create UTF-16LE output. `wevtutil` can also return consecutive `Event` elements without one enclosing root.

Check the byte-order mark:

```bash
xxd -l 32 /path/to/aismon-lab.xml
```

An initial `fffe` identifies UTF-16LE. Convert the file to UTF-8 and add one `Events` root:

```bash
{ printf '<Events>'; iconv -f UTF-16 -t UTF-8 /path/to/aismon-lab.xml; printf '</Events>\n'; } > /path/to/aismon-lab-wrapped.xml
```

## 5. Run `aismon`

```bash
cd /path/to/aismon
source .venv/bin/activate
python parser.py /path/to/aismon-lab-wrapped.xml --detect-only
```

Expected detection metadata for the test endpoint reference:

```json
{
  "rule_id": "AI-025",
  "name": "AI Vendor API Reference",
  "severity": "low",
  "category": "ai_api_activity",
  "tags": [
    "api-reference",
    "ai-vendor"
  ]
}
```

The fake credential-like value should appear as `[REDACTED]` in the output command line.

Save and validate the complete result:

```bash
python parser.py /path/to/aismon-lab-wrapped.xml --detect-only > /path/to/aismon-lab-detection.json
python -m json.tool /path/to/aismon-lab-detection.json
```

## 6. Upload to Splunk

In Splunk Enterprise:

1. Select **Add Data**.
2. Select **Upload** and choose `aismon-lab-detection.json`.
3. Use source type `_json`.
4. Set the host field to the Windows endpoint hostname.
5. Select a dedicated `aismon` index.
6. Review the field preview, then submit the event.

## 7. Search the detection

```spl
index=aismon
| spath path=detections{}.rule_id output=rule_id
| spath path=detections{}.name output=detection_name
| spath path=detections{}.severity output=severity
| spath path=detections{}.category output=category
| table _time host User Image CommandLine rule_id detection_name severity category
```

A complete result should show:

- Endpoint hostname
- Windows user
- Process image
- Redacted command line
- Rule ID
- Detection name
- Severity
- Category

## Scope

This is a manual validation workflow. The current version does not collect live endpoint events, parse binary `.evtx` files, or send data to Splunk automatically.
