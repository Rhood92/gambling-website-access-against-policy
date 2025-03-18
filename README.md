# Threat Event (Unauthorized Gambling Website Access & History Deletion)  
**John Doe Accessing Gambling Sites Despite Prior Warnings & Deleting Browser History**  

## Reason for the Hunt  
John Doe aka labuserich has been previously warned about accessing gambling websites such as FanDuel and DraftKings during work hours. His manager suspects that he is still visiting these sites and actively deleting his browser history to cover his tracks. The security team has been tasked with conducting an investigation to confirm whether John is violating company policy.  

---


## Steps the "Bad Actor" Took to Create Logs and IoCs  

1. **Access Gambling Websites on Work Computer:**  
   - John visits gambling websites like `fanduel.com` and `draftkings.com` before the Sunday NFL games.  
   - He places sports bets and enters parlays while at work.  

2. **Deletes Browser History to Cover Tracks:**  
   - After placing his bets, John manually deletes his browsing history from Firefox.  
   - Alternatively, he uses private/incognito mode to prevent history from being stored.  

3. **Attempts to Bypass Security Controls:**  
   - John may use VPN services or proxy websites to hide his traffic.  
   - He may clear DNS cache using the following command in CMD to remove traces:  
     ```cmd
     ipconfig /flushdns
     ```  

4. **Continued Policy Violations:**  
   - Despite prior warnings, John continues this behavior, making it necessary for security to investigate further. 

---

## Tables Used to Detect IoCs  


| **Parameter**        | **Description** |
|----------------------|----------------|
| **Name**            | DeviceNetworkEvents |
| **Info**            | [Microsoft Defender - Network Events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**         | Used to detect network traffic to gambling sites such as FanDuel and DraftKings. |


| **Parameter**        | **Description** |
|----------------------|----------------|
| **Name**            | DeviceProcessEvents |
| **Info**            | [Microsoft Defender - Process Events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**         | Detects incognito mode usage or command-line clearing of DNS cache. |


| **Parameter**        | **Description** |
|----------------------|----------------|
| **Name**            | DeviceFileEvents |
| **Info**            | [Microsoft Defender - File Events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**         | Detects browser history deletion and other suspicious file modifications. |
---

## Related Queries  

```kql
// Detect browsing activity for fanduel.com & draftkings.com using Firefox
DeviceNetworkEvents
| where RemoteUrl has_any ("fanduel.com", "draftkings.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
| order by Timestamp desc 

// Detect if user is attempting to clear DNS cache
DeviceProcessEvents
|where DeviceName == "rich-mde-test"
| where ProcessCommandLine contains " /flushdns"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc 


// Detect if user has deleted browsing history in Firefox, yielded no results!!
DeviceFileEvents
| where DeviceName == "rich-mde-test"
| where FolderPath has "Mozilla\\Firefox\\Profiles"
| where FileName has "places.sqlite"
| where ActionType in ("FileDeleted", "FileModified")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath

//Option #2: Doesn't pinpoint the "deleted browsing history" in Firefox, but it does show that showing was deleted within the browser!!
DeviceFileEvents
| where DeviceName == "rich-mde-test"
| where FolderPath contains "firefox"
| where ActionType in ("FileDeleted", "FileModified")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath
| order by Timestamp desc 

// Detect Firefox Private Browsing (Incognito) Mode Usage, however, nothing queried for this incident!!
DeviceProcessEvents
| where DeviceName == "rich-mde-test"
| where ProcessCommandLine has "firefox.exe -private"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Tried to query private browsing, but no results, however, I can still see that the event is logged even though I viewed it in Private
DeviceProcessEvents
|where DeviceName == "rich-mde-test"
| where ProcessCommandLine has "firefox.exe"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
| order by Timestamp desc 
```

---

## Created By:
- **Author Name**: Richard Hood Jr. 
- **Author Contact**: https://www.linkedin.com/in/richard-hood-jr
- **Date**: March 16, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  16, 2025`  | `Richard Hood Jr.`   
