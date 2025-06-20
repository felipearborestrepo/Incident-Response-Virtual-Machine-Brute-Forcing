# 🔐 Azure Sentinel: Brute Force Detection & Incident Response

This project simulates a brute force attack detection on an Azure VM using Microsoft Sentinel, Microsoft Defender for Endpoint (MDE), and Azure Log Analytics. It follows the **NIST 800-61 Incident Response Lifecycle** and maps activity to **MITRE ATT&CK** techniques.

![ChatGPT Image Jun 20, 2025, 12_19_41 AM](https://github.com/user-attachments/assets/eedddaf2-c01a-484b-8499-0dac68a7c8ce)

---

## 📘 Overview

Remote attackers attempting to log in to Azure VMs generate logs in `DeviceLogonEvents`. These logs are ingested into Microsoft Sentinel, where we set up a scheduled query rule to detect brute force activity and respond appropriately.

![image](https://github.com/user-attachments/assets/0b6e3f21-4a62-4e51-92b6-74df5650f90e)

---

## 🔍 Step 1: Create Analytics Rule
![Screenshot 2025-06-19 223844](https://github.com/user-attachments/assets/32ca42c1-eba8-4b8b-8fba-217f588863b0)

### 🛠️ Rule Configuration

- **Type:** Scheduled Query Rule  
- **Frequency:** Every 5 hours  
- **Lookup Time:** Last 5 hours
- 
- **Entity Mappings:**
  - Host → `DeviceName`
  - IP → `RemoteIP`
![Screenshot 2025-06-19 225354](https://github.com/user-attachments/assets/b77307cd-b4c2-4f50-b208-d98a58c265ad)
  - Stop Running Query for 24
![Screenshot 2025-06-19 225526](https://github.com/user-attachments/assets/1080a132-054d-4e89-9030-cc79a4e60c7a)
![Screenshot 2025-06-19 225504](https://github.com/user-attachments/assets/7390caa2-d459-4694-aedc-047fdfbbe20e)
![Screenshot 2025-06-19 225526](https://github.com/user-attachments/assets/08377c0b-2286-4114-aad8-006b5cc6725d)

- **MITRE ATT&CK Techniques:**
  - T1110.001 – Password Guessing  
  - T1110.002 – Password Cracking  
  - T1087.001 – Account Discovery (Local)

![Screenshot 2025-06-19 225131](https://github.com/user-attachments/assets/226502a1-7013-4818-aae9-c71381067772)

![Screenshot 2025-06-19 225158](https://github.com/user-attachments/assets/572fd467-0d47-43ff-8f6d-d86f0162f54a)

### 📌 KQL Query

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by DeviceName, RemoteIP, ActionType
| where NumberOfFailures >= 50
```
![Screenshot 2025-06-20 001438](https://github.com/user-attachments/assets/e150f4fd-fdd3-48aa-a0cf-19accbbfa53e)

![Screenshot 2025-06-19 225330](https://github.com/user-attachments/assets/47361ce2-3860-4ad3-afd6-51aac55b0690)

- This screenshot shows the Incident Settings tab of the Microsoft Sentinel Analytics Rule Wizard, where alert grouping is configured.
- This setting groups multiple triggered alerts from the same analytics rule into a single incident to reduce noise and alert fatigue in the SOC.
- By grouping alerts, SOC analysts can investigate one consolidated incident instead of dozens of redundant ones — improving efficiency, visibility, and triage speed.

![Screenshot 2025-06-19 225559](https://github.com/user-attachments/assets/b4dca3a6-5015-4aac-91a0-27189651012d)

**Analytics Rule Created**

![Screenshot 2025-06-19 225614](https://github.com/user-attachments/assets/7db348d5-b269-40ed-b593-836f93489631)

---

## ⚠️ Step 2: Trigger Alert and Assign the Incident

- Simulate failed logins manually if needed  
- Wait for Sentinel to detect the behavior  
- Assign the incident to yourself and activate it

![Screenshot 2025-06-19 230155](https://github.com/user-attachments/assets/d7b23bc7-ff3f-4049-8807-142fee62d3a9)
![Screenshot 2025-06-19 230205](https://github.com/user-attachments/assets/2b7705e8-12d1-40f4-aed1-8c982bfda249)

---

## ⚙️ Step 3: Review Rule Details

Review the rule details and confirm the configuration matches your detection goals. 

Work your incident to completion and close it out, in accordance with the **NIST 800-61**: Incident Response Lifecycle

- Preparation
- Document roles, responsibilities, and procedures.
- Ensure tools, systems, and training are in place.
![incident-response-lifecycle](https://github.com/user-attachments/assets/bcd1ec3a-4efd-4f45-9629-4684e23aec0f)

---

## 🔎 Step 4: Detection & Analysis (NIST Phase 2)

### 🧠 Actions

- Use **Investigation Graph** in Sentinel  
- Analyze failed login attempts, sources, and affected VMs  
- Confirm whether IPs repeatedly failed login attempts on one or more hosts

![Screenshot 2025-06-19 230716](https://github.com/user-attachments/assets/d7280117-f0c9-4c5e-9aa1-a1df6a6ceeb4)

- Analyzing failed login attempts, sources, and affected VMs
- **Confirmed that the IPs repeatedly failed login attempts**
```kql

DeviceLogonEvents
| where RemoteIP in ("81.230.146.160", "62.139.199.159", "62.139.199.159")
| where ActionType != "LogonFailed"

```
![Screenshot 2025-06-19 231747](https://github.com/user-attachments/assets/a6ce3f25-636f-4897-ae90-5cb86ad1486e)

---

## 🛡️ Step 5: Containment & Eradication (NIST Phase 3)

### 🔐 Defender for Endpoint Actions

- **Isolate the affected VM**

![Screenshot 2025-06-19 230936](https://github.com/user-attachments/assets/c0fd24a2-c5f6-4071-ac7c-43584f234854)

- **Run an Antivirus Scan**

![Screenshot 2025-06-19 231203](https://github.com/user-attachments/assets/b86038d1-b7ac-4db4-b50a-f0b02d55c7b5)


---

## 🔍 Step 6: Verification – Were Logins Successful?

Check to see if any brute force IPs successfully logged in.

### 📌 Query

```kql
DeviceLogonEvents
| where RemoteIP in ("81.230.146.160", "62.139.199.159")
| where ActionType == "LogonSuccess"
```

### 🔍 Result

✅ No successful logins were observed.

![image](https://github.com/user-attachments/assets/0fc34be7-0848-4497-ac29-5b30800a187a)

---

## 🌐 Step 7: Lock Down NSG Rules (Recovery Phase)

### ⚠️ Observation

The NSG contained a rule named `DANGER_AllowAnyAny` that allowed open RDP access.

### ✅ Action

- Locked down the NSG to allow only access from specific IPs
- Proposed company-wide **Azure Policy** to prevent open RDP

![Screenshot 2025-06-19 232217](https://github.com/user-attachments/assets/55cbb56f-5d06-4674-bdab-6687a7335cfd)

---

## 🧠 Step 8: Post-Incident Actions & Lessons Learned

### 📘 Lessons

- **NSGs must default to least privilege**  
- **Defender isolation** is essential for fast containment  
- **Scheduled KQL queries** allow proactive brute force detection  
- **Entity mappings** help visualize threat relationships

---

## ✅ Step 9: Incident Closure

- **Classification:** True Positive – Suspicious Activity  
- **Actions Taken:** VM isolated, AV scan completed, NSG updated  
- **Status:** Incident closed with documentation and mitigation completed

![Screenshot 2025-06-19 232630](https://github.com/user-attachments/assets/c3025fb0-7fa9-4cbb-9d4e-0d91ba997552)
![Screenshot 2025-06-19 232906](https://github.com/user-attachments/assets/eb9a3731-9cc3-456a-bea1-7040fe893262)

---

## 📊 Final Summary

| Phase        | Action Taken                                          |
|--------------|-------------------------------------------------------|
| Detection    | Rule triggered from 50+ failed logins in 5h window    |
| Analysis     | 6 IPs, 2 hosts, confirmed with KQL & Investigation    |
| Containment  | VM isolated via Defender for Endpoint                 |
| Eradication  | Antivirus scan run from Defender                      |
| Recovery     | NSG restricted to analyst IP; Azure Policy proposed  |
| Closure      | No successful logins; Incident closed as True Positive |

---

## 👤 Author

**Felipe Restrepo**  
Cybersecurity Intern – Login Pacific LLC  
📅 June 2025

---
