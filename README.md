# Forensic-Investigation-PowerShell-Script

## Overview 🚀
As a Forensic Investigator or an Incident Handling and Response Professional, the ability to **rapidly and precisely collect incident data** from an endpoint is paramount. This PowerShell script is engineered to streamline that critical initial phase of an investigation, enabling swift and comprehensive data acquisition from Windows systems.

It serves as a **non-intrusive data collection tool**, designed to gather a wide array of system, network, user, and security-related information. This structured approach helps L1 analysts and seasoned investigators alike to create an initial forensic snapshot, facilitating faster triage and more informed decision-making during security incidents, including ransomware investigations.

---

## Key Information Collected 📊
This script meticulously gathers the following data points from the target Windows system, organizing the output for ease of analysis:

### **System Information**
* System Information (detailed `systeminfo` output)
* Date and Time
* Hostname
* Hardware Information (Model, Manufacturer, System Type, BIOS details)
* BIOS Serial Number
* Computer System Info (brief)
* Operating System Information (Caption, Version, OS Architecture, Install Date)
* Environment Variables

### **User & Logon Information**
* All User Accounts (local and domain)
* Local Administrators Group Members
* User Account Details (Name, SID)
* User Login Info (Name, Last Login, Bad Password Count)
* Group List
* User Profile Paths

### **Network Information**
* IP Configuration (`ipconfig /all`)
* ARP Cache
* Active Network Connections (detailed)
* Listening Ports
* Network Adapters (Name, Description, MAC Address)
* DNS Client Cache
* Wireless Network Interfaces
* Saved Wi-Fi Profiles

### **Firewall & Security Posture**
* Windows Firewall Rules (Name, DisplayName, Enabled, Direction, Action)
* Windows Defender Status (Real-time protection, update status, scan times)
* Network Shares
* Connected Network Sessions

### **Running Processes & Services**
* Running Processes (ID, Name, Path, Working Set, CPU)
* Processes with No Window Title (potential suspicious activity)
* All Services (detailed status and configuration)
* Scheduled Tasks

### **Installed Software & Patches**
* Installed Applications (64-bit and 32-bit registry entries)
* Hotfixes and Updates (`Get-HotFix` output)

### **Persistence & Autoruns (Critical for Ransomware Investigation)**
* Autorun (Current User Registry)
* Autorun (All Users Registry)
* Autorun (64-bit Registry)
* Startup Folder (programs launched at user logon)
* Prefetch File History (history of executed programs)
* List Shadow Copies (evidence of data deletion attempts)
* Volume List (information on system volumes)

### **Event Logs (Recent Critical Events)**
* Recent Security Log Events (e.g., Audit Failures, ID 4625)
* Recent System Log Events (Critical Level)
* Recent PowerShell Log Events

---

## How to Use 🚀

1.  **Download the Script:** Clone this repository or download the `MyForesnicScript-GUI-Version.ps1` script.
2.  **Run with Administrator Privileges:** Open PowerShell as an Administrator. This is crucial for collecting comprehensive system data.
3.  **Navigate to Script Directory:** Change your directory to where you saved the script (e.g., `cd C:\Forensics\`).
4.  **Set Execution Policy (if needed):** If you encounter an error, you might need to adjust your PowerShell execution policy:
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    ```
5.  **Execute the Script:**
    ```powershell
    .\MyForesnicScript-GUI-Version.ps1
    ```
6.  **Provide Case Details:** The script will prompt you for essential investigation details (Investigator Name, Case Name/ID, Location, Incident Description) via a user-friendly graphical interface.
7.  **Review Output:** The script will create a timestamped folder (e.g., `Forensic_Data_YOURHOSTNAME_YYYY-MM-DD_HH-MM-SS`) in the same directory as the script. Inside, you'll find `forensic_log.txt` containing all collected data, organized by clear headings.

---

## Important Considerations ⚠️

* **Forensic Soundness:** This script is designed for **read-only data collection** to preserve evidence integrity. It does *not* include commands that modify system configurations (e.g., stopping services, adding users, changing firewall rules).
* **Permissions:** Running the script requires Administrator privileges to access system-level information.
* **Environment:** For sensitive investigations, always execute forensic tools in a **controlled and isolated environment** (e.g., a forensic workstation, a forensically sound boot environment, or a virtual machine).
* **Customization:** The script can be easily customized to add or remove commands based on specific investigation requirements.

---

## Contribution & Feedback 🤝
Muhammad Anwar

## A complied version is also available in the Realese 
Screenshot of the complied version 4.2

<img width="580" height="700" alt="image" src="https://github.com/user-attachments/assets/fe3687d5-f70a-486f-9c55-a418e925d978" />
