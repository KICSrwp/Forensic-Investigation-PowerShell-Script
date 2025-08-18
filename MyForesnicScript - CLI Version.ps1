#
# PowerShell Forensic Data Collection Script - Enhanced
#
# This script is a more comprehensive tool for gathering forensic data,
# covering system, network, user, and security information.
#
# Disclaimer: Use this script only on systems where you have authorization
# for forensic purposes.
#

# --- 1. PROMPT FOR FORENSIC CASE DETAILS ---
Write-Host "--- FORENSIC EVIDANCE COLLECTION BY MUHAMMAD ANWAR ---" -ForegroundColor Green
Write-Host "--- FORENSIC CASE DETAILS ---" -ForegroundColor Green
$InvestigatorName = Read-Host "Enter the Investigator's Name"
$CaseName = Read-Host "Enter the Case Name or ID"
$Location = Read-Host "Enter the Investigation Location"
$IncidentDescription = Read-Host "Enter a brief Incident Description"

# --- 2. SET UP OUTPUT FILE AND FOLDER ---
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
$LogFolder = "$PSScriptRoot\Forensic_Data_$ComputerName_$Timestamp"
$LogFile = "$LogFolder\forensic_log.txt"

# Create the output folder if it doesn't exist
New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
Write-Host "`nOutput will be saved to: $LogFile" -ForegroundColor Green

# --- 3. DEFINE A FUNCTION TO EXECUTE COMMANDS AND FORMAT OUTPUT ---
function Run-Command {
    param (
        [string]$Heading,
        [string]$Command
    )
    Write-Host "Running: $Heading..."
    Add-Content -Path $LogFile -Value "=========================================================="
    Add-Content -Path $LogFile -Value "--- $Heading ---"
    Add-Content -Path $LogFile -Value "=========================================================="
    Add-Content -Path $LogFile -Value ""

    try {
        # Execute the command and capture the output
        $Output = Invoke-Expression -Command $Command 2>&1
        if ($Output) {
            $Output | Out-File -FilePath $LogFile -Append -Encoding UTF8
        } else {
            Add-Content -Path $LogFile -Value "No output to display."
        }
    }
    catch {
        Add-Content -Path $LogFile -Value "ERROR: Could not run command '$Command'. Reason: $_"
    }

    Add-Content -Path $LogFile -Value "`n`n"
}

# --- 4. WRITE THE CASE DETAILS TO THE LOG FILE ---
Write-Host "Writing case details to log file..."
Add-Content -Path $LogFile -Value "=========================================================="
Add-Content -Path $LogFile -Value "--- FORENSIC CASE REPORT ---"
Add-Content -Path $LogFile -Value "=========================================================="
Add-Content -Path $LogFile -Value ""
Add-Content -Path $LogFile -Value "Investigator: $InvestigatorName"
Add-Content -Path $LogFile -Value "Case Name: $CaseName"
Add-Content -Path $LogFile -Value "Investigation Date: $(Get-Date)"
Add-Content -Path $LogFile -Value "System Hostname: $ComputerName"
Add-Content -Path $LogFile -Value "Location: $Location"
Add-Content -Path $LogFile -Value "Description: $IncidentDescription"
Add-Content -Path $LogFile -Value ""
Add-Content -Path $LogFile -Value "----------------------------------------------------------"
Add-Content -Path $LogFile -Value "`n`n"

# SYSTEM INFO
Run-Command "System Information" "systeminfo"
Run-Command "Date and Time" "Get-Date"
Run-Command "Hostname" "hostname"
Run-Command "Hardware Information" "wmic csproduct get name, vendor"
Run-Command "BIOS Serial Number" "wmic bios get serialnumber"
Run-Command "Computer System Info" "wmic computersystem list brief"

# USERS & GROUPS
Run-Command "All Users" "net user"
Run-Command "Local Administrators Group Members" "net localgroup administrators"
Run-Command "User Account Details" "wmic useraccount get name, sid"
Run-Command "User Login Info" "wmic netlogin get name, lastlogin, badpasswordcount"
Run-Command "Group List" "wmic group list"

# NETWORK
Run-Command "Network Configuration" "ipconfig /all"
Run-Command "Active Network Connections" "netstat -naob"
Run-Command "Routing Table" "route print"
Run-Command "ARP Cache" "arp -a"
Run-Command "Wireless Network Interfaces" "netsh wlan show interfaces"
Run-Command "Saved Wi-Fi Profiles" "netsh wlan show profile"

# FIREWALL & SECURITY
Run-Command "Windows Firewall Rules" "Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action"
Run-Command "Windows Defender Status" "Get-MpComputerStatus"
Run-Command "Network Shares" "Get-CimInstance -ClassName Win32_Share"
Run-Command "Connected Network Sessions" "net session"

# SHARES & VOLUMES
Run-Command "Network Shares" "net share"
Run-Command "Active Network Sessions" "net session"
Run-Command "Shares via WMIC" "wmic share get"
Run-Command "Logical Disk Information" "wmic logicaldisk get"
Run-Command "Volume Information" "wmic volume get"

# PROCESSES & SERVICES
Run-Command "Running Services" "wmic service list brief | findstr Running"
Run-Command "Stopped Services" "wmic service list brief | findstr Stopped"
Run-Command "All Services" "wmic service list brief"
Run-Command "Running Tasks (Processes)" "tasklist"
Run-Command "Scheduled Tasks" "schtasks /query /fo LIST /v"

# SECURITY & LOGS
Run-Command "Security Event Log Settings" "wevtutil gl Security"
Run-Command "Audit Policies" "auditpol /get /category:*"
Run-Command "Firewall Rules" "netsh advfirewall show rule name=all"

# AUTORUNS & STARTUP
Run-Command "Startup Programs" "wmic startup list full"

# INSTALLED SOFTWARE & PATCHES
Run-Command "Installed Applications (64-bit)" "Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
Run-Command "Installed Applications (32-bit)" "Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'"
Run-Command "Hotfixes and Updates" "Get-HotFix"

# Autorun keys for the current user
Run-Command "Autorun (Current User)" "Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'"
# Autorun keys for all users
Run-Command "Autorun (All Users)" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'"
# 64-bit autorun keys (important for 64-bit systems)
Run-Command "Autorun (64-bit)" "Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'"

Run-Command "Startup Folder" "Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\Start\Menu\Programs\Startup"

# Shadow Copies: Checking if shadow copies exist
Run-Command "List Shadow Copies" "vssadmin list shadows"

# Get a list of the 50 most recently modified files in the user's Downloads directory
Run-Command "Recent User Downloads" "Get-ChildItem -Path '$env:USERPROFILE\Downloads' | Sort-Object LastWriteTime -Descending | Select-Object -First 50"
# SMS Session Details
Run-Command "SMB Sessions" "Get-SmbSession"
#DNS Cache 
Run-Command "DNS Client Cache" "Get-DnsClientCache"

Run-Command "Windows Defender Status" "Get-MpComputerStatus | Format-List"


Write-Host "Forensic data collection complete. Data is saved in: $LogFile"