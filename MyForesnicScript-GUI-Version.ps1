#
# PowerShell Forensic Data Collection Script - Enhanced
#
# This script is a more comprehensive tool for gathering forensic data,
# covering system, network, user, and security information.
#
# Disclaimer: Use this script only on systems where you have authorization
# for forensic purposes.
#

# Load the necessary assemblies for the GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Custom Blue Style Settings ---
$customFont = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$formBackColor = [System.Drawing.Color]::FromArgb(230, 240, 250) # Light blue
$buttonBackColor = [System.Drawing.Color]::FromArgb(30, 144, 255) # A nice dark blue
$buttonTextColor = [System.Drawing.Color]::White

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Forensic Case Details - Developed by Muhammad Anwar"
$form.Size = New-Object System.Drawing.Size(430, 320)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.BackColor = $formBackColor
$form.Font = $customFont

# Create and configure form controls
$labelInvestigator = New-Object System.Windows.Forms.Label
$labelInvestigator.Text = "Investigator's Name:"
$labelInvestigator.Location = New-Object System.Drawing.Point(10, 20)
$labelInvestigator.Size = New-Object System.Drawing.Size(120, 20)
$labelInvestigator.BackColor = $formBackColor

$textBoxInvestigator = New-Object System.Windows.Forms.TextBox
$textBoxInvestigator.Location = New-Object System.Drawing.Point(140, 20)
$textBoxInvestigator.Size = New-Object System.Drawing.Size(200, 20)

$labelCase = New-Object System.Windows.Forms.Label
$labelCase.Text = "Case Name/ID:"
$labelCase.Location = New-Object System.Drawing.Point(10, 50)
$labelCase.Size = New-Object System.Drawing.Size(120, 20)
$labelCase.BackColor = $formBackColor

$textBoxCase = New-Object System.Windows.Forms.TextBox
$textBoxCase.Location = New-Object System.Drawing.Point(140, 50)
$textBoxCase.Size = New-Object System.Drawing.Size(200, 20)

$labelLocation = New-Object System.Windows.Forms.Label
$labelLocation.Text = "Location:"
$labelLocation.Location = New-Object System.Drawing.Point(10, 80)
$labelLocation.Size = New-Object System.Drawing.Size(120, 20)
$labelLocation.BackColor = $formBackColor

$textBoxLocation = New-Object System.Windows.Forms.TextBox
$textBoxLocation.Location = New-Object System.Drawing.Point(140, 80)
$textBoxLocation.Size = New-Object System.Drawing.Size(200, 20)

$labelDescription = New-Object System.Windows.Forms.Label
$labelDescription.Text = "Description:"
$labelDescription.Location = New-Object System.Drawing.Point(10, 110)
$labelDescription.Size = New-Object System.Drawing.Size(120, 20)
$labelDescription.BackColor = $formBackColor

$textBoxDescription = New-Object System.Windows.Forms.TextBox
$textBoxDescription.Location = New-Object System.Drawing.Point(140, 110)
$textBoxDescription.Size = New-Object System.Drawing.Size(200, 100)
$textBoxDescription.Multiline = $true

$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = "Start Investigation"
$okButton.Location = New-Object System.Drawing.Point(235, 220)
$okButton.Size = New-Object System.Drawing.Size(100, 50)
$okButton.BackColor = $buttonBackColor
$okButton.ForeColor = $buttonTextColor
$okButton.Add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK })
$okButton.FlatStyle = 'Flat'
$okButton.FlatAppearance.BorderSize = 0

# Add controls to the form
$form.Controls.Add($labelInvestigator)
$form.Controls.Add($textBoxInvestigator)
$form.Controls.Add($labelCase)
$form.Controls.Add($textBoxCase)
$form.Controls.Add($labelLocation)
$form.Controls.Add($textBoxLocation)
$form.Controls.Add($labelDescription)
$form.Controls.Add($textBoxDescription)
$form.Controls.Add($okButton)

# Show the form and get the results
if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    # Assign textbox values to variables
    $InvestigatorName = $textBoxInvestigator.Text
    $CaseName = $textBoxCase.Text
    $Location = $textBoxLocation.Text
    $IncidentDescription = $textBoxDescription.Text
} else {
    Write-Host "`nUser canceled the operation. Exiting script." -ForegroundColor Red
    $form.Dispose()
    exit
}

$form.Dispose()


# Now the rest of the script can use these variables to write the report
# ... (rest of your script below)


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
