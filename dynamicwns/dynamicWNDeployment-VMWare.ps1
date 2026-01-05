<#
.SYNOPSIS
    Clones and customizes a VMware vSphere VM for a Symantec Data Loss Prevention (DLP) Worker Node
    from a template, starts it, runs a post-provisioning script to update DLP properties, and restarts the DLP service.

.DESCRIPTION
    This script automates the deployment of a new, unique Symantec Data Loss Prevention (DLP) Worker Node virtual machine.
    It connects to a vCenter Server, clones a VM from a specified template, and applies a VM Customization
    Specification to ensure the new VM has a unique hostname and identity (sysprep).

    After cloning and customization, it waits for VMware Tools, verifies guest credentials are active,
    executes a PowerShell script inside the guest OS to update application-specific properties for the DLP Worker Node,
    and finally restarts the Symantec DLP Detector service on the guest VM.

.PARAMETER VCenterServer
    The fully qualified domain name (FQDN) or IP address of the vCenter Server.

.PARAMETER TemplateName
    The name of the VM template or source VM to clone from.

.PARAMETER NewVMName
    The name for the new virtual machine. This will also become the guest OS hostname.

.PARAMETER ClusterName
    The name of the vSphere cluster where the new VM will be deployed.

.PARAMETER DatastoreName
    The name of the datastore to house the new VM's files.

.PARAMETER CustomizationSpecName
    The name of the VM Customization Specification to apply (for sysprep).

.PARAMETER VMFolderName
    The name of the VM and Template folder to place the new VM in.

.PARAMETER GuestCredential
    A PSCredential object for an account on the guest OS with permissions to run scripts.
    If not provided, the script will securely prompt for this credential.

.PARAMETER PropertyFile
    The absolute path to the properties file inside the guest OS to update.

.PARAMETER DataNodeIP
    The IP address to be assigned to the 'datanodeip' property in the properties file.

.PARAMETER ServiceToRestart
    The name of the service to restart on the guest VM after configuration is complete.

.EXAMPLE
    # The script will securely prompt for the vCenter credentials and the Guest VM credentials.
    .\vmcustomization-wn.ps1 -VCenterServer 'vcenter.example.com' -TemplateName 'TPL-WIN2022' -NewVMName 'my-new-vm' -ClusterName 'PROD-Cluster' -DatastoreName 'DS-SSD-01' -CustomizationSpecName 'win-sysprep-12' -VMFolderName 'WebServers' -PropertyFile 'C:\app\config.properties' -DataNodeIP '192.168.1.100' -ServiceToRestart 'SymantecDLPDetectorService'

.NOTES
    --------------------------
    --- SCRIPT PREREQUISITES ---
    --------------------------

    SOFTWARE:
    - This script requires the VMware PowerCLI module. To install it, run the following command in PowerShell:
      Install-Module -Name VMware.PowerCLI -Scope CurrentUser

    VSPHERE / VCENTER PERMISSIONS:
    - The user running this script requires login access to the vCenter Server.
    - The user's role must have permissions for:
        - Viewing the source VM template.
        - Deploying a new VM from a template.
        - Running guest operations on a VM, specifically:
            - "VirtualMachine.GuestOperations.Modify"
            - "VirtualMachine.GuestOperations.Execute"

    GUEST OPERATING SYSTEM (WINDOWS):
    - The template VM must have the following registry key set to allow remote script execution via Invoke-VMScript:
      New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWORD -Force
    - The user must provide credentials for a guest OS account that has sufficient permissions to restart the target service (e.g., 'SymantecDLPDetectorService'). This usually requires local administrator rights.

    POWERCLI CONFIGURATION:
    - Before running, you may need to configure PowerCLI to ignore self-signed certificates from your vCenter server by running:
      Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

    TESTING ENVIRONMENT:
    - This script was successfully tested with the following components:
        - VMware.PowerCLI Version: 13.3.0.24145083
        - Host OS: Windows Server 2022
        - PowerShell Version: 5.1
#>

# --- Script Parameters ---
# This section defines all the inputs for the script.
# [Parameter(Mandatory=$true)] ensures that the script will prompt the user for any parameter not provided when the script is run.
param(
    [Parameter(Mandatory=$true)]
    [string]$VCenterServer,

    [Parameter(Mandatory=$true)]
    [string]$TemplateName,

    [Parameter(Mandatory=$true)]
    [string]$NewVMName,

    [Parameter(Mandatory=$true)]
    [string]$ClusterName,

    [Parameter(Mandatory=$true)]
    [string]$DatastoreName,

    [Parameter(Mandatory=$true)]
    [string]$DataNodeIP,

    [Parameter(Mandatory=$true)]
    [string]$CustomizationSpecName,

    [Parameter(Mandatory=$true)]
    [string]$VMFolderName,

    [pscredential]$GuestCredential,

    [Parameter(Mandatory=$true)]
    [string]$PropertyFile,

    [Parameter(Mandatory=$true)]
    [string]$ServiceToRestart
)

# --- Main Script ---

# --- Securely Gather Credentials ---
# Prompt for vCenter credentials with a clear message.
$vCenterCredential = Get-Credential -Message "Please enter credentials for vCenter Server: $VCenterServer"

# If guest credentials were not provided as a parameter, prompt for them with a clear message.
if (-not $GuestCredential) {
    $GuestCredential = Get-Credential -Message "Please enter Guest OS credentials for the new VM: $NewVMName"
}

# Establish a connection to the vCenter Server.
Write-Host "Connecting to vCenter Server: $VCenterServer..."
Connect-VIServer -Server $VCenterServer -Credential $vCenterCredential

# --- Main Try/Catch Block for Cleanup ---
# This block contains the entire workflow. If any command fails, the 'catch' block will be executed.
# The 'finally' block will always run, ensuring we disconnect from vCenter.
try {
    # --- Retrieve vSphere objects ---
    # Gather all the necessary vCenter objects (template, cluster, etc.) before starting.
    # -ErrorAction Stop ensures that if any object is not found, the script will halt immediately and jump to the 'catch' block.
    Write-Host "Retrieving vSphere objects..."
    $template = Get-Template -Name $TemplateName -ErrorAction Stop
    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $datastore = Get-Datastore -Name $DatastoreName -ErrorAction Stop
    $vmFolder = Get-Folder -Name $VMFolderName -ErrorAction Stop
    $customizationSpec = Get-OSCustomizationSpec -Name $CustomizationSpecName -ErrorAction Stop

    # Find the default resource pool within the specified cluster.
    $resourcePool = Get-ResourcePool -Location $cluster | Where-Object { $_.Name -eq "Resources" }
    if (-not $resourcePool) { throw "Default 'Resources' Resource Pool not found in cluster '$ClusterName'." }

    # --- Clone the Virtual Machine ---
    # Check if a VM with the same name already exists to prevent conflicts.
    if (Get-VM -Name $NewVMName -ErrorAction SilentlyContinue) {
        throw "A VM with the name '$NewVMName' already exists."
    }

    # Create the new VM from the template and apply the customization specification.
    # The -OSCustomizationSpec parameter is key to making the new VM unique (hostname, SID, etc.).
    Write-Host "Cloning VM '$NewVMName' from template '$TemplateName' and applying customization..."
    $vm = New-VM -Name $NewVMName -Template $template -Datastore $datastore -ResourcePool $resourcePool -Location $vmFolder -OSCustomizationSpec $customizationSpec -ErrorAction Stop

    Write-Host "[SUCCESS] VM '$NewVMName' created. Customization will occur on first boot."

    # --- Power On and Configure Guest ---
    # Power on the VM. This action triggers the sysprep process defined in the customization spec.
    Write-Host "Powering on VM '$NewVMName' to begin customization..."
    Start-VM -VM $vm

    # Wait for the guest OS to finish customizing and for VMware Tools to start.
    # This indicates the OS is up and running. The timeout is increased to allow time for sysprep.
    Write-Host "Waiting for VMware Tools to be running post-customization (this may take several minutes)..."
    if (-not ($vm | Wait-Tools -TimeoutSeconds 1200)) { # Increased timeout for sysprep
        throw "VMware Tools did not start within the timeout period. Post-provisioning script will be skipped."
    }
    Write-Host "[SUCCESS] VMware Tools is running inside the customized VM."

    # --- Verify Guest Credentials Post-Customization ---
    # After sysprep, the guest OS may still be initializing. This loop repeatedly tries to authenticate
    # until the guest OS is fully ready to accept remote commands.
    Write-Host "Verifying guest credentials are ready post-customization..."
    $maxRetries = 20 # 20 retries * 30 seconds = 10 minutes timeout
    $retryIntervalSeconds = 30
    $credentialsVerified = $false

    for ($i = 1; $i -le $maxRetries; $i++) {
        Write-Host 'Attempt $i of $maxRetries: Checking guest credential readiness...'
        try {
            # Execute a simple, non-destructive command to test authentication.
            Invoke-VMScript -VM $vm -GuestCredential $GuestCredential -ScriptType Powershell -ScriptText "Write-Output 'auth_test_ok'" -ErrorAction Stop | Out-Null
            
            # If the command succeeds, credentials are valid and we can proceed.
            $credentialsVerified = $true
            Write-Host "[SUCCESS] Guest credentials are valid and OS is ready."
            break # Exit the loop
        }
        catch {
            # If it fails, wait and retry. This is expected for the first few minutes after sysprep.
            Write-Host "Guest OS not ready yet. Waiting $retryIntervalSeconds seconds before retrying..."
            Start-Sleep -Seconds $retryIntervalSeconds
        }
    }

    # If the loop finishes without a successful authentication, fail the script.
    if (-not $credentialsVerified) {
        throw "CRITICAL: Timed out waiting for guest credentials to become valid after customization. Please check the VM console for errors."
    }

    # --- Define and Execute Guest Script ---
    # This here-string defines a block of PowerShell code that will be executed *inside* the guest VM.
    # It modifies the specified properties file.
    $guestScript = @"
# This script runs inside the guest OS of the new VM.
Write-Output "Guest script started."

`$propFile = "$PropertyFile"

# Fail fast if the properties file does not exist.
if (-not (Test-Path `$propFile)) {
    Write-Error "CRITICAL: Properties file not found at '`$propFile'. Cannot proceed with customization."
    exit 1
}

# Define the properties to be updated.
`$propertiesToUpdate = @{
    "discover.cluster.node.id" = [guid]::NewGuid().ToString()
    "discover.cluster.ignite.discovery.addresses"  = "$DataNodeIP"
}

# Read the existing properties file into a hashtable for easy manipulation.
`$existingProperties = @{}
Get-Content -Path `$propFile | ForEach-Object {
    if (`$_ -match "=") {
        `$key, `$value = `$_`.Split('=', 2)
        `$existingProperties[`$key.Trim()] = `$value.Trim()
    }
}

# Merge the new/updated values into the existing properties.
`$propertiesToUpdate.GetEnumerator() | ForEach-Object {
    `$existingProperties[`$_.Name] = `$_.Value
    Write-Output "Set property: `$(`$_.Name) = `$(`$_.Value)"
}

# Build the new content for the properties file.
`$newLines = @()
`$existingProperties.GetEnumerator() | Sort-Object Name | ForEach-Object {
    `$newLines += "`$(`$_.Name)=`$(`$_.Value)"
}

# Write the updated content back to the file, failing if any error occurs.
try {
    Set-Content -Path `$propFile -Value `$newLines -Force -ErrorAction Stop
    Write-Output "Successfully updated properties in '`$propFile'."
}
catch {
    Write-Error "A failure occurred while writing to '`$propFile' - `$_ "
    exit 1
}

Write-Output "Guest script finished."
"@

    # Send the guest script to the VM for execution.
    Write-Host "Executing post-provisioning script to update properties file..."
    Invoke-VMScript -VM $vm -GuestCredential $GuestCredential -ScriptType Powershell -ScriptText $guestScript -ErrorAction Stop
    Write-Host "[SUCCESS] Post-provisioning script executed successfully."

    # --- Restart Guest Service ---
    # If a service name was provided, execute a second guest script to restart it.
    if (-not [string]::IsNullOrEmpty($ServiceToRestart)) {
        Write-Host "Attempting to restart service '$ServiceToRestart' on the guest VM..."
        $serviceRestartScript = @"
# Check if the service exists before trying to restart it.
`$service = Get-Service -Name '$ServiceToRestart' -ErrorAction SilentlyContinue
if (`$service) {
    try {
        # Restart the service.
        Restart-Service -Name '$ServiceToRestart' -Force -ErrorAction Stop
        Write-Output "Service '$ServiceToRestart' restarted successfully."
    }
    catch {
        # Fail if the restart command fails.
        Write-Error "Failed to restart service '$ServiceToRestart'. Error: `$_"
        exit 1
    }
} else {
    # Warn the user if the service doesn't exist, but do not fail the script.
    Write-Warning "Service '$ServiceToRestart' not found. Skipping restart."
}
"@
        # Send the service restart script to the VM for execution.
        Invoke-VMScript -VM $vm -GuestCredential $GuestCredential -ScriptType Powershell -ScriptText $serviceRestartScript -ErrorAction Stop
        Write-Host "[SUCCESS] Service restart command sent successfully."
    }

} catch {
    # This block catches any terminating error from the 'try' block above.
    Write-Error "A critical error occurred during the VM deployment process. Error: $_"
} finally {
    # --- Disconnect ---
    # This block always runs, whether the script succeeded or failed, ensuring the vCenter session is closed.
    Write-Host "Disconnecting from vCenter Server."
    Disconnect-VIServer -Server $VCenterServer -Confirm:$false -ErrorAction SilentlyContinue
}
