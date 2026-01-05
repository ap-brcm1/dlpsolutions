# `dynamicWNDeployment-VMWare.ps1`

## Synopsis

Clones and customizes a VMware vSphere VM for a Symantec Data Loss Prevention (DLP) Worker Node from a template, starts it, runs a post-provisioning script to update DLP properties, and restarts the DLP service.

## Description

This script automates the deployment of a new, unique Symantec Data Loss Prevention (DLP) Worker Node virtual machine. It connects to a vCenter Server, clones a VM from a specified template, and applies a VM Customization Specification to ensure the new VM has a unique hostname and identity (sysprep).

After cloning and customization, it waits for VMware Tools, verifies guest credentials are active, executes a PowerShell script inside the guest OS to update application-specific properties for the DLP Worker Node, and finally restarts the Symantec DLP Detector service on the guest VM.

## Parameters

-   `VCenterServer`: The fully qualified domain name (FQDN) or IP address of the vCenter Server.
-   `TemplateName`: The name of the VM template or source VM to clone from.
-   `NewVMName`: The name for the new virtual machine. This will also become the guest OS hostname.
-   `ClusterName`: The name of the vSphere cluster where the new VM will be deployed.
-   `DatastoreName`: The name of the datastore to house the new VM's files.
-   `CustomizationSpecName`: The name of the VM Customization Specification to apply (for sysprep).
-   `VMFolderName`: The name of the VM and Template folder to place the new VM in.
-   `GuestCredential`: A PSCredential object for an account on the guest OS with permissions to run scripts. If not provided, the script will securely prompt for this credential.
-   `PropertyFile`: The absolute path to the properties file inside the guest OS to update.
-   `DataNodeIP`: The IP address to be assigned to the 'datanodeip' property in the properties file.
-   `ServiceToRestart`: The name of the service to restart on the guest VM after configuration is complete.

## Example

The script will securely prompt for the vCenter credentials and the Guest VM credentials.

```powershell
.\dynamicWNDeployment-VMWare.ps1 -VCenterServer 'vcenter.example.com' -TemplateName 'TPL-WIN2022' -NewVMName 'my-new-vm' -ClusterName 'PROD-Cluster' -DatastoreName 'DS-SSD-01' -CustomizationSpecName 'win-sysprep-12' -VMFolderName 'WebServers' -PropertyFile 'C:\\app\\config.properties' -DataNodeIP '192.168.1.100' -ServiceToRestart 'SymantecDLPDetectorService'
```

## Prerequisites

### Software:
- This script requires the VMware PowerCLI module. To install it, run the following command in PowerShell:
  ```powershell
  Install-Module -Name VMware.PowerCLI -Scope CurrentUser
  ```

### vSphere / vCenter Permissions:
- The user running this script requires login access to the vCenter Server.
- The user's role must have permissions for:
    - Viewing the source VM template.
    - Deploying a new VM from a template.
    - Running guest operations on a VM, specifically:
        - "VirtualMachine.GuestOperations.Modify"
        - "VirtualMachine.GuestOperations.Execute"

### Guest Operating System (Windows):
- The template VM must have the following registry key set to allow remote script execution via Invoke-VMScript:
  ```powershell
  New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWORD -Force
  ```
- The user must provide credentials for a guest OS account that has sufficient permissions to restart the target service (e.g., 'SymantecDLPDetectorService'). This usually requires local administrator rights.

### PowerCLI Configuration:
- Before running, you may need to configure PowerCLI to ignore self-signed certificates from your vCenter server by running:
  ```powershell
  Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
  ```

### Testing Environment:
- This script was successfully tested with the following components:
    - VMware.PowerCLI Version: 13.3.0.24145083
    - Host OS: Windows Server 2022
    - PowerShell Version: 5.1
