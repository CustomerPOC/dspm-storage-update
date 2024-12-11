<#
.SYNOPSIS
    This script allows for the re-ip or re-creation of DIG | Prisma Cloud DSPM VNets used for data scanning.

.DESCRIPTION
    This script will look for all VNets in a resource group matching: "dig-security-rg-" and then find all VNets matching the tag "dig-security"
    Once identified the script will remove all subnets and CIDR's, replace with specified CIDR.

.PARAMETER Backup
    Switch to backup existing VNet as JSON file.

.PARAMETER Cidr
    Address prefix to use for new VNets: 10.1.0.0/24

.PARAMETER CreateVNet
    Create/re-create new VNets based on defined regions.

.PARAMETER Force
    If CreateVNet is used, this will overwrite existing VNets instead of prompting to replace.

.PARAMETER ImportFile
    Import CSV file with CIDR's to use for each region. The CSV format should have a header row with the following columns:
    Region, Cidr

.PARAMETER Prompt
    Switch to prompt user for new CIDR.

.PARAMETER Regions
    Comma-separated list of Azure regions: "westus,eastus,centralus"
    When selected only the specified regions will be modified.
    
.EXAMPLE
    Create VNet's in westus, eastus, and eastus2 regions.

    .\dspm-vnet-change.ps1 -CreateVNet -Regions "westus,eastus, eastus2" -Cidr 10.10.0.0/24

.EXAMPLE
    Modify existing VNets with new CIDR by importing a CSV file.

    .\dspm-vnet-change.ps1 -ImportFile .\cidr.csv

.EXAMPLE
    Re-IP existing VNets with new CIDR.

    .\dspm-vnet-change.ps1 -Cidr 10.10.0.0/24

.EXAMPLE
    Re-IP existing VNets with new CIDR and backup existing VNets.

    .\dspm-vnet-change.ps1 -Cidr 10.10.0.0/24 -Backup

.EXAMPLE
    Re-IP existing VNets with new CIDR and prompt for each region CIDR.

    .\dspm-vnet-change.ps1 -Cidr 10.10.0.0/24 -Prompt

.NOTES
    Author: Erick Moore
    Date: 2024-12-09

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, HelpMessage = "Allowed public IPs to allow. Default: '54.225.205.121, 18.214.146.232, 3.93.120.3'")]
    [string]$Ips, 
    [Parameter(Mandatory=$false, HelpMessage="Comma-separated list of Azure regions used for CreateVNet switch (e.g., 'westus,eastus,centralus')")]
    [string]$Access
)

$tagName            = 'dig-security'
$resourceGroup      = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -match "dig-security-rg-" }
$allVnets           = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup.ResourceGroupName
$allStorageAccounts = Get-AzStorageAccount -ResourceGroupName $resourceGroup.ResourceGroupName
$storageCount       = $allStorageAccounts.Count
$serviceEndpoints   = @("Microsoft.AzureCosmosDB", "Microsoft.Sql", "Microsoft.Storage")
$dspmIps            = @("54.225.205.121", "18.214.146.232", "3.93.120.3")
$azureAccess        = "Logging, Metrics, AzureServices"


if ($Ips) { $publicIPs = $Ips.Split(",").Trim() }

# Set Default values if not provided
if (-not $Ips) { $publicIPs = $dspmIps }
if (-not $Access) { $Access = $azureAccess }

# ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
# ║ Main Process: Loop through all discovered VNet's, find matching tag, remove all subnets and CIDR's, replace with specified CIDR.         ║
# ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
foreach  ($storageAccount in $allStorageAccounts) {

    # Match VNet to storage account location
    $currentVNet = $allVnets | Where-Object Location -eq $storageAccount.Location

    $counter++
    $percentComplete = ($counter / $storageCount) * 100

    # Progress bar
    Write-Progress -Activity "Processing Storage Account $($storageAccount.StorageAccountName)" -Status "Processing Storage Account $counter of $storageCount" -PercentComplete $percentComplete -Id 1

    # Skip if no matching VNet
    if (-not $currentVNet) { continue }

    # Set Dig | DSPM subnet name format
    $subnetName = "$($tagName)-$($currentVNet.Location)"

    try {
        # Set service endpoints on default subnet
        $subnetConfig = Set-AzVirtualNetworkSubnetConfig -Name $subnetName -ServiceEndpoint $serviceEndpoints -VirtualNetwork $currentVNet -AddressPrefix $currentVNet.Subnets[0].AddressPrefix 
        $subnetConfig | Set-AzVirtualNetwork 
    
        # Get scan subnet id
        $dspmSubnet = @($currentVNet.Subnets.Id)
    
        # Build storage account allow rules for IP's and VNet
        $ipRules    = $publicIPs | ForEach-Object { @{IPAddressOrRange = $_; Action = "allow" } }
        $vnetRules  = $dspmSubnet | ForEach-Object { @{VirtualNetworkResourceId = $_; Action = "allow" } }
    
        Set-AzStorageAccount -ResourceGroupName $resourceGroup.ResourceGroupName -Name $storageAccount.StorageAccountName `
            -NetworkRuleSet (@{bypass=$azureAccess;
                ipRules=$ipRules;
                virtualNetworkRules=$vnetRules;
                defaultAction="deny"}) 
    }
    catch {
        Write-Error "Failed to modify Storage Account $($storageAccount.StorageAccountName): $_"
    }
}