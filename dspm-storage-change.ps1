<#
.SYNOPSIS
    This script modifies Azure Storage accounts in the Dig | DSPM hub scanning account to restrict access to the specified IP addresses.

.DESCRIPTION
    This script will look for all storage accounts and VNets in a resource group matching: "dig-security-rg-"
    Once identified the script will set the storage account firewall to deny access except to the regional VNet from Dig | DSPM and Dig | DSPM SaaS IP addresses.

.PARAMETER Ips
    Specify Ip's to add to storage account firewall: "54.225.205.121, 18.214.146.232, 3.93.120.3"
    
.PARAMETER Regions
    Comma-separated list of Azure regions: "westus,eastus,centralus"
    When selected only the specified regions will be modified.

.EXAMPLE
    Modify storage account firewall to allow specified IP's

    .\dspm-storage-change.ps1 -Ips "54.225.205.121, 18.214.146.232, 3.93.120.3"

.EXAMPLE
    Modify storage account firewall only in westus, eastus, and eastus2 regions.

    .\dspm-storage-change.ps1  -Regions "westus,eastus, eastus2" 

.NOTES
    Author: Erick Moore
    Date: 2024-12-11

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, HelpMessage = "Allowed public IPs to allow. Default: '54.225.205.121, 18.214.146.232, 3.93.120.3, 52.48.123.3, 99.80.210.235, 34.247.249.123'")]
    [string]$Ips,
    [Parameter(Mandatory=$false, HelpMessage="Comma-separated list of Azure regions to apply changes (e.g., 'westus,eastus,centralus')")]
    [string]$Regions    
)

$tagName            = 'dig-security'
$resourceGroup      = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -match "dig-security-rg-" }
$allVnets           = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup.ResourceGroupName
$allStorageAccounts = Get-AzStorageAccount -ResourceGroupName $resourceGroup.ResourceGroupName
$storageCount       = $allStorageAccounts.Count
$serviceEndpoints   = @("Microsoft.AzureCosmosDB", "Microsoft.Sql", "Microsoft.Storage")
$dspmIps            = @("54.225.205.121", "18.214.146.232", "3.93.120.3", "52.48.123.3", "99.80.210.235", "34.247.249.123")
$azureAccess        = "Logging, Metrics, AzureServices"


if ($Ips) { $publicIPs = $Ips.Split(",").Trim() }
if ($Regions) { $dspmRegions = $Regions.Split(',').Trim() }

# Set Default values if not provided
if (-not $Ips) { $publicIPs = $dspmIps }

# ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
# ║ Main Process: Loop through all discovered storage accounts in Dig | DSPM resource group, add VNet and required IP's to storage firewall. ║
# ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
foreach  ($storageAccount in $allStorageAccounts) {

    # Match VNet to storage account location
    $currentVNet = $allVnets | Where-Object Location -eq $storageAccount.Location

    $counter++
    $percentComplete = ($counter / $storageCount) * 100

    # If Regions switch is used, skip account if not in specified regions
    if ($Regions) {
        if ($storageAccount.Location -notin $dspmRegions) {
            Start-Sleep -Seconds 1
            continue
        }
    }

    # Progress bar
    Write-Progress -Activity "Region: $($storageAccount.Location) | Storage Account: $($storageAccount.StorageAccountName)" -Status "Processing Storage Account $counter of $storageCount" -PercentComplete $percentComplete -Id 1

    # Skip if no matching VNet
    if (-not $currentVNet) { continue }

    # Set Dig | DSPM subnet name format
    $subnetName = "$($tagName)-$($currentVNet.Location)"

    try {
        # Set service endpoints on default subnet
        $currentVNet | Set-AzVirtualNetworkSubnetConfig -Name $subnetName -ServiceEndpoint $serviceEndpoints -AddressPrefix $currentVNet.Subnets[0].AddressPrefix -NetworkSecurityGroupId $currentVNet.Subnets[0].NetworkSecurityGroup.Id | Set-AzVirtualNetwork > $null
    
        # Get scan subnet id
        $dspmSubnet = @($currentVNet.Subnets.Id)
    
        # Build storage account allow rules for IP's and VNet
        $ipRules    = $publicIPs | ForEach-Object { @{IPAddressOrRange = $_; Action = "allow" } }
        $vnetRules  = $dspmSubnet | ForEach-Object { @{VirtualNetworkResourceId = $_; Action = "allow" } }
    
        Set-AzStorageAccount -ResourceGroupName $resourceGroup.ResourceGroupName -Name $storageAccount.StorageAccountName `
            -PublicNetworkAccess Enabled `
            -NetworkRuleSet (@{bypass=$azureAccess;
                ipRules=$ipRules;
                virtualNetworkRules=$vnetRules;
                defaultAction="deny"}) > $null
    }
    catch {
        Write-Error "Failed to modify Storage Account $($storageAccount.StorageAccountName): $_"
    }
}