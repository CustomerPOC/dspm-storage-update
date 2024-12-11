# DIG | Prisma Cloud DSPM Storage Update

This repo contains an Azure Powershell script that can be used to modify Storage Account firewalls for DIG | DSPM that are used for data scanning.  This script will look for all Storage Accounts and VNets in a resource group matching: "dig-security-rg-". Once identified, the script will set the Storage Account firewall to only allow access from the DIG | DSPM VNet and the SaaS endpoints defined [here](https://docs.prismacloud.io/en/enterprise-edition/content-collections/data-security-posture-management/prisma-cloud-dspm-deployment/deploy-prisma-cloud-dspm-on-azure/azure-permissions): 


> [!NOTE]
> Even though the Storage Account by default is set with no firewall configuration, all containers and blobs are set to private access only and are not accessible from the internet.

---

Help can be acccessed by running the script with the -Help parameter.

```shell
help ./dspm-storage-change.ps1 
```

Examples are also available using the help -Examples switch.

```shell
help ./dspm-storage-change.ps1 -Examples
```

## Installation

Open Azure Cloud Shell and clone this repo.

```shell
git clone https://github.com/CustomerPOC/dspm-storage-update
```

Set your subscription id to target the DIG hub account subscription.

```shell
Set-AzContext -Subscription 00000000-0000-0000-0000-000000000000
```

Chnage the directory to the cloned repo.

```shell
cd dspm-storage-update
```

## Example Usage

Modify the Storage Account firewall to restrict access to the DIG | DSPM VNet and SaaS endpoints.

```shell
./dspm-storage-change.ps1 
```

Modify the Storage Account firewall to restrict access to the DIG | DSPM VNet and SaaS endpoints only in eastus and westus regions.

```shell
./dspm-storage-change.ps1 -Regions "eastus,westus"
```