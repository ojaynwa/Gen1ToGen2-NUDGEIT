Param (
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$VMName,

    [Parameter(Mandatory = $true)]
    [string]$AdminUsername,

    [Parameter(Mandatory = $true)]
    [securestring]$AdminPassword,

    [Parameter(Mandatory = $false)]
    [switch]$EnableGen2Security
)

function Write-Log ($message) {
    $message = "$(Get-Date ([datetime]::UtcNow) -Format "o") $message"
    Write-Host $message
    if ([System.IO.Directory]::Exists($env:temp)) {
        try {
            Write-Output $message | Out-File "$($Script:localPath)\$($Script:logFileName)" -Append -Encoding utf8
        } 
        catch {} 
    }
}
Function Get-IPSettings {
    Param (
        $vmName,
        $nicId,
        $count
    )
    $nic = Get-AzNetworkInterface -ResourceId $nicId
    $sourceSubnetId = $nic.IpConfigurations.Subnet.Id | Select-Object -Unique
    $nicProps = [ordered]@{
        Name           = $nic.Name
        SourceVnetId   = $sourceSubnetId.Substring(0, $sourceSubnetId.IndexOf("/subnets/"))
        SourceVnetName = $sourceSubnetId.Substring(0, $sourceSubnetId.IndexOf("/subnets/"))[($sourceSubnetId.Substring(0, $sourceSubnetId.IndexOf("/subnets/")).LastIndexOf("/") + 1)..($sourceSubnetId.Substring(0, $sourceSubnetId.IndexOf("/subnets/")).Length - 1)] -join ''
        SourceSubnetId = $sourceSubnetId
        properties     = [pscustomobject][ordered]@{
            ipConfigurations            = @()
            Primary                     = $false
            enableAcceleratedNetworking = $false
            enableIPForwarding          = $false
        }
        Id             = $nicId
        
    }
    $i = 1
    foreach ($ip in $nic.IpConfigurations) {
        $mainProps = [pscustomobject][ordered]@{
            name = "ipconfig$i-eth$count"
        }
        $ipProps = [pscustomobject][ordered]@{
            primary = $ip.Primary
        }
        if ($ip.PrivateIpAllocationMethod -eq "Static") {
            $ipProps | Add-Member -MemberType NoteProperty -Name privateIPAddress -Value $ip.PrivateIpAddress
            $ipProps | Add-Member -MemberType NoteProperty -Name privateIPAllocationMethod -Value $ip.PrivateIpAllocationMethod
        }
        else {
            $ipProps | Add-Member -MemberType NoteProperty -Name privateIPAllocationMethod -Value $ip.PrivateIpAllocationMethod
        }
        if ($null -ne $ip.PublicIpAddress) {
            $publicIPAddress = [pscustomobject][ordered]@{
                name = $ip.PublicIpAddress.id[($ip.PublicIpAddress.id.LastIndexOf("/") + 1)..($ip.PublicIpAddress.id.Length - 1)] -join ''
                id   = $ip.PublicIpAddress.id
            }
            
            $ipProps | Add-Member -MemberType NoteProperty -Name publicIPAddress -Value $publicIPAddress
        }
        
        $properties = $ipProps
        $mainProps | Add-Member -MemberType NoteProperty -Name properties -Value $properties
        $nicProps.properties.ipConfigurations += $mainProps
        $nicProps.properties.Primary = $nic.Primary
        $nicProps.properties.enableIPForwarding = $nic.enableIPForwarding
        $nicProps.properties.enableAcceleratedNetworking = $nic.enableAcceleratedNetworking
        $i++
    }
    
    $nicSettings = New-Object psobject -Property $nicProps

    return @($nicSettings)
}
function Get-DataDiskDetails {
    param (
        $disk
    )
    if ($null -eq $disk.Name) {
        return $null
    }
    $diskProps = Get-AzDisk -ResourceGroupName $Script:sourceRG -DiskName $disk.Name
    $diskOutput = [PSCustomObject][ordered]@{
        Name             = $disk.Name
        Lun              = $disk.Lun
        Caching          = $disk.Caching
        CreateOption     = $disk.CreateOption
        Sku              = $diskProps.Sku.Name
        SizeGB           = $diskProps.DiskSizeGB
        HyperVGeneration = $diskProps.HyperVGeneration
        Id               = $diskProps.Id
    }
    return $diskOutput
}
function ParseVmList {
    param (
        $VmList,
        [bool]$ConvertToV2
    )

    function CloneObject {
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [pscustomobject]$InputObject
        )
    
        $json = $InputObject | ConvertTo-Json -Depth 100
        $clone = $json | ConvertFrom-Json

        return $clone
    }
    $selectQuery = @(
        "Name"
        "Location"
        "PowerState"
        "LicenseType"
        "Tags"
        "Plan"
        "OSProfile"
        "AvailabilitySetReference"
        @{
            Name       = "VmSize"
            Expression = { $_.HardwareProfile.VmSize } 
        }
        @{
            Name       = "OsDisk"
            Expression = { $_.StorageProfile.OsDisk } 
        }
        @{
            Name       = "DataDisks"
            Expression = { $_.StorageProfile.DataDisks | select name, lun, caching, createOption } 
        }
        @{
            Name       = "NicCount"
            Expression = { $_.NetworkProfile.NetworkInterfaces.count } 
        }
        @{
            Name       = "NicSettings"
            Expression = { 
                $nics = @()
                $i = 0
                foreach ($nic in $_.NetworkProfile.NetworkInterfaces) {
                    $nics += Get-IPSettings -nicId $nic.Id -count $i -vmName $_.Name
                    $i++
                }
                $nics 
            }
        }
        @{
            Name       = "DiagnosticsStorageAccountName"
            Expression = {
                $_.DiagnosticsProfile.BootDiagnostics.StorageUri -replace 'https://(?<stg>.*).blob.core.*', '${stg}'
            }
        },
        "Id"
    )
    $parsedVms = $VmList | Select-Object $selectQuery
    $vmTable = @()
    $i = 0
    foreach ($vm in $parsedVms) {
        $targetDataDisks = @()
        foreach ($disk in $vm.dataDisks) {
            $targetDiskOutput = Get-DataDiskDetails -disk $disk
            $targetDataDisks += $targetDiskOutput
        }
        $osDiskOutput = Get-DataDiskDetails -disk $vm.osDisk
        $sourceOsDisk = $osDiskOutput
        if ($null -ne $osDiskOutput) {
            $targetOsDisk = CloneObject -InputObject $osDiskOutput
        }
        $targetOsDisk.Name = "$($sourceOsDisk.Name)-V2"
        $targetOsDisk.Id = $targetOsDisk.Id -replace "/$($sourceOsDisk.Name)", "/$($targetOsDisk.Name)"
        $targetOsDisk.HyperVGeneration = "V2"
        $nicSettings = $vm.NicSettings

        if ($null -eq $vm.OSProfile.WindowsConfiguration) {
            if ($vm.OsDisk.OsType -ne "Windows") {
                $osType = "Linux"
            }
            else {
                $osType = "Windows"
            }
        }
        else {
            $osType = "Windows"
        }


        $vmTable += [PSCustomObject][ordered]@{
            Name                          = $vm.Name
            Location                      = $vm.Location
            PowerState                    = $vm.PowerState
            LicenseType                   = $vm.LicenseType
            Tags                          = $vm.Tags
            VmSize                        = $vm.VmSize
            Plan                          = $vm.Plan
            OsType                        = $osType
            SourceOsDisk                  = $sourceOsDisk
            TargetOsDisk                  = $targetOsDisk
            TargetDataDisks               = $targetDataDisks
            NicCount                      = $vm.nicCount
            NicSettings                   = $nicSettings
            HasAS                         = $false
            DiagnosticsStorageAccountName = $vm.DiagnosticsStorageAccountName
            Id                            = $vm.Id
        }
        if ($null -ne $vm.AvailabilitySetReference) {
            $asObj = [PSCustomObject][ordered]@{
                id = $vm.AvailabilitySetReference.id
            }
            $vmTable[$i] | Add-Member -MemberType NoteProperty -Name AvailabilitySet -Value $asObj
            $vmTable[$i].hasAS = $true
        }
        $i++
    }

    return $vmTable
}

$ErrorActionPreference = "Stop"
$Script:SourceRG = $ResourceGroupName

$scriptPath = $PSCommandPath
if (-not $PSCommandPath) {
    $scriptPath = ".\Convert-AzVMv1TOv2.ps1"
}

$AvailableGen2Images = [PSCustomObject][ordered]@{
    Server = @(
        [PSCustomObject][ordered]@{
            Name      = "Windows Server 2019 Datacenter"
            Publisher = "MicrosoftWindowsServer"
            Offer     = "WindowsServer"
            Sku       = "2019-datacenter-gensecond"
        }
        [PSCustomObject][ordered]@{
            Name      = "Windows Server 2022 Datacenter"
            Publisher = "MicrosoftWindowsServer"
            Offer     = "WindowsServer"
            Sku       = "2022-datacenter-g2"
        }
    )
    Client = @(
        [PSCustomObject][ordered]@{
            Name      = "Windows 10 Enterprise"
            Publisher = "MicrosoftWindowsDesktop"
            Offer     = "Windows-10"
            Sku       = "win10-22h2-ent-g2"
        }
        [PSCustomObject][ordered]@{
            Name      = "Windows 10 Enterprise for Virtual Desktops"
            Publisher = "MicrosoftWindowsDesktop"
            Offer     = "Windows-10"
            Sku       = "win10-22h2-avd-g2"
        }
    )
}

if (Test-Path $scriptPath) {
    $Script:localPath = Split-Path $scriptPath -Resolve
    $Script:logFileName = "$((Split-Path $scriptPath -Leaf).Replace("ps1","log"))"

    # Connect to Azure      
    if ((Get-AzContext).Subscription.Id -ne $SubscriptionId) {
        Write-Log -message "Connecting to Azure with subscription '$SubscriptionId'"
        Connect-AzAccount -SubscriptionId $SubscriptionId
    }
    else {
        try {
            Get-AzAccessToken -WarningAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Log -message "Connecting to Azure with subscription '$SubscriptionId'"
            Connect-AzAccount -SubscriptionId $SubscriptionId
        }
    }

    $Script:authHeader = @{
        "Authorization" = "Bearer $((Get-AzAccessToken -WarningAction SilentlyContinue).Token)"
        "Content-Type"  = "application/json"
    }

    # Retrieve Gen1 VM details
    $vm = Get-AzVm -ResourceGroupName $ResourceGroupName -Name $VMName
    $fullVMConfig = ParseVmList -VmList $vm -ConvertToV2 $true
    $location = $fullVMConfig.Location
    $tags = $fullVMConfig.Tags
    $vmStatus = Get-AzVm -ResourceGroupName $ResourceGroupName -Name $VMName -Status
    $vmPwr = $vmStatus.Statuses | Where-Object { $_.Code -match "PowerState" }
    if ($vmPwr.Code -notmatch "running") {
        Write-Log -message "The VM '$VMName' is not running. Aborting..."
        exit
    }
    if ($fullVMConfig.OsType -ne "Windows") {
        Write-Log -message "OS Disk is not a 'Windows' OS. Aborting..."
        exit
    }

    # Locate the OS base image
    $vmOsName = $vmStatus.OsName
    if ($vmOsName -match "Server") {
        $osType = "Server"
        $fullOsType = "Windows Server"
        
    }
    else {
        $osType = "Client"
        $fullOsType = "Windows 10"
    }
    $imageReference = $AvailableGen2Images.$osType | Where-Object { $_.Name -eq "$vmOsName" }

    # Manually set the OS base image in case the image could not be determined
    if (!$imageReference) {
        Write-Log "Image reference could not be determined"
        $caption = "Select VM OS Type"
        $message = "Please select the source VM OS type (Server or Client)"
        $choices = [System.Management.Automation.Host.ChoiceDescription[]] @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&Server", "Windows Server"),
            [System.Management.Automation.Host.ChoiceDescription]::new("&Client", "Windows Client")
        )
        $defaultChoice = 0
        $userChoice = $Host.UI.PromptForChoice($caption, $message, $choices, $defaultChoice)
        # Choose by OS type
        switch ($userChoice) {
            0 { 
                $osType = "Server"
                $publisherName = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $availableVersions = @(
                    @{"2019" = "Windows Server 2019" }
                    @{"2022" = "Windows Server 2022" }
                )
                $optionChars = [char[]]('A'..'Z')
                $caption = "Select VM OS Version"
                $message = "Please select the source VM OS version (2012, 2016, 2019 or 2022)"
                
                # Choose by OS version (servers only)
                $avQuery = @(
                    @{
                        Name       = "#"
                        Expression = {
                            ($availableVersions.IndexOf($_) + 1)
                        }
                    }
                    @{
                        Name       = "WindowsVersion"
                        Expression = {
                            $_.Values
                        }
                    }
                )
                
                Write-Host "`nAvailable OS options"
                Write-Host "--------------------"
                $num = 0
                $availableVersions | ForEach-Object {
                    $num++
                    Write-Host "[$num] $($_.Values)"
                }
                Write-Host "[0] Exit"

                # Choose the image SKU to be used for deployment
                $choice = $null
                while ($choice -notin @(0..$num)) {
                    $askChoice = { (Read-Host "`nPlease select the desired OS version") -as [int] }
                    $choice = & $askChoice
                }
                if ($choice -eq 0) {
                    Write-Host "Exiting script..."
                    return
                }
                $osVersion = $availableVersions[$choice - 1].Keys
                
            }
            1 {
                $osType = "Client"
                $publisherName = "MicrosoftWindowsDesktop"
                $offer = "Windows-10"
            }
        }
        
        # Retrieve the available images according to the OS type and version filters
        $availableSkus = Get-AzVMImageSku -Location $location -PublisherName $publisherName -Offer $offer | ? { $_.Skus -match "(\-g2|\-gensecond)" -and $_.Skus -like "*$osVersion*" }
        Write-Host "`nAvailable Gen2 images"
        Write-Host "---------------------"
        $num = 0
        $availableSkus.Skus | ForEach-Object {
            $num++
            Write-Host "[$num] $($_)"
        }
        Write-Host "[0] Exit"

        # Choose the image SKU to be used for deployment
        $choice = $null
        while ($choice -notin @(0..$num)) {
            $askChoice = { (Read-Host "`nPlease select the desired image SKU") -as [int] }
            $choice = & $askChoice
        }
        if ($choice -eq 0) {
            Write-Host "Exiting script..."
            return
        }
        else {
            # Set image reference to the selected SKU
            $imageSku = $availableSkus[$choice - 1]
            $imageReference = $AvailableGen2Images.$osType | Where-Object { $_.Sku -eq "$($imageSku.Skus)" }
            if (!$imageReference) {
                $imageReference = [PSCustomObject][ordered]@{
                    Name      = ("$fullOsType $osVersion").Trim(" ")
                    Publisher = $imageSku.PublisherName
                    Offer     = $imageSku.Offer
                    Sku       = $imageSku.Skus
                }
            }
        }
    }

    # Set disk parameters
    $sourceOsDisk = $fullVMConfig.SourceOsDisk
    $targetOsDisk = $fullVMConfig.TargetOsDisk
    $sourceDiskId = $sourceOsDisk.Id

    if ($sourceOsDisk.HyperVGeneration -like "V2") {
        Write-Log -message "OS Disk is already Gen2. Aborting..."
        return
    }

    # Take backup snapshot
    try {
        $backupSnapshotName = "snapshot-$($sourceOsDisk.Name)-backup"
        Write-Log -message "Creating backup snapshot: $backupSnapshotName"
        $backupSnapshotConfig = New-AzSnapshotConfig -SourceUri $sourceDiskId -CreateOption Copy -Location $location -HyperVGeneration $sourceOsDisk.HyperVGeneration
        $backupSnapshot = New-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $backupSnapshotName -Snapshot $backupSnapshotConfig
        Write-Log -message "Backup snapshot is ready"
    }
    catch {
        Write-Log -message "Failed to create the backup snapshot with error:"
        $_
    }

    # Begin disk MBR to GPT conversion
    Write-Log -message "Staring the OS disk MBR to GPT conversion process"
    $convertRun = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId "RunPowerShellScript" -ScriptString ".`"C:\Windows\system32\MBR2GPT.EXE`" /convert /disk:0 /allowFullOS"
    $convertCompleted = $false

    # Check conversion results
    Write-Log -message "Conversion process is complete. Checking if successfull..."
    if ($convertRun.Value[0].Message -split "`n" -contains "MBR2GPT: Conversion completed successfully") {
        Write-Log -message "Conversion was successfull. The disk is now in GPT mode."
        Write-Log -message "Stopping VM..."
        Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force | Out-Null
        $convertCompleted = $true
    }
    else {
        Write-Log -message "MBR to GPT conversion had failed."
        $convertRun.Value[0].Message
    }

    if ($convertCompleted) {
        # Creating Gen2 snapshot
        $targetDiskName = $targetOsDisk.Name
        try {
            $snapshotName = "snapshot-$($targetDiskName)"
            Write-Log -message "Creating snapshot of converted disk as Gen2: $snapshotName"
            $snapshotConfig = New-AzSnapshotConfig -SourceUri $sourceDiskId -CreateOption Copy -Location $location -HyperVGeneration $targetOsDisk.HyperVGeneration
            $snapshot = New-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotName -Snapshot $snapshotConfig
        }
        catch {
            Write-Log -message "Failed to create the Gen2 snapshot with error:"
            $_
        }

        # Creating Gen2 OS disk from the snapshot
        Write-Log -message "Creating new Gen2 OS disk from the snapshot"
        $diskConfig = New-AzDiskConfig -Location $location -CreateOption Copy -SourceResourceId $snapshot.Id -SkuName $targetOsDisk.Sku -HyperVGeneration $targetOsDisk.HyperVGeneration
        New-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $targetDiskName -Disk $diskConfig | Out-Null

        # Removing Gen1 VM
        Write-Log -message "Removing old VM resource"
        Remove-AzResource -ResourceId $fullVMConfig.Id -Force -Confirm:$false | Out-Null

        # Creating Gen2 VM with source VM parameters
        Write-Log -message "Creating a new Gen2 VM with source VM parameters"
        $psc = New-Object System.Management.Automation.PSCredential($AdminUsername, $AdminPassword)
        $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $fullVMConfig.VmSize -SecurityType Standard
        if ($fullVMConfig.HasAS){
            $vmConfig.AvailabilitySetReference = $fullVMConfig.AvailabilitySet
        }
        $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName $imageReference.Publisher -Offer $imageReference.Offer -Skus $imageReference.Sku -Version "latest"
        $vmConfig = Set-AzVMOSDisk -VM $vmConfig -DiskSizeInGB $targetOsDisk.SizeGB -CreateOption FromImage
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -ComputerName $VMName -Windows -EnableAutoUpdate -Credential $psc
        if (-not ([string]::IsNullOrEmpty($fullVMConfig.DiagnosticsStorageAccountName))) {
            $stgs = Get-AzStorageAccount
            $diagnosticsResults = $stgs | Where-Object { $_.StorageAccountName -eq $fullVMConfig.DiagnosticsStorageAccountName }
            $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig -Enable -StorageAccountName $diagnosticsResults.StorageAccountName -ResourceGroupName $diagnosticsResults.ResourceGroupName
        }
        foreach ($nic in $fullVMConfig.NicSettings) {
            $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
        }
        
        $newVmProps = @{
            VM                = $vmConfig
            ResourceGroupName = $ResourceGroupName
            Location          = $location
            Tag               = $tags
        }
        if ($fullVMConfig.LicenseType) {
            $newVmProps["LicenseType"] = $fullVMConfig.LicenseType
        }
        
        New-AzVM @newVmProps | Out-Null

        # Swapping the OS disk with the snapshot genterated Gen2 disk 
        $targetVm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
        $tmpDiskId = $targetVm.StorageProfile.OsDisk.ManagedDisk.Id
        Write-Log -message "VM '$VMName' was re-created. Deallocating the VM to swap OS disks..."
        Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force | Out-Null
        $targetVm = Set-AzVMOSDisk -VM $targetVm -ManagedDiskId $targetOsDisk.Id -Name $targetDiskName
        foreach ($dataDisk in $fullVMConfig.TargetDataDisks) {
            Write-Log "Adding additional data disk from the source VM: $($dataDisk.Name) | Lun: $($dataDisk.Lun) | Caching: $($dataDisk.Caching)"
            $targetVm = Add-AzVMDataDisk -VM $targetVm -ManagedDiskId $dataDisk.Id -Caching $dataDisk.Caching -Lun $dataDisk.Lun -CreateOption Attach
        }
        # First VM start after swapping the disks
        try {
            Update-AzVM -VM $targetVm -ResourceGroupName $ResourceGroupName | Out-Null
            Write-Log -message "Starting the VM after swapping to converted disk..."
            Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName | Out-Null
        }
        catch {
            Write-Log -message "Failed to swap OS disk. Please review the error:"
            Write-Log -message "$($_ | fl | Out-String)"
            return
        }
        if ($EnableGen2Security) {
            Write-Log -message "Stopping the VM to enable new security features..."
            Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force | Out-Null
            try {
                Update-AzVM -VM $targetVm -ResourceGroupName $ResourceGroupName -SecurityType "TrustedLaunch" -EnableSecureBoot $true -EnableVtpm $true
                Write-Log -message "Starting the VM after enabling security features..."
                Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName | Out-Null
            }
            catch {
                Write-Log -message "Failed to enable security features. Please review the error:"
                Write-Log -message "$($_ | fl | Out-String)"
            }
        }
        # Clean-up process
        $Title = "Do you want to remove the temporary disk and the Gen2 snapshot?"
        $Prompt = "Enter your choice"
        $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
        $Default = 1

        # Prompt for the choice
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)

        switch ($Choice) {
            0 {
                Write-Log -message "Removing the following resources:"
                Write-Log -message "    $tmpDiskId"
                Write-Log -message "    $($snapshot.Id)"
                Remove-AzResource -ResourceId $tmpDiskId -Force -Confirm:$false | Out-Null
                Remove-AzResource -ResourceId $snapshot.Id -Force -Confirm:$false | Out-Null
            }
            1 {
                Write-Log -message "Keeping unused resources resources:"
                Write-Log -message "    $tmpDiskId"
                Write-Log -message "    $($snapshot.Id)"
            }
        }
    }
}
else {
    Write-Error "Script file wasn't found in '$scriptPath'"
}

