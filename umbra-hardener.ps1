# ---------------------------------------------------------------------------------------------------------------------
#
#
# Author: Daechir
# Author URL: https://github.com/daechir
# Modified Date: 03/16/20
# Version: v1
#
#
# ---------------------------------------------------------------------------------------------------------------------
#
#
# Changelog:
#		v1
#			* This marks the beginning of the Umbra Hardener.
#
#
# ---------------------------------------------------------------------------------------------------------------------


function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

function SysCleanup {
	# Bloatware app cleanup
	$apps = @(
		# Microsoft apps
		"Microsoft.3DBuilder"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingMaps"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.BingTravel"
		"Microsoft.BingWeather"
		"Microsoft.CommsPhone"
		"Microsoft.ConnectivityStore"
		"Microsoft.FreshPaint"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.HelpAndTips"
		"Microsoft.Media.PlayReadyClient.2"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftPowerBIForWindows"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.MicrosoftStickyNotes"
		"Microsoft.MinecraftUWP"
		"Microsoft.MixedReality.Portal"
		"Microsoft.MoCamera"
		"Microsoft.MSPaint"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.News"
		"Microsoft.Office.Lens"
		"Microsoft.Office.OneNote"
		"Microsoft.Office.Sway"
		"Microsoft.Office.Todo.List"
		"Microsoft.OfficeLens"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		"Microsoft.Reader"
		"Microsoft.RemoteDesktop"
		"Microsoft.ScreenSketch"
		"Microsoft.SkypeApp"
		"Microsoft.StorePurchaseApp"
		"Microsoft.Todos"
		"Microsoft.Wallet"
		"Microsoft.WebMediaExtensions"
		"Microsoft.Whiteboard"
		"Microsoft.Windows.Photos"
		"Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsReadingList"
		"Microsoft.WindowsScan"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.WinJS.1.0"
		"Microsoft.WinJS.2.0"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGamingOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.YourPhone"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		
		# Microsoft store
		"Microsoft.DesktopAppInstaller"
		"Microsoft.Services.Store.Engagement"
		"Microsoft.StorePurchaseApp"
		"Microsoft.WindowsStore"
		
		# Microsoft.Advertising.Xaml - Called last due to dependency errors
		"Microsoft.Advertising.Xaml" 
		
		# Third party apps
		"2414FC7A.Viber"
		"41038Axilesoft.ACGMediaPlayer"
		"46928bounde.EclipseManager"
		"4DF9E0F8.Netflix"
		"64885BlueEdge.OneCalendar"
		"7EE7776C.LinkedInforWindows"
		"828B5831.HiddenCityMysteryofShadows"
		"89006A2E.AutodeskSketchBook"
		"9E2F88E3.Twitter"
		"A278AB0D.DisneyMagicKingdoms"
		"A278AB0D.DragonManiaLegends"
		"A278AB0D.MarchofEmpires"
		"ActiproSoftwareLLC.562882FEEB491"
		"AD2F1837.GettingStartedwithWindows8"
		"AD2F1837.HPJumpStart"
		"AD2F1837.HPRegistration"
		"AdobeSystemsIncorporated.AdobePhotoshopExpress"
		"Amazon.com.Amazon"
		"C27EB4BA.DropboxOEM"
		"CAF9E577.Plex"
		"CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
		"D52A8D61.FarmVille2CountryEscape"
		"D5EA27B7.Duolingo-LearnLanguagesforFree"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials"
		"DolbyLaboratories.DolbyAccess"
		"Drawboard.DrawboardPDF"
		"E046963F.LenovoCompanion"
		"Facebook.Facebook"
		"Fitbit.FitbitCoach"
		"flaregamesGmbH.RoyalRevolt2"
		"GAMELOFTSA.Asphalt8Airborne"
		"KeeperSecurityInc.Keeper"
		"king.com.BubbleWitch3Saga"
		"king.com.CandyCrushFriends"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"king.com.FarmHeroesSaga"
		"LenovoCorporation.LenovoID"
		"LenovoCorporation.LenovoSettings"
		"Nordcurrent.CookingFever"
		"PandoraMediaInc.29680B314EFC2"
		"PricelinePartnerNetwork.Booking.comBigsavingsonhot"
		"SpotifyAB.SpotifyMusic"
		"ThumbmunkeysLtd.PhototasticCollage"
		"WinZipComputing.WinZipUniversal"
		"XINGAG.XING"
	)
	
    foreach ($app in $apps) {
        Get-AppxPackage -AllUsers -Name $app| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
    }
	
	# Bloatware registry keys cleanup
    $keys = @(
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    foreach ($key in $keys) {
        Remove-Item $key -Recurse
    }
	
	# Bloatware tasks cleanup
    Get-ScheduledTask  "XblGameSaveTask" | Disable-ScheduledTask
    Get-ScheduledTask  "Consolidator" | Disable-ScheduledTask
    Get-ScheduledTask  "UsbCeip" | Disable-ScheduledTask
    Get-ScheduledTask  "DmClient" | Disable-ScheduledTask
    Get-ScheduledTask  "DmClientOnScenarioDownload" | Disable-ScheduledTask
}

function SvcDependency {
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" | Out-Null
	}

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" | Out-Null
	}
		
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" | Out-Null
	}	
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" | Out-Null
	}

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
		
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" | Out-Null
	}

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" | Out-Null
	}
	
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings")) {
		New-Item -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
		New-Item -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
		New-Item -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Personalization\Settings" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Siuf\Rules" | Out-Null
	}

	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
		
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
	}
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}	
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
}

function SvcTweaks {	
	# Disable ActiveX Installer (AxInstSV)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AxInstSV" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Activity History
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -PropertyType DWord -Value 0

	# Disable Adobe Flash
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -PropertyType DWord -Value 0

	# Disable Advertising ID
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -PropertyType DWord -Value 0

	# Disable Alljoyn Router Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AJRouter" -Name "Start" -PropertyType DWord -Value 4

	# Disable Application Suggestions and automatic installation
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -PropertyType DWord -Value 0
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		New-ItemProperty -Force -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
	
	# Disable Audio Video Control Transport Protocol
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Background Apps
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -PropertyType DWord -Value 0
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "Disabled" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path $_.PsPath -Name "DisabledByUser" -PropertyType DWord -Value 1
	}
	
	# Disable BcastDVRUserService
	Get-Service -name "BcastDVRUserService*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "BcastDVRUserService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -PropertyType DWord -Value 2
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -PropertyType DWord -Value 2
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -PropertyType DWord -Value 1
	
	# Disable Biometrics
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc" -Name "Start" -PropertyType DWord -Value 4
		
	# Disable BitLocker Drive Encryption Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BDESVC" -Name "Start" -PropertyType DWord -Value 4
		
	# Disable Bluetooth Services
	Get-Service -name "BluetoothUserService*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "BluetoothUserService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthA2dp" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthEnum" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthHFEnum" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthLEEnum" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthMini" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTHMODEM" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthPan" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTHUSB" -Name "Start" -PropertyType DWord -Value 4
	Get-ScheduledTask  "NotificationTask" | Disable-ScheduledTask
	
	# Disable Capture Service
	Get-Service -name "CaptureService*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "CaptureService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Certificate Propagation
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertPropSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Clipboard History
	Get-Service -name "cbdhsvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "cbdhsvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0

	# Disable Connected Devices Platform
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -PropertyType DWord -Value 4
	Get-Service -name "CDPUserSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "CDPUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable ConsentUX (ConsentUxUserSvc)
	Get-Service -name "ConsentUxUserSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "ConsentUxUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Contact Data (PimIndexMaintenanceSvc)
	Get-Service -name "PimIndexMaintenanceSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "PimIndexMaintenanceSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable Cortana
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Value 0
	
	# Disable Data Usage
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DusmSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Delivery Optimization
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name "Start" -PropertyType DWord -Value 4
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -PropertyType DWord -Value 1
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -PropertyType DWord -Value 1
	} Else {
		# Method used since 1703
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	}
	
	# Disable DevQuery Background Discovery Broker
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevQueryBroker" -Name "Start" -PropertyType DWord -Value 4

	# Disable Developermode
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -ErrorAction SilentlyContinue
	
	# Disable Diagnostic
		# Execution
		Stop-Service "diagsvc" -WarningAction SilentlyContinue
		Set-Service "diagsvc" -StartupType Disabled
		# Policy
		Stop-Service "DPS" -WarningAction SilentlyContinue
		Set-Service "DPS" -StartupType Disabled
		# Service
		Stop-Service "WdiServiceHost" -WarningAction SilentlyContinue
		Set-Service "WdiServiceHost" -StartupType Disabled
		# System
		Stop-Service "WdiSystemHost" -WarningAction SilentlyContinue
		Set-Service "WdiSystemHost" -StartupType Disabled
		# Track
		Stop-Service "DiagTrack" -WarningAction SilentlyContinue
		Set-Service "DiagTrack" -StartupType Disabled
	
	# Disable Embedded Mode
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\embeddedmode" -Name "Start" -PropertyType DWord -Value 4

	# Disable Enterprise App Management Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EntAppSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable fast user switching
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -PropertyType DWord -Value 1
	
	# Disable feedback
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
	
	# Disable File History
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -Name "Start" -PropertyType DWord -Value 4
	Get-ScheduledTask  "File History (maintenance mode)" | Disable-ScheduledTask

	# Disable first logon animation
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 0

	# Disable Geolocation
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Hello Face
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Hello.Face*" } | Remove-WindowsCapability -Online | Out-Null	

	# Disable Hibernation
	New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -PropertyType DWord -Value 0
	powercfg /HIBERNATE OFF 2>&1 | Out-Null
	
	# Disable HV Host
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss" -Name "Start" -PropertyType DWord -Value 4

	# Disable IE
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null

	# Disable Location
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1
	
	# Disable Math Recognizer
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "MathRecognizer*" } | Remove-WindowsCapability -Online | Out-Null
	
	# Disable Messaging Service
	Get-Service -name "MessagingService*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "MessagingService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable Microsoft (R) Diagnostics Hub Standard Collector Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -PropertyType DWord -Value 4

	# Disable Microsoft Account Sign-in Assistant
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount" -Name "value" -PropertyType DWord -Value 0

	# Disable Microsoft Edge
	Get-Process | Where-Object { $_.Name -like "MicrosoftEdg*" } | Stop-Process
	If ((Test-Path "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe")) {
		Rename-Item "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_Disabled"
	}
	If ((Test-Path "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe")) {	
		Rename-Item "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_Disabled"
	}
	
	# Disable Microsoft iSCSI Initiator Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -PropertyType DWord -Value 4

	# Disable Microsoft Storage Spaces SMP
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\smphost" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Microsoft Windows SMS Router Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SmsRouter" -Name "Start" -PropertyType DWord -Value 4

	# Disable .NET Framework 2.0, 3.0 and 3.5 runtimes
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Disable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	}
	
	# Disable Offline Maps
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -PropertyType DWord -Value 4
	Get-ScheduledTask  "MapsToastTask" | Disable-ScheduledTask
	Get-ScheduledTask  "MapsUpdateTask" | Disable-ScheduledTask
	
	# Disable Optimize Drives
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable OneDrive
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -PropertyType DWord -Value 1
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	}
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	
	# Disable Parental Controls
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpcMonSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Payments and NFC/SE Manager
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SEMgrSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Performance Counter DLL Host
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PerfHost" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Performance Logs & Alerts
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\pla" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Phone Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\autotimesvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TapiSrv" -Name "Start" -PropertyType DWord -Value 4

	# Disable Portable Device Enumerator Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WPDBusEnum" -Name "Start" -PropertyType DWord -Value 4

	# Disable Program Compatibility Assistant Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Problem Reports and Solutions Control Panel Support
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Quality Windows Audio Video Experience
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVEdrv" -Name "Start" -PropertyType DWord -Value 4

	# Disable Quick Assist
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null

	# Disable Retail Demo
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RetailDemo" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Remote Procedure Call (RPC) Locator
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Remote Registry
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Sensors
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -PropertyType DWord -Value 1
	
	# Disable Secondary Logon 
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Shared PC Account Manager
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\shpamsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Smart Card Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCardSvr" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Sleep
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -PropertyType DWord -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
	
	# Disable Sync Host (OneSyncSvc)
	Get-Service -name "OneSyncSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "OneSyncSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Tailored Experiences
	New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1
	
	# Disable Telemetry
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -PropertyType DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

	# Disable Touch Keyboard and Handwriting Panel Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable User Data Access (UserDataSvc)
	Get-Service -name "UserDataSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "UserDataSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable User Data Storage (UnistoreSvc)
	Get-Service -name "UnistoreSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "UnistoreSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable User Tracking
	New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -PropertyType DWord -Value 1
	
	# Disable Volumetric Audio Compositor Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VacSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Wallet Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WalletService" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable WarpJITSvc 
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WarpJITSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Web Account Manager
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TokenBroker" -Name "Start" -PropertyType DWord -Value 4

	# Disable Web Client
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name "Start" -PropertyType DWord -Value 4

	# Disable Web Lang
	New-ItemProperty -Force -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -PropertyType DWord -Value 1
	
	# Disable Web Search in Start Menu
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 1

	# Disable Windows Camera Frame Server
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServer" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Error Reporting Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1
	Get-ScheduledTask  "QueueReporting" | Disable-ScheduledTask
	
	# Disable Windows Event Collector
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Windows Insider Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wisvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Legacy Components
	Disable-WindowsOptionalFeature -Online -FeatureName "LegacyComponents" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
	# Disable Windows Linux Subsystem
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
	# Disable Windows Media player
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -PropertyType DWord -Value 1
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MediaPlayback" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
	
	# Disable Windows Powershell v2
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else { 
		Uninstall-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
	}
	
	# Disable Windows Print Bloat
	Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-LPDPrintService" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-LPRPortMonitor" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
		
	# Disable Windows Restore Points
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -PropertyType DWord -Value 1
	vssadmin Delete Shadows /For=$env:SYSTEMDRIVE /Quiet
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wbengine" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swprv" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SDRSVC" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Windows Script Host
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings" -Name "Enabled" -PropertyType DWord -Value 0
	
	# Disable Windows Storage Sense
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
	Get-ScheduledTask  "StorageSense" | Disable-ScheduledTask
	
	# Disable Windows Wifi Sense
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -PropertyType DWord -Value 0
	
	# Disable Xbox Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\xboxgip" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Enable DEP for All Processes
	bcdedit.exe /set `{current`} nx AlwaysOn
	
	# Enable Explorer Tweaks
		# Disable Recent Documents
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1
		
		# Disable Autoplay
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ShellHWDetection" -Name "Start" -PropertyType DWord -Value 4
		
		# Disable Autorun
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255
		
		# Enable long NTFS paths
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -PropertyType DWord -Value 1
		
		# Disable NTFS last access
		fsutil behavior set DisableLastAccess 1 | Out-Null
	
	# Enable .Net Strong Cryptopgraphy
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1
	
	# Enable Page File wipe on shutdown
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -PropertyType DWord -Value 1
	
	# Enable Windows Defender Tweaks
		# Enable CFA
		Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
		
		# Enable CIM	
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -PropertyType DWord -Value 1
		
		# Hide Account Protection warning in Defender about not using a Microsoft account	
		New-ItemProperty -Force "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1

	# Enable Windows Update Tweaks
		# Disable automatic downloads
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Value 2
		
		# Disable automatic restart
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -PropertyType String -Value "cmd.exe"
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -PropertyType DWord -Value 1

		# Disable nightly wake-up for Automatic Maintenance and Windows Updates
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -PropertyType DWord -Value 0
}

function NetworkTweaks {
	# Disable automatic install of network devices
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Connection Sharing
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ALG" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Data Sharing Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DsSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Device Association
	Get-Service -name "DeviceAssociationBrokerSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DeviceAssociationBrokerSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" -Name "Start" -PropertyType DWord -Value 4

	# Disable Device Picker
	Get-Service -name "DevicePickerUserSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DevicePickerUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable Device Flow
	Get-Service -name "DevicesFlowUserSvc*" | Stop-Service -WarningAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DevicesFlowUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	
	# Disable Device Management 
		# Enrollment
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" -Name "Start" -PropertyType DWord -Value 4
		# Wireless Application Protocol
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Distributed Link
		# Tracking Client
		Stop-Service "TrkWks" -WarningAction SilentlyContinue
		Set-Service "TrkWks" -StartupType Disabled
		# Transaction Coordinator
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSDTC" -Name "Start" -PropertyType DWord -Value 4
		# KtmRm for Distributed Transaction Coordinator
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KtmRm" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable DNS settings on adapters
		# Append parent suffixes
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0
	
		# Register this connections address in DNS
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" -Recurse -ErrorAction SilentlyContinue
		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
			New-ItemProperty -Force -Path $_.PsPath -Name "RegistrationEnabled" -PropertyType DWord -Value 0
		}
		
	# Disable Extensible Authentication Protocol
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eaphost" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Function Discovery Provider Host
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Homegroup
	If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
		Set-Service "HomeGroupListener" -StartupType Disabled
	}
	
	If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
		Set-Service "HomeGroupProvider" -StartupType Disabled
	}
	
	# Disable Ipv6
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value "0xFFFFFFFF"
	
	# Disable IP Helper
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable IP Translation
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable IPsec 
		# IKE and AuthIP IPsec Keying Modules
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT" -Name "Start" -PropertyType DWord -Value 4
		# Policy Agent
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "Start" -PropertyType DWord -Value 4

	# Disable Link-Layer Topology Discovery Mapper
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable LLMNR	
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0
	
	# Disable LLDP
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"

	# Disable LLTD
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
	
	# Disable Microsoft Virtual Wi-Fi Adapter
	netsh wlan stop hostednetwork
	netsh wlan set hostednetwork mode=disallow
	Get-NetAdapter -InterfaceDescription "Microsoft Wi-Fi Direct Virtual*" | Disable-NetAdapter -Confirm:$false
	
	# Disable MS Net Client
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"

	# Disable Natural Authentication
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Network Connection Broker
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcbService" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable NetBIOS
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "NetbiosOptions" -PropertyType DWord -Value 2
	}
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBIOS" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT" -Name "Start" -PropertyType DWord -Value 4

	# Disable Net Logon
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Net TCP Port Sharing
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" -Name "Start" -PropertyType DWord -Value 4

	# Disable NCSI Probe
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -PropertyType DWord -Value 1	
	
	# Disable Peer Networking Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable power management option on adapters 
	foreach ($NIC in (Get-NetAdapter -Physical)){
		$PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | ? {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
		if ($PowerSaving.Enable){
			$PowerSaving.Enable = $false
			$PowerSaving | Set-CimInstance
		}
	}
	
	# Disable projecting to this PC
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "AllowProjectionToPC" -PropertyType DWord -Value 0

	# Disable QoS
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
	
	# Disable Remote Services
		# Access Connection Manager
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan" -Name "Start" -PropertyType DWord -Value 4
		
		# Access Auto Connection Manager
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -PropertyType DWord -Value 4
		
		# Assistance
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0
		Get-ScheduledTask  "RemoteAssistanceTask" | Disable-ScheduledTask
		
		# Desktop
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -PropertyType DWord -Value 4
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -PropertyType DWord -Value 4
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -PropertyType DWord -Value 4
		
		# Routing and remote access
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -PropertyType DWord -Value 4
		
		# SMB Server
		Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
		Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
		Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
		Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
		Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
		Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -WarningAction SilentlyContinue | Out-Null
		Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Deprecation" -NoRestart -WarningAction SilentlyContinue | Out-Null
		
		# Windows Remote Management (WS-Management)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Remote Differential Compression API Support 
	Disable-WindowsOptionalFeature -Online -FeatureName "MSRDC-Infrastructure" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
	# Disable Shared Experiences
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "EnableCdp" -PropertyType DWord -Value 0
	
	# Disable SNMP Trap
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTRAP" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable SSDP Discovery
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable SSTP
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable SSH
		# Client
		Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" } | Remove-WindowsCapability -Online | Out-Null
		# Server
		Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Remove-WindowsCapability -Online | Out-Null
		
	# Disable UPnP Device Host
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -PropertyType DWord -Value 4
	Get-ScheduledTask  "UPnPHostConfig" | Disable-ScheduledTask
	
	# Disable VPN
		# Over a Metered Connection 
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" -Name "NoCostedNetwork" -PropertyType DWord -Value 1
		# Over a Roaming Connection
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" -Name "NoRoamingNetwork" -PropertyType DWord -Value 1
		# Tasks
		Get-ScheduledTask  "MobilityManager" | Disable-ScheduledTask
		
	# Disable Workstation & Server
		# Admin Shares (Also known as Hidden Shares)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -PropertyType DWord -Value 0
		
		# Anonymous user access
		New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -PropertyType DWord -Value 2
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -PropertyType DWord -Value 1
		
		# Login password storage on disk
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -PropertyType DWord -Value 5
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -PropertyType DWord -Value 1
		
		# Mapped Drives
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
		
		# Server Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "Start" -PropertyType DWord -Value 4
		
		# Workstation Feature & Service
		Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Wi-Fi Direct Services Connection Manager Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Windows Connect Now - Config Registrar
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wcncsvc" -Name "Start" -PropertyType DWord -Value 4
	
	# Disable Windows Mobile Hotspot Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache" -Name "OsuRegistrationStatus" -PropertyType DWord -Value 0
	Get-ScheduledTask  "MNO Metadata Parser" | Disable-ScheduledTask
	
	# Disable WWAN AutoConfig
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WwanSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlpasvc" -Name "Start" -PropertyType DWord -Value 4
	Get-ScheduledTask  "NotificationTask" | Disable-ScheduledTask
	
	# Harden Windows Firewall
		# Remove all pre-existing firewall rules
		netsh advfirewall firewall delete rule name=all

		# Change all firewall profiles to:
		# Block inbound & outbound unless specified
		# Disable notifications
		# Disable unicast responses
		# Disable all logging
		Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen False -AllowUnicastResponseToMulticast False -LogAllowed False -LogBlocked False -LogIgnored False

	# Set current network profile to public
	Set-NetConnectionProfile -NetworkCategory Public

	# Set unknown network profiles to public
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

function UITweak {
	# Disable Action Center
	New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -PropertyType DWord -Value 0
	
	# Disable Accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122"
	
	# Disable default pins
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			New-ItemProperty -Force -Path "$($_.PsPath)\Current" -Name "Data" -PropertyType Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		New-ItemProperty -Force -Path $key.PSPath -Name "Data" -PropertyType Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
	
	# Disable Explorer
		# 3D Access shortcuts
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide"
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide"

		# Give access to menu
		Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
		Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
		Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
		Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
		
		# Include in library menu
		Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue
		
		# Quickaccess menu
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -PropertyType DWord -Value 1
		
		# Recent shortcuts
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -PropertyType DWord -Value 0
		
		# Share menu
		Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue
		
		# Sharing Wizard
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -PropertyType DWord -Value 0
	
		# Sync Notifications
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWord -Value 0
		
		# Thumbnail cache
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1
		
	# Disable F1 help key
	New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -PropertyType "String" -Value ""
	New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType "String" -Value ""
	
	# Disable Lock Screen
		# Blur
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -PropertyType DWord -Value 1
		
		# Network Options
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1
		
		# Shutdown Options
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -PropertyType DWord -Value 0
		
	# Disable new app prompt
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -PropertyType DWord -Value 1
		
	# Disable search in store
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -PropertyType DWord -Value 1
	
	# Disable adding '- shortcut' to shortcut name
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -PropertyType Binary -Value ([byte[]](0,0,0,0))
	
	# Disable Taskbar 
		# People
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value 0
		
		# Search
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value 0
		
		# Taskview
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value 0
	
	# Enable Build #
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -PropertyType DWord -Value 1
	
	# Enable Control Panel 
		# On Desktop
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0

		# Small icons
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -PropertyType DWord -Value 1
	
	# Enable Explorer 
		# Expanded Nav Panel
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -PropertyType DWord -Value 1

		# File operation details
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1
	
		# Hidden files
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWord -Value 1
		
		# Known Extensions
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0
	
	# Enable Smallicons
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -PropertyType DWord -Value 1
	
	# Enable Taskbar combine when full
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -PropertyType DWord -Value 1
	
	# Enable Task Manager details
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	$timeout = 30000
	$sleep = 100
	Do {
		Start-Sleep -Milliseconds $sleep
		$timeout -= $sleep
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences -or $timeout -le 0)
	Stop-Process $taskmgr
	If ($preferences) {
		$preferences.Preferences[28] = 0
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -PropertyType Binary -Value $preferences.Preferences
	}
	
	# Enable Tray icons
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -PropertyType DWord -Value 1

	# Enable Visual FX Performance
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -PropertyType String -Value 0
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -PropertyType String -Value 0
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -PropertyType Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -PropertyType String -Value 0
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -PropertyType DWord -Value 3
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -PropertyType DWord -Value 0
}

function MiscTweak {
	# Enable F8 Bootmenu
	bcdedit.exe /set `{current`} BootMenuPolicy Legacy
}

function WaitForReboot {
	Write-Output "`nPress any key to restart..."
	[Console]::ReadKey($true) | Out-Null
}

function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}


RequireAdmin
SysCleanup
SvcDependency
UITweak
SvcTweaks
NetworkTweaks
MiscTweak
WaitForReboot
Restart

