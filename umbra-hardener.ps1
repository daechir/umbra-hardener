# ---------------------------------------------------------------------------------------------------------------------
#
#
# Author: Daechir
# Author URL: https://github.com/daechir
# Modified Date: 06/05/20
# Version: v3
#
#
# ---------------------------------------------------------------------------------------------------------------------
#
#
# Changelog:
#		v3
#			* Added the following:
#				* Numerous SysCleanup items.
#				* Logging functions CreateLog & StopLog.
#			* Overhauled the following:
#				* SvcDependency, moved to arr format to reduce redundancies.
#			* Removed the following:
#				* Deprecated SysCleanup items.
#		v2
#			* Overhauled the following:
#				* SysCleanup bloat reg keys removed.
#					* It's far more efficient to use an auto reg cleaner to address these instead, like CCleaner.
#				* WindowsCapability and WindowsOptionalFeature, moved to SysCleanup in arr format.
#				* ScheduledTask, moved to SysCleanup in arr format.
#				* SvcTweaks should now only include random non-essential features or services.
#				* NetworkTweaks should now only include network related features or services.
#					* Note: Some items, while they have networking concepts (Activity History, Telemetry, Cortana, etc), aren't considered Networking Tweaks
#							because they have very little do with hardening or disabling attack sectors of the network stack.
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

function CreateLog ($logname,$functionname) {
	$logfile = $PSScriptRoot + "\logs\" + $logname
	$functionname = "Now logging for function: " + $functionname + "`n`n"

	New-Item -Force $logfile

	Add-Content -Path $logfile -Value $functionname

	Start-Transcript -Path $logfile -Append
}

function StopLog {
	Stop-Transcript
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

	write "`n ***** Now removing Appx*Package ***** `n"

    foreach ($app in $apps) {
		write "`n $app `n"
        Get-AppxPackage -AllUsers -Name $app| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
    }

	# Bloatware features
	# First round, optional WindowsCapability features
	$features_1 = @(
		"App.StepsRecorder*"
		"App.Support.QuickAssist*"
		"Browser.InternetExplorer*"
		"Hello.Face*"
		"MathRecognizer*"
		"Media.WindowsMediaPlayer*"
		"Microsoft.Windows.MSPaint*"
		"Microsoft.Windows.Notepad*"
		"Microsoft.Windows.WordPad*"
		"OneCoreUAP.OneSync*"
		"OpenSSH.Client*"
		"OpenSSH.Server*"
		"Print.Fax.Scan*"
	)

	write "`n ***** Now removing WindowsCapability features ***** `n"

    foreach ($feature in $features_1) {
		write "`n $feature `n"
		Get-WindowsCapability -Online | Where-Object { $_.Name -like $feature } | Remove-WindowsCapability -Online | Out-Null
    }

	# Second round, optional WindowsFeature
	$features_2 = @(
		"FaxServicesClientPackage"
		"LegacyComponents"
		"MediaPlayback"
		"MicrosoftWindowsPowerShellV2Root"
		"Microsoft-Windows-Subsystem-Linux"
		"MSRDC-Infrastructure"
		"NetFx3"
		"Printing-Foundation-Features"
		"Printing-Foundation-InternetPrinting-Client"
		"Printing-Foundation-LPDPrintService"
		"Printing-Foundation-LPRPortMonitor"
		"Printing-PrintToPDFServices-Features"
		"Printing-XPSServices-Features"
		"SMB1Protocol"
		"SMB1Protocol-Client"
		"SMB1Protocol-Deprecation"
		"SMB1Protocol-Server"
		"WindowsMediaPlayer"
		"WorkFolders-Client"
	)

	write "`n ***** Now disabling WindowsOptionalFeature ***** `n"

	foreach ($feature in $features_2) {
		write "`n $feature `n"
		Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction SilentlyContinue | Out-Null
	}

	# Bloatware tasks cleanup
	$tasks = @(
		"CDSSync"
		"Consolidator"
		"CreateObjectTask"
		"DmClient"
		"DmClientOnScenarioDownload"
		"FamilySafetyMonitor"
		"FamilySafetyRefreshTask"
		"File History (maintenance mode)"
		"FODCleanupTask"
		"MapsToastTask"
		"MapsUpdateTask"
		"Microsoft-Windows-DiskDiagnosticDataCollector"
		"Microsoft Compatibility Appraiser"
		"MNO Metadata Parser"
		"MobilityManager"
		"NetworkStateChangeTask"
		"Notifications"
		"NotificationTask"
		"OobeDiscovery"
		"ProgramDataUpdater"
		"Proxy"
		"QueueReporting"
		"ReconcileFeatures"
		"RefreshCache"
		"RemoteAssistanceTask"
		"SR"
		"StorageSense"
		"Storage Tiers Management*"
		"UPnPHostConfig"
		"UsageDataFlushing"
		"UsageDataReporting"
		"UsbCeip"
		"WindowsActionDialog"
		"WinSAT"
		"XblGameSaveTask"
	)

	write "`n ***** Now disabling ScheduledTask ***** `n"

    foreach ($task in $tasks) {
		write "`n $task `n"
		Get-ScheduledTask -TaskName $task | Disable-ScheduledTask
    }

	# Lastly bloatware apps or programs that can't be removed by normal means because Microsoft marked them as "non-removable"
	# First round, C:\Windows\SystemApps\
	$paths = @(
		"C:\Windows\SystemApps\Microsoft.AsyncTextService_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.BioEnrollment_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy"
		"C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy"
		"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy"
		"C:\Windows\SystemApps\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy"
		"C:\Windows\SystemApps\NcsiUwpApp_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy"
	)

    foreach ($path in $paths) {
		$FirstString = -join ((48..57) + (97..122) | Get-Random -Count 16 | % {[char]$_})

		If ((Test-Path "$path")) {
			If ("$path" -like "MicrosoftEdg*") {
				Get-Process | Where-Object { $_.Name -like "MicrosoftEdg*" } | Stop-Process
			}

			Rename-Item "$path" "C:\Windows\SystemApps\$FirstString"
		}
    }

	# Second round, user specified
	$SecondString = -join ((48..57) + (97..122) | Get-Random -Count 16 | % {[char]$_})

	# Disable Internet Explorer
	If ((Test-Path "C:\Program Files\Internet Explorer")) {
		Rename-Item "C:\Program Files\Internet Explorer" "C:\Program Files\$SecondString"
	}
	If ((Test-Path "C:\Program Files (x86)\Internet Explorer")) {
		Rename-Item "C:\Program Files (x86)\Internet Explorer" "C:\Program Files (x86)\$SecondString"
	}
}

function SvcDependency {
	$dependencies = @(
		"HKCU:\SOFTWARE\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee\1.0\0\win32"
		"HKCU:\SOFTWARE\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee\1.0\0\win64"
		"HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
		"HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
		"HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
		"HKCU:\SOFTWARE\Microsoft\Windows Script\Settings"
		"HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
		"HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
		"HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
		"HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
		"HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
		"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe"
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722\PropertyBag"
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"
		"HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"
		"HKLM:\SOFTWARE\Policies\Microsoft\Biometrics"
		"HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
		"HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
		"HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons"
		"HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
		"HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
		"HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
		"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
		"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722\PropertyBag"
		"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
		"HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings"
	)

	foreach ($dependency in $dependencies) {
		If (!(Test-Path "$dependency")) {
			New-Item -Force -Path "$dependency" | Out-Null
		}
	}
}

function SvcTweaks {
	# Disable ActiveX Installer Service (AxInstSV)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AxInstSV" -Name "Start" -PropertyType DWord -Value 4

	# Disable Activity History Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -PropertyType DWord -Value 0

	# Disable Advertising ID Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -PropertyType DWord -Value 0

	# Disable Application Suggestions and Automatic Installation Feature
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

	# Disable AVCTP Service (BthAvctpSvc)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Background Apps Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -PropertyType DWord -Value 0
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "Disabled" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path $_.PsPath -Name "DisabledByUser" -PropertyType DWord -Value 1
	}

	# Disable Biometric Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable BitLocker Drive Encryption Service (BDESVC)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BDESVC" -Name "Start" -PropertyType DWord -Value 4

	# Disable Capture Service
	Get-Service -Name "CaptureService*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "CaptureService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Clipboard History Feature
	Get-Service -Name "cbdhsvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "cbdhsvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0

	# Disable Connected User Experiences and Telemetry Service (DiagTrack)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -PropertyType DWord -Value 4

	# Disable ConsentUX Service (ConsentUxUserSvc)
	Get-Service -Name "ConsentUxUserSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "ConsentUxUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Contact Data Service (PimIndexMaintenanceSvc)
	Get-Service -Name "PimIndexMaintenanceSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "PimIndexMaintenanceSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Cortana Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Value 0

	# Disable Diagnostic
		# Execution Service
		Get-Service -Name "diagsvc" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "diagsvc" -StartupType Disabled
		# Policy Service
		Get-Service -Name "DPS" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "DPS" -StartupType Disabled
		# Service Host
		Get-Service -Name "WdiServiceHost" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "WdiServiceHost" -StartupType Disabled
		# System Host
		Get-Service -Name "WdiSystemHost" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "WdiSystemHost" -StartupType Disabled

	# Disable Embedded Mode Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\embeddedmode" -Name "Start" -PropertyType DWord -Value 4

	# Disable Enterprise App Management Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EntAppSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Fast User Switching Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -PropertyType DWord -Value 1

	# Disable Feedback Notifications Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1

	# Disable File History Feature
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable GameDVR and Broadcast Service (BcastDVRUserService)
	Get-Service -Name "BcastDVRUserService*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "BcastDVRUserService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -PropertyType DWord -Value 2
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -PropertyType DWord -Value 2
	New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -PropertyType DWord -Value 1

	# Disable Geolocation Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Hibernation Feature
	New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -PropertyType DWord -Value 0
	powercfg /HIBERNATE OFF 2>&1 | Out-Null

	# Disable Hyper-V Hypervisor Services (HvHost)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HvHost" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvmsession" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss" -Name "Start" -PropertyType DWord -Value 4

	# Disable Location Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1

	# Disable Messaging Service
	Get-Service -Name "MessagingService*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "MessagingService*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Microsoft (R) Diagnostics Hub Standard Collector Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -PropertyType DWord -Value 4

	# Disable Microsoft Account Sign-in Assistant Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount" -Name "value" -PropertyType DWord -Value 0

	# Disable Microsoft iSCSI Initiator Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -PropertyType DWord -Value 4

	# Disable Microsoft Storage Spaces SMP Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\smphost" -Name "Start" -PropertyType DWord -Value 4

	# Disable Microsoft Windows SMS Router Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SmsRouter" -Name "Start" -PropertyType DWord -Value 4

	# Disable Offline Maps Feature
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -PropertyType DWord -Value 4

	# Disable Optimize Drives Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable OneDrive Feature
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

	# Disable Parental Controls Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpcMonSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Payments and NFC/SE Manager Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SEMgrSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Performance Counter DLL Host Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PerfHost" -Name "Start" -PropertyType DWord -Value 4

	# Disable Performance Logs & Alerts Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\pla" -Name "Start" -PropertyType DWord -Value 4

	# Disable Phone Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\autotimesvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TapiSrv" -Name "Start" -PropertyType DWord -Value 4

	# Disable Portable Device Enumerator Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WPDBusEnum" -Name "Start" -PropertyType DWord -Value 4

	# Disable Program Compatibility Assistant Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Problem Reports and Solutions Control Panel Support Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -PropertyType DWord -Value 4

	# Disable Quality Windows Audio Video Experience Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVE" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\QWAVEdrv" -Name "Start" -PropertyType DWord -Value 4

	# Disable Retail Demo Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RetailDemo" -Name "Start" -PropertyType DWord -Value 4

	# Disable Remote Procedure Call (RPC) Locator Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -PropertyType DWord -Value 4

	# Disable Remote Registry Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -PropertyType DWord -Value 4

	# Disable Sensors Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -PropertyType DWord -Value 1

	# Disable Secondary Logon Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon" -Name "Start" -PropertyType DWord -Value 4

	# Disable Shared PC Account Manager Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\shpamsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Smart Card Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertPropSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCardSvr" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCPolicySvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Sleep Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -PropertyType DWord -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0

	# Disable Sync Host Service (OneSyncSvc)
	Get-Service -Name "OneSyncSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "OneSyncSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Tailored Experiences Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1

	# Disable Telemetry Feature
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

	# Disable Touch Keyboard and Handwriting Panel Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService" -Name "Start" -PropertyType DWord -Value 4

	# Disable User Data Access Service (UserDataSvc)
	Get-Service -Name "UserDataSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "UserDataSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable User Data Storage Service (UnistoreSvc)
	Get-Service -Name "UnistoreSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "UnistoreSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable User Tracking Feature
	New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -PropertyType DWord -Value 1
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -PropertyType DWord -Value 1

	# Disable Volumetric Audio Compositor Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VacSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Wallet Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WalletService" -Name "Start" -PropertyType DWord -Value 4

	# Disable WarpJITSvc Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WarpJITSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Web Account Manager Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TokenBroker" -Name "Start" -PropertyType DWord -Value 4

	# Disable Web Client Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name "Start" -PropertyType DWord -Value 4

	# Disable Web Lang Service
	New-ItemProperty -Force -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -PropertyType DWord -Value 1

	# Disable Web Search in Start Menu Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 1

	# Disable Windows Camera Frame Server Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FrameServer" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Error Reporting Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1

	# Disable Windows Event Collector Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Insider Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wisvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Restore Point Feature
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -PropertyType DWord -Value 1
	vssadmin Delete Shadows /For=$env:SYSTEMDRIVE /Quiet
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wbengine" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swprv" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SDRSVC" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Script Host Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings" -Name "Enabled" -PropertyType DWord -Value 0

	# Disable Windows Storage Sense Feature
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

	# Disable Windows Wifi Sense Feature
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -PropertyType DWord -Value 0

	# Disable Windows Update
		# Automatic Downloads
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Value 2
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWord -Value 1

		# Automatic Restart
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -PropertyType String -Value "cmd.exe"
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -PropertyType DWord -Value 1

		# Background Intelligent Transfer Service (BITS)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -Name "Start" -PropertyType DWord -Value 4

		# Delivery Optimization (DoSvc)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name "Start" -PropertyType DWord -Value 4
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -PropertyType DWord -Value 100

		# Microsoft Store Install Service (InstallService)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\InstallService" -Name "Start" -PropertyType DWord -Value 4

		# Nightly wake-up for Automatic Maintenance and Windows Updates
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -PropertyType DWord -Value 0

		# Update Orchestrator Service (UsoSvc)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name "Start" -PropertyType DWord -Value 4

		# Windows License Manager Service (LicenseManager)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager" -Name "Start" -PropertyType DWord -Value 4

		# Windows Modules Installer (TrustedInstaller)
		Get-Service -Name "TrustedInstaller" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "TrustedInstaller" -StartupType Disabled

		# Windows Update (wuauserv)
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -PropertyType DWord -Value 4

		# Windows Update Medic Service (WaaSMedicSvc)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Xbox Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\xboxgip" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" -Name "Start" -PropertyType DWord -Value 4

	# Enable DEP for All Processes
	bcdedit.exe /set `{current`} nx AlwaysOn

	# Enable Explorer.exe
		# Disable Autoplay
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ShellHWDetection" -Name "Start" -PropertyType DWord -Value 4

		# Disable Autorun
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255

		# Disable NTFS last access
		fsutil behavior set DisableLastAccess 1 | Out-Null

		# Disable Recent Documents
		New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1

		# Enable long NTFS paths
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -PropertyType DWord -Value 1

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
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1
}

function NetworkTweaks {
	# Disable Alljoyn Router Service (AJRouter)
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AJRouter" -Name "Start" -PropertyType DWord -Value 4

	# Disable Automatic Installation of Network Devices (Drivers, Printers, w/e)
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" -Name "Start" -PropertyType DWord -Value 4

	# Disable Bluetooth Services
	Get-Service -Name "BluetoothUserService*" | Stop-Service -Force -ErrorAction SilentlyContinue
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

	# Disable Connection Sharing Feature
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ALG" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Connected Devices Platform Service
	# Note: This service is heavily undocumented but appears to be used with bluetooth, network devices, etc
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -PropertyType DWord -Value 4
	Get-Service -Name "CDPUserSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "CDPUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Data Sharing Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DsSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Data Usage Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DusmSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Device Association Service
	Get-Service -Name "DeviceAssociationBrokerSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DeviceAssociationBrokerSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" -Name "Start" -PropertyType DWord -Value 4

	# Disable DevQuery Background Discovery Broker Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DevQueryBroker" -Name "Start" -PropertyType DWord -Value 4

	# Disable Device Picker Service
	Get-Service -Name "DevicePickerUserSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DevicePickerUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Device Flow Service
	Get-Service -Name "DevicesFlowUserSvc*" | Stop-Service -Force -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse -Include "DevicesFlowUserSvc*" -ErrorAction SilentlyContinue | New-ItemProperty -Force -Name "Start" -PropertyType DWord -Value 4 | Out-Null

	# Disable Device Management
		# Enrollment Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" -Name "Start" -PropertyType DWord -Value 4
		# Wireless Application Protocol Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -PropertyType DWord -Value 4

	# Disable Distributed Link
		# Tracking Client Service
		Get-Service -Name "TrkWks" | Stop-Service -Force -ErrorAction SilentlyContinue
		Set-Service "TrkWks" -StartupType Disabled
		# Transaction Coordinator Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSDTC" -Name "Start" -PropertyType DWord -Value 4
		# KtmRm for Distributed Transaction Coordinator Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KtmRm" -Name "Start" -PropertyType DWord -Value 4

	# Disable DNS settings on adapters
		# Append parent suffixes
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0

		# Register this connections address in DNS
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" -Recurse -ErrorAction SilentlyContinue
		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
			New-ItemProperty -Force -Path $_.PsPath -Name "RegistrationEnabled" -PropertyType DWord -Value 0
		}

	# Disable Extensible Authentication Protocol Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eaphost" -Name "Start" -PropertyType DWord -Value 4

	# Disable Function Discovery Provider Host Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub" -Name "Start" -PropertyType DWord -Value 4

	# Disable Ipv6
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value "0xFFFFFFFF"

	# Disable IP Helper Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable IP Translation Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable IPsec
		# IKE and AuthIP IPsec Keying Modules Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT" -Name "Start" -PropertyType DWord -Value 4
		# Policy Agent Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "Start" -PropertyType DWord -Value 4

	# Disable Link-Layer Topology Discovery Mapper Service
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

	# Disable Natural Authentication Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" -Name "Start" -PropertyType DWord -Value 4

	# Disable Network Connection Broker Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcbService" -Name "Start" -PropertyType DWord -Value 4

	# Disable NetBIOS
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "NetbiosOptions" -PropertyType DWord -Value 2
	}
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBIOS" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT" -Name "Start" -PropertyType DWord -Value 4

	# Disable Net Logon Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "Start" -PropertyType DWord -Value 4

	# Disable Net TCP Port Sharing Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" -Name "Start" -PropertyType DWord -Value 4

	# Disable NCSI Probe
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -PropertyType DWord -Value 1

	# Disable Peer Networking Services
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Power Management Option on Adapters
	foreach ($NIC in (Get-NetAdapter -Physical)){
		$PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | ? {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
		if ($PowerSaving.Enable){
			$PowerSaving.Enable = $false
			$PowerSaving | Set-CimInstance
		}
	}

	# Disable Projecting to This PC Feature
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

		# Desktop
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -PropertyType DWord -Value 4
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -PropertyType DWord -Value 4
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -PropertyType DWord -Value 4

		# Routing and Remote Access
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -PropertyType DWord -Value 4

		# SMB Server
		Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"

		# Windows Remote Management (WS-Management)
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -PropertyType DWord -Value 4

	# Disable Shared Experiences Feature
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "EnableCdp" -PropertyType DWord -Value 0

	# Disable SNMP Trap Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMPTRAP" -Name "Start" -PropertyType DWord -Value 4

	# Disable SSDP Discovery Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -PropertyType DWord -Value 4

	# Disable SSTP Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable UPnP Device Host Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -PropertyType DWord -Value 4

	# Disable VPN
		# Over a Metered Connection
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" -Name "NoCostedNetwork" -PropertyType DWord -Value 1
		# Over a Roaming Connection
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" -Name "NoRoamingNetwork" -PropertyType DWord -Value 1

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

		# Workstation Service
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "Start" -PropertyType DWord -Value 4

	# Disable Wi-Fi Direct Services Connection Manager Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Connect Now - Config Registrar Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wcncsvc" -Name "Start" -PropertyType DWord -Value 4

	# Disable Windows Mobile Hotspot Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache" -Name "OsuRegistrationStatus" -PropertyType DWord -Value 0

	# Disable WWAN AutoConfig Service
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WwanSvc" -Name "Start" -PropertyType DWord -Value 4
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wlpasvc" -Name "Start" -PropertyType DWord -Value 4

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

	# Disable Accessibility Keys Prompts (Sticky keys, Toggle keys, Filter keys)
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122"

	# Disable Default Pins
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

	# Disable Explorer.exe
		# 3D Access Shortcuts
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

		# Thumbnail Cache
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1

	# Disable F1 help key
	New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -PropertyType "String" -Value ""
	New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType "String" -Value ""

	# Disable First Logon Animation
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 0

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

		# Small Icons
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -PropertyType DWord -Value 1

	# Enable Explorer.exe
		# Expanded Nav Panel
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -PropertyType DWord -Value 1

		# File operation details
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1

		# Hidden files
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWord -Value 1

		# Known Extensions
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0

	# Enable Small Taskbar Icons
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

CreateLog "sys-cleanup-function.log" "SysCleanup"
SysCleanup
StopLog

SvcDependency

CreateLog "ui-tweak-function.log" "UITweak"
UITweak
StopLog

CreateLog "svc-tweaks-function.log" "SvcTweaks"
SvcTweaks
StopLog

CreateLog "network-tweaks-function.log" "NetworkTweaks"
NetworkTweaks
StopLog

MiscTweak
WaitForReboot
Restart

