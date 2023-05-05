#zmienne globalne
$global:IleSprawdzen = 0
$global:SpelniajaceZalozenia = 0
$global:NiespelniajaceZalozen = 0
$global:SprawdzeniaOdrzucone = 0
$global:Procent = 0
$global:Ocena
$global:KolorOceny

#okreslenie zdarzenia przy wyst¹pieniu bledu - zakonczenie dzialania
$ErrorActionPreference = "Stop"

#funkcja dodajaca do pliku wynik pojedynczego sprawdzenia w postaci wiersza html
function Cis-Reg( $NazwaRaportu, $Rozdzial, $Lokalizacja, $Parametr, $WartoscZalecana) {


    Try {

        #pobieramy wartosc z rejestru
        $PobranyElement = Get-ItemProperty -Path $Lokalizacja -Name $Parametr
        $WartoscOdczytana = $PobranyElement.$Parametr

        #sprawdzamy za pomoca regexa czy spelniony jest warunek
        $Spelnione = $WartoscOdczytana -match $WartoscZalecana

        #ustawiamy zmienna oznaczajaca kolor wiersza na czerwony
        $Kolor = "#FA1E3C"

        #jezeli warunek jest spelniony to ustawiamy kolor na zielony i zwiekszamy odpowiednia zmienna globalna
        if ($Spelnione) {

            $Kolor = "#05E75C"
            $global:SpelniajaceZalozenia += 1
        
            }

        else {

            #jezeli warunek nie jest spelniony to kolor pozostaje czerwony i zwiekszamy odpowiednia zmienna globalna
            $global:NiespelniajaceZalozen += 1
        
            }
        }

    Catch [System.Management.Automation.PSArgumentException] { 

        $Kolor = "#AC9CB0"
        $global:SprawdzeniaOdrzucone += 1
        
        } 

    Catch [System.Management.Automation.ItemNotFoundException] {

        $Kolor = "#AC9CB0"
        $global:SprawdzeniaOdrzucone += 1
        
        }

  
    Finally { $ErrorActionPreference = "Continue" }


    #tworzymy odpowiedni wiersz w html
    $WierszHtml = "<tr style='background-color:$Kolor;'><td>$Rozdzial</td><td>$Lokalizacja</td><td>$Parametr</td><td>$WartoscZalecana</td><td>$WartoscOdczytana</td></tr>"

    #dodajemy go do pliku
    Add-Content $NazwaRaportu $WierszHtml

    #zwiekszam liczbe wykonanych sprawdzen
    $global:IleSprawdzen += 1

    #obliczenie stosunku procentowego oraz zaokr¹glenie go w góre

    $global:Procent = [int][Math]::Ceiling(($SpelniajaceZalozenia /($IleSprawdzen - $SprawdzeniaOdrzucone))*100)
  

    #oceny konfiguracji systemu
    if ($Procent -ge 0 -and $Procent -le 50) { $global:Ocena= "niedostateczna"; $global:KolorOceny = "FA1E3C"}
    if ($Procent -ge 51 -and $Procent -lt 75) { $global:Ocena= "dostateczna"; $global:KolorOceny = "F1C232"}
    if ($Procent -ge 75 -and $Procent -lt 85) { $global:Ocena= "dobra"; $global:KolorOceny = "8FCE00"}
    if ($Procent -ge 85 -and $Procent -le 100) { $global:Ocena= "bardzo dobra"; $global:KolorOceny = "38761D"}

}

$Data = Get-Date

$NazwaPliku = "Raport.html"

$System = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
$Wersja = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion 
New-Item $NazwaPliku -Force 

#dodajemy tresc - style, nazwe komputera i date
Set-Content $NazwaPliku "
<html>
<style>

    body {

        font-family: arial, sans-serif;
        
        }

    table {
    
        border-collapse: collapse;
        width: 80%;
    
        }
  
    td, th {

        border: 1px solid #000000;
        text-align: center;
        padding: 8px;

        }

    #ParametryKomputera {

        font-family: arial, sans-serif;
        color: #006B77;
        font-size: 14px;
    
        }

    #Data {

        font-family: arial, sans-serif;
        color: #000000;
        font-size: 14px;
    
        }

    #Tytul {
        
        font-family: arial, sans-serif;
        color: #000000;
        font-size: 20px;
        font-weight: 900;
        
        }



</style>
<p id='Tytul'>NARZÊDZIE DO AUTOMATYCZNEJ WERYFIKACJI ZGODNOŒCI KONFIGURACJI SYSTEMU OPERACYJNEGO MICROSOFT WINDOWS 10 Z WYTYCZNYMI CIS BENCHMARK</p>
Krzysztof KRASECKI WCY18KC1S1
<p id='ParametryKomputera'>Nazwa komputera: <strong>$env:computername</strong></p>
<p id='ParametryKomputera'>System: <strong>$System</strong></p>
<p id='ParametryKomputera'>Wersja: <strong>$Wersja</strong></p>
<p id='Data'>Data i godzina uruchomienia: <strong>$Data</strong></p>
<br><br>
"

#dodajemy naglowek tabeli
Add-Content $NazwaPliku "
<table >
<tr>
<th>ROZDZIA£</th><th>LOKALIZACJA</th><th>PARAMETR</th><th>WARTOŒÆ ZALECANA</th><th>WARTOŒÆ ODCZYTANA</th>
</tr>
"


#ROZDZIAL 2:

Cis-Reg $NazwaPliku "2.2.35" "HKLM:\SYSTEM\ControlSet001\Services\WdiServiceHost" "ObjectName" "NT AUTHORITY\\LocalService"
Cis-Reg $NazwaPliku "2.3.1.4" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" "1"
Cis-Reg $NazwaPliku "2.3.2.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" "1"
Cis-Reg $NazwaPliku "2.3.2.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" "0"
Cis-Reg $NazwaPliku "2.3.4.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" "1"
Cis-Reg $NazwaPliku "2.3.6.1" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" "1"
Cis-Reg $NazwaPliku "2.3.6.2" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" "1"
Cis-Reg $NazwaPliku "2.3.6.3" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" "1"
Cis-Reg $NazwaPliku "2.3.6.4" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" "0"
Cis-Reg $NazwaPliku "2.3.6.5" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" "^([1-9]|[12][0-9]|30)$" 
Cis-Reg $NazwaPliku "2.3.6.6" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" "1"
Cis-Reg $NazwaPliku "2.3.7.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "0"
Cis-Reg $NazwaPliku "2.3.7.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" "1"
Cis-Reg $NazwaPliku "2.3.7.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MaxDevicePasswordFailedAttempts" "^([1-9]|10)$"
Cis-Reg $NazwaPliku "2.3.7.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "^([1-9]|[1-9][0-9]|[1-8][0-9][0-9]|900)$"
Cis-Reg $NazwaPliku "2.3.7.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "^$"
Cis-Reg $NazwaPliku "2.3.7.6" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption" "^$"
Cis-Reg $NazwaPliku "2.3.7.7" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "^([1-4])$"
Cis-Reg $NazwaPliku "2.3.7.8" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning" "^[5-9]|[1-9][0-4]$"
Cis-Reg $NazwaPliku "2.3.8.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" "1"
Cis-Reg $NazwaPliku "2.3.8.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" "1"
Cis-Reg $NazwaPliku "2.3.8.3" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" "0"
Cis-Reg $NazwaPliku "2.3.9.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoDisconnect" "^([0-9]|1[1-5]|10)$"
Cis-Reg $NazwaPliku "2.3.9.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" "1"
Cis-Reg $NazwaPliku "2.3.9.3" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" "1"
Cis-Reg $NazwaPliku "2.3.9.4" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableForcedLogoff" "1"
Cis-Reg $NazwaPliku "2.3.10.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" "1"
Cis-Reg $NazwaPliku "2.3.10.3" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" "1"
Cis-Reg $NazwaPliku "2.3.10.4" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" "1"
Cis-Reg $NazwaPliku "2.3.10.5" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" "0"
Cis-Reg $NazwaPliku "2.3.10.9" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess" "1"
Cis-Reg $NazwaPliku "2.3.10.11" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" "^$"
Cis-Reg $NazwaPliku "2.3.11.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" "1"
Cis-Reg $NazwaPliku "2.3.11.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback" "0"
Cis-Reg $NazwaPliku "2.3.11.5" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" "1"
Cis-Reg $NazwaPliku "2.3.15.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "ObCaseInsensitive" "1"
Cis-Reg $NazwaPliku "2.3.15.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1"
Cis-Reg $NazwaPliku "2.3.17.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" "1"
Cis-Reg $NazwaPliku "2.3.17.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "2"
Cis-Reg $NazwaPliku "2.3.17.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" "0"
Cis-Reg $NazwaPliku "2.3.17.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" "1"
Cis-Reg $NazwaPliku "2.3.17.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" "1"
Cis-Reg $NazwaPliku "2.3.17.6" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "1"
Cis-Reg $NazwaPliku "2.3.17.7" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "1"
Cis-Reg $NazwaPliku "2.3.17.8" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" "1"


#ROZDZIAL 5:

Cis-Reg $NazwaPliku "5.1" "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" "Start" "0"
Cis-Reg $NazwaPliku "5.2" "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" "Start" "0"
Cis-Reg $NazwaPliku "5.3" "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" "Start" "0"
Cis-Reg $NazwaPliku "5.4" "HKLM:\SYSTEM\CurrentControlSet\Services\bowser" "Start" "0"
Cis-Reg $NazwaPliku "5.5" "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" "Start" "0"
Cis-Reg $NazwaPliku "5.6" "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN" "Start" "0"
Cis-Reg $NazwaPliku "5.7" "HKLM:\SYSTEM\CurrentControlSet\Services\irmon" "Start" "0"
Cis-Reg $NazwaPliku "5.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" "Start" "0"
Cis-Reg $NazwaPliku "5.9" "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" "Start" "0"
Cis-Reg $NazwaPliku "5.10" "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager" "Start" "0"
Cis-Reg $NazwaPliku "5.11" "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC" "Start" "0"
Cis-Reg $NazwaPliku "5.12" "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" "Start" "0"
Cis-Reg $NazwaPliku "5.13" "HKLM:\SYSTEM\CurrentControlSet\Services\sshd" "Start" "0"
Cis-Reg $NazwaPliku "5.14" "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" "Start" "0"
Cis-Reg $NazwaPliku "5.15" "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" "Start" "0"
Cis-Reg $NazwaPliku "5.16" "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" "Start" "0"
Cis-Reg $NazwaPliku "5.17" "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" "Start" "0"
Cis-Reg $NazwaPliku "5.18" "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" "Start" "0"
Cis-Reg $NazwaPliku "5.19" "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" "Start" "0"
Cis-Reg $NazwaPliku "5.20" "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" "Start" "0"
Cis-Reg $NazwaPliku "5.21" "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" "Start" "0"
Cis-Reg $NazwaPliku "5.22" "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" "Start" "0"
Cis-Reg $NazwaPliku "5.23" "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" "Start" "0"
Cis-Reg $NazwaPliku "5.24" "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" "Start" "0"
Cis-Reg $NazwaPliku "5.25" "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" "Start" "0"
Cis-Reg $NazwaPliku "5.26" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" "Start" "0"
Cis-Reg $NazwaPliku "5.27" "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp" "Start" "0"
Cis-Reg $NazwaPliku "5.28" "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" "Start" "0"
Cis-Reg $NazwaPliku "5.29" "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr" "Start" "0"
Cis-Reg $NazwaPliku "5.30" "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" "Start" "0"
Cis-Reg $NazwaPliku "5.31" "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" "Start" "0"
Cis-Reg $NazwaPliku "5.32" "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc" "Start" "0"
Cis-Reg $NazwaPliku "5.33" "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" "Start" "0"
Cis-Reg $NazwaPliku "5.34" "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" "Start" "0"
Cis-Reg $NazwaPliku "5.35" "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" "Start" "0"
Cis-Reg $NazwaPliku "5.36" "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" "Start" "0"
Cis-Reg $NazwaPliku "5.37" "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" "Start" "0"
Cis-Reg $NazwaPliku "5.38" "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall" "Start" "0"
Cis-Reg $NazwaPliku "5.39" "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" "Start" "0"
Cis-Reg $NazwaPliku "5.40" "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC" "Start" "0"
Cis-Reg $NazwaPliku "5.41" "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" "Start" "0"
Cis-Reg $NazwaPliku "5.42" "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" "Start" "0"
Cis-Reg $NazwaPliku "5.43" "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" "Start" "0"
Cis-Reg $NazwaPliku "5.44" "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" "Start" "0"


#ROZDZIAL 9:

Cis-Reg $NazwaPliku "9.1.1" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile" "EnableFirewall" "1"
Cis-Reg $NazwaPliku "9.1.5" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile" "DisableNotifications" "0"
Cis-Reg $NazwaPliku "9.1.6" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\LogFiles\\Firewall\\domainfw.log"
Cis-Reg $NazwaPliku "9.1.7" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
Cis-Reg $NazwaPliku "9.1.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging" "LogDroppedPackets" "1"
Cis-Reg $NazwaPliku "9.1.9" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging" "LogSuccessfulConnections" "1"
Cis-Reg $NazwaPliku "9.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1"
Cis-Reg $NazwaPliku "9.2.4" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" "0"
Cis-Reg $NazwaPliku "9.2.5" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\logfiles\\firewall\\privatefw.log"
Cis-Reg $NazwaPliku "9.2.6" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
Cis-Reg $NazwaPliku "9.2.7" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1"
Cis-Reg $NazwaPliku "9.2.8" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1"
Cis-Reg $NazwaPliku "9.3.1" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile" "EnableFirewall" "1"
Cis-Reg $NazwaPliku "9.3.4" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile" "DisableNotifications" "0"
Cis-Reg $NazwaPliku "9.3.7" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\Logfiles\\Firewall\\publicfw.log"
Cis-Reg $NazwaPliku "9.3.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
Cis-Reg $NazwaPliku "9.3.9" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging" "LogDroppedPackets" "1"
Cis-Reg $NazwaPliku "9.3.10" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging" "LogSuccessfulConnections" "1"


#ROZDZIAL 18:

Cis-Reg $NazwaPliku "18.5.10.2" "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled" "1"
Cis-Reg $NazwaPliku "18.9.4.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" "0"
Cis-Reg $NazwaPliku "18.9.83.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0"
Cis-Reg $NazwaPliku "18.9.96.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0"
Cis-Reg $NazwaPliku "18.9.103.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" "0"


#dodajemy pozostala czesc dokumentu html


Add-Content Raport.html "
</table>
<br><br>
Dokonano sprawdzeñ: <b>$global:IleSprawdzen</b><br>
Sprawdzenia spe³niaj¹ce wytyczne: <b>$global:SpelniajaceZalozenia</b><br>
Sprawdzenia niespe³niaj¹ce wytycznych: <b>$global:NiespelniajaceZalozen</b><br>
Sprawdzenia odrzucone: <b>$global:SprawdzeniaOdrzucone</b><br>
Wynik procentowy: <b>$global:Procent%</b><br>
Konfiguracja komputera jest <b style='color:$KolorOceny;'<b>$global:Ocena</b></span>
</html>
"

$Shell = New-Object -ComObject "WScript.Shell"
$Przycisk = $Shell.Popup("Naciœnij OK, aby kontynuowaæ", 0, "Skrypt pomyœlnie zakoñczy³ pracê", 0)




