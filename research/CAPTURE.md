# Porównawczy capture S400

## Linux / Raspberry Pi

Najpierw zapisz stan i adres adaptera:

```bash
bluetoothctl list
bluetoothctl show
bluetoothctl scan on
```

W drugim terminalu uruchom binarny HCI trace:

```bash
sudo btmon -i hci0 -w captures/s400.btsnoop
```

Opcjonalny czytelny zapis tekstowy (osobne podejście, aby uniknąć pomieszania
sesji):

```bash
sudo btmon -i hci0 -T > captures/s400-btmon.txt
```

Procedura jednej sesji:

1. Wyjmij baterie, włóż je ponownie i wykonaj factory reset zgodnie z instrukcją
   konkretnej rewizji S400.
2. Uruchom `btmon` przed wybudzeniem wagi.
3. Wybudź wagę i uruchom `tools/s400_diag.py`; dla trace pairingu zamiast niego
   uruchom `tools/s400_pair.py`.
4. Po wyniku auth odczekaj 10 s i zatrzymaj `btmon` przez Ctrl-C.
5. Zachowaj firmware, PID, MAC, wynik na wyświetlaczu i dokładny czas próby.

Analiza:

```bash
tshark -r captures/s400.btsnoop -Y 'btatt || btle' -V > captures/s400-att.txt
tshark -r captures/s400.btsnoop -Y 'btatt.opcode == 0x1b || btatt.opcode == 0x12 || btatt.opcode == 0x52'
rg -i 'fe95|00000010|00000019|0000001[abc]|02:00:00:00:00:05' captures/s400-btmon.txt
```

Po ustaleniu ATT handle charakterystyk `0x0010` i `0x0019` można ograniczyć
widok Wiresharka filtrem `btatt.handle == 0xNNNN`. Handle jest zależny od
firmware, dlatego nie wpisujemy go na stałe.

## Android Emulator na Windows

Zwykły AVD telefonu nie korzysta z radia Bluetooth Windows. W badanym obrazie
Android 16/API 36 proces `bt_vhci_forwarder` był uruchomiony, a kontroler HCI
był podłączony przez `/dev/vport7p3`; jest to wirtualny kontroler RootCanal.
Taki AVD nie zobaczy fizycznej S400.

Android Emulator obsługuje przekazanie całego urządzenia USB. Lista urządzeń
widocznych dla emulatora:

```powershell
.\tools\windows\s400_android_emulator.ps1 -ListUsb
```

Uruchomienie utworzonego wcześniej AVD Automotive z zewnętrznym donglem,
przykładowo `0b05:17cb`:

```powershell
.\tools\windows\s400_android_emulator.ps1 `
  -Avd S400_AAOS `
  -VendorId 0b05 `
  -ProductId 17cb `
  -BluetoothPassthroughHal
```

Opcja `-BluetoothPassthroughHal` przekazuje właściwość startową
`vendor.qemu.preferred.bt.service=passthrough`. Obraz systemu musi zawierać
`btlinux` HAL oraz sterownik USB dla chipsetu dongla. Publiczne obrazy Android
Automotive są przygotowane do tego trybu; standardowy obraz telefonu może
jedynie zobaczyć urządzenie USB i nadal uruchomić wirtualny HAL.

Na Windows emulator wymaga obu pakietów z katalogu
`%LOCALAPPDATA%\Android\Sdk\emulator\drivers`: usługi `UsbAssist` oraz pakietu
WinUSB `Android_USB_Assistant.inf`. Po instalacji administrator może je
zweryfikować tak:

```powershell
sc.exe query UsbAssist
pnputil.exe /enum-drivers | Select-String Android_USB_Assistant -Context 3,5
```

W tym laboratorium wbudowany adapter Intel `8087:0026` został poprawnie
znaleziony przez `emulator -list-usb` jako `Bus 3, Port 14`, ale żądanie
`USBASSIST_IOCTL_DEVICE_OPS` zwróciło błąd Win32 `50` (`ERROR_NOT_SUPPORTED`).
Adapter pozostał przy Windows, a w sysfs gościa nie pojawiło się urządzenie
`8087:0026`. Tego adaptera nie należy używać do dalszych prób passthrough.
Potrzebny jest osobny dongle USB; oficjalna dokumentacja AOSP potwierdza testy
ASUS USB-BT400 `0b05:17cb` na hoście Linux. Na Windows także ten model trzeba
zweryfikować komendą `-ListUsb` i w sysfs gościa.

Po starcie sprawdź, czy Android rzeczywiście używa sprzętowego HAL:

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb shell getprop init.svc.bt_vhci_forwarder
& $adb shell getprop vendor.qemu.preferred.bt.service
& $adb shell ls -l /sys/bus/usb/devices
& $adb shell cat /proc/modules | Select-String 'btusb|btintel|btbcm|btrtl'
```

Sukces wymaga widocznego urządzenia o VID/PID dongla oraz aktywnego HAL
passthrough. Samo występowanie modułu `btusb` albo włącznika Bluetooth w UI nie
jest dowodem, ponieważ moduły są obecne także w obrazie używającym RootCanal.

Źródła dla tego wariantu:

- [Android Emulator release notes: USB passthrough na Windows](https://developer.android.com/studio/releases/emulator)
- [AOSP: Emulator USB passthrough guide dla Bluetooth](https://source.android.com/docs/automotive/start/passthrough)
- [AOSP: implementacja `usbassist_winusb_load`](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android/android-emu/android/emulation/USBAssist.cpp)
- [AOSP: dodanie `btlinux` HAL i właściwości `vendor.qemu.preferred.bt.service=passthrough`](https://android.googlesource.com/device/generic/car/+/61af1657a0ca78e50afc298e96a9901d83f56902)

## Android + Mi Home

Ta sesja ma rozstrzygnąć, co Mi Home wysyła **między ACK klucza publicznego
urządzenia a nagłówkiem DID**. Na czas próby wyłącz lub odsuń inne urządzenia
BLE, aby ślad miał możliwie jedno połączenie ATT.

1. W Androidzie włącz opcje programistyczne oraz **Bluetooth HCI snoop log**
   (jeśli telefon oferuje poziom logowania, wybierz pełny).
2. Wyłącz i włącz Bluetooth, a najlepiej uruchom ponownie telefon.
3. Wykonaj factory reset S400. Nie uruchamiaj lokalnego klienta przed próbą Mi
   Home, ponieważ samo rozpoczęcie rejestracji zmienia stan wagi.
4. Zanotuj czas, rozpocznij dodawanie S400 w Mi Home i doprowadź je do końca.
5. Zrób jeden pomiar, zanotuj czas i od razu utwórz raport błędu.

Na Windows można zainstalować ADB i pobrać raport tak:

```powershell
winget install --id Google.PlatformTools
adb devices
adb shell dumpsys bluetooth_manager > captures\android-bluetooth-manager.txt
adb bugreport captures\android-s400-bugreport
```

`adb bugreport` zwykle tworzy ZIP, nawet gdy podana nazwa nie ma rozszerzenia.
Po rozpakowaniu znajdź snoop log bez zakładania ścieżki właściwej dla konkretnej
wersji Androida:

```powershell
Expand-Archive captures\android-s400-bugreport.zip captures\android-s400-bugreport
Get-ChildItem captures\android-s400-bugreport -Recurse -File |
  Where-Object { $_.Name -match 'btsnoop|snoop_hci' } |
  Select-Object FullName,Length
```

Najczęściej plik leży pod `FS/data/misc/bluetooth/logs/btsnoop_hci.log` albo
`FS/data/misc/bluedroid/btsnoop_hci.log`. Bezpośredni `adb pull` z tych ścieżek
zwykle wymaga roota; raport błędu go nie wymaga. Na starszych telefonach można
też sprawdzić:

```bash
adb pull /sdcard/btsnoop_hci.log captures/
```

Skopiuj znaleziony plik jako `captures/android-s400-btsnoop_hci.log`. Nie
przycinaj jeszcze capture i nie filtruj wyłącznie `0x0010/0x0019`: właśnie
szukamy potencjalnej brakującej operacji na innym kanale. Eksport całego ATT
wykonuje narzędzie repozytorium:

```powershell
uv run --no-project tools\s400_hci_extract.py `
  captures\android-s400-btsnoop_hci.log `
  -o captures\android-s400-att.jsonl `
  --tshark "$env:ProgramFiles\Wireshark\tshark.exe"
```

Równoważny eksport ręczny z nagłówkiem TSV:

```powershell
$ts = "$env:ProgramFiles\Wireshark\tshark.exe"
& $ts -r captures\android-s400-btsnoop_hci.log -Y btatt -T fields `
  -E header=y -E separator=/t -E occurrence=a `
  -e frame.number -e frame.time_relative -e hci_h4.direction `
  -e bthci_acl.connection_handle -e btatt.opcode -e btatt.handle `
  -e btatt.value > captures\android-s400-att.tsv
```

W badanym firmware uchwyty wartości characteristic były następujące. Android
powinien zobaczyć tę samą bazę GATT, ale eksport zachowuje wszystkie uchwyty na
wypadek różnicy:

| Characteristic | ATT value handle |
|---|---:|
| `0x0010` UPNP | `0x001a` |
| `0x0019` AVDTP/auth | `0x001d` |
| `0x0017` | `0x0020` |
| `0x0018` | `0x0023` |
| `0x001a` | `0x0026` |
| `0x001b` | `0x0029` |
| `0x001c` | `0x002c` |

Przy analizie interesują nas szczególnie operacje ATT Write Request/Command
(`0x12`/`0x52`) oraz Notification/Indication (`0x1b`/`0x1d`). Sam adres MAC
nie występuje przy każdym pakiecie ACL; po ustanowieniu połączenia ruch wiąże się
po `bthci_acl.connection_handle`. Dlatego wiarygodniej wybrać właściwe zdarzenie
LE Connection Complete dla `<S400_MAC>`, zanotować connection handle i
filtrować dalszy ATT po tym handle niż polegać tylko na `bluetooth.addr`.

Do porównania sieci aplikacji, na kontrolowanym interfejsie Raspberry Pi:

```bash
sudo tcpdump -i any -s 0 -w captures/mihome-network.pcap \
  '(udp port 53 or tcp port 80 or tcp port 443)'
tshark -r captures/mihome-network.pcap -Y 'dns' -T fields \
  -e frame.time_relative -e ip.src -e dns.qry.name
```

Lista hostname'ów i endpointów musi powstać z tego capture. Bez próbki nie ma
podstaw, aby przypisywać konkretny endpoint do provisioningu S400. Sam TLS
capture ujawni DNS/SNI, lecz payload HTTPS wymaga kontrolowanego Androida z
własnym CA. Dopiero jeśli Mi Home odrzuci CA, należy sprawdzić pinning i ustalić,
czy jest w OkHttp, Conscrypt czy bibliotece natywnej. Hook musi być dopasowany do
konkretnej wersji APK; uniwersalny hook „wszystkiego” zaciera dowody i często
łamie aplikację przed provisioningiem.

## Zestaw porównawczy

Zbierz trzy osobne sesje z nowym numerem pliku:

1. factory-new S400 + lokalny `s400_pair.py`;
2. ponowny factory reset + oficjalne Mi Home;
3. login już zarejestrowanego urządzenia.

Porównujemy kolejność write/notify na `0x0010/0x0019`, zawartość nagłówków,
długość DID, obecność operacji na pozostałych kanałach, OOB i kody wyniku.
Klucze ephemeral będą różne, więc ich wartości nie powinny być identyczne;
porównujemy strukturę, kolejność i długości. Najważniejszy wycinek zaczyna się od
single-frame `00000203` z 64-bajtowym kluczem urządzenia i obejmuje ACK
`00000300` oraz wszystkie kolejne zapisy klienta.
