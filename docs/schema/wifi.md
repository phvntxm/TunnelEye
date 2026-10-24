# Модуль `wifi`

Версия модуля 1.1.0 (1.1.0 — по ревью 001: наличие Wi-Fi по адаптерам, нераспознанный вывод — ошибка, дата по культуре, `bss[].interfaceName`). Файл: `collectors/wifi.ps1`. Права администратора не нужны.

**Статусы.** Есть ли Wi-Fi, решают адаптеры (`Get-NetAdapter -Physical`, `NdisPhysicalMedium = 9` — Native 802.11; виртуальные Wi-Fi Direct не считаются), а не текст `netsh`: новая раскладка `netsh` не должна выглядеть как «Wi-Fi нет».
- `skipped` — нет Wi-Fi-адаптера («No Wi-Fi adapter…») или все Wi-Fi-адаптеры отключены («The Wi-Fi adapter is disabled.»). Причина — в `errors[]` (`source = collector`, `NotSupported`). Выключенный радиомодуль и режим «в самолёте» модуль не различает: для правила «Wi-Fi выключен» — `adapters` и эта причина.
- `partial`:
  - адаптер включён, но `WlanSvc` нет или она не запущена — ошибка `WlanSvc`, все секции `null`;
  - `netsh wlan show interfaces` ответил, а интерфейс не распознан — ошибка `Exception` «Unrecognized netsh output», `interfaces = []`, `drivers` и `neighbors` собираются дальше;
  - без разрешения на доступ к местоположению — `AccessDenied` у источника. Windows 11 24H2+ требует его для данных WLAN, `netsh` тогда отвечает отказом со ссылкой на `ms-settings:privacy-location`. Как подсказать пользователю — D-010.
- Если не прочитался сам список адаптеров (ошибка `Get-NetAdapter`), модуль не пропускается и работает по `netsh`.

Модуль собирает факты, не делая выводов. «Слабый Wi-Fi» считает анализатор (этап 2):
- сигнал < 50 %;
- загруженный канал 2,4 ГГц — по `neighbors.bss` (сколько точек на том же и соседних каналах, `channelUtilizationPercent`);
- линк ниже возможностей — `interfaces[].radioType` и `bandGHz` против `drivers[].radioTypesSupported` и `bandsSupportedGHz`.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `interfaces` | `netsh wlan show interfaces` |
| `drivers` | `netsh wlan show drivers` |
| `neighbors` | `netsh wlan show networks` (`mode=bssid`) — результаты последнего сканирования, новое не запускается |
| (наличие Wi-Fi) | `Get-NetAdapter`, `WlanSvc` |

## Разбор вывода `netsh`

Метки и многие значения локализованы («Канал», «5 ГГц», «2,4 ГГц»). Набор и порядок строк зависят от версии Windows: Windows 11 24H2 добавила `Band`, `Rssi`, `Connected Akm-cipher`, `Bss Load`. Длинные русские метки переносятся на следующую строку. Поэтому поля определяются по форме значения, а из меток используются только непереводимые `SSID`, `BSSID`, `Rssi`:

| Поле | Как найдено |
| --- | --- |
| GUID | значение вида GUID |
| сигнал | `NN%` |
| тип радио | `802.11…` |
| диапазон | `2.4` / `2,4` / `5` / `6` + единица |
| канал | первое целое после строки BSSID: в Windows 10 он стоит после «Connection mode», в Windows 11 — сразу после «Band» |
| скорости приёма и передачи | два числа перед строкой сигнала |
| проверка подлинности, шифр | две строки после типа радио |
| загрузка канала | `NN (P%)` / `NN (P %)`; число станций — целое в строке перед ней |

Проверено на обезличенном реальном выводе русской и английской Windows 11 и на раскладке Windows 10 (`tests/collectors/fixtures/wlan-*.txt`). Исходный текст в снимок не кладётся: в нём SSID, BSSID и MAC.

**Дата драйвера.** `netsh` пишет её в коротком формате даты культуры пользователя; дочерний `powershell.exe` модуля наследует ту же культуру. Сначала разбор по `ShortDatePattern` текущей культуры (en-GB `03/12/2026` → 3 декабря, en-US `3/12/2026` → 12 марта), затем запасной список (`dd.MM.yyyy`, `M/d/yyyy`, `yyyy-MM-dd`, …).

**Несколько Wi-Fi-интерфейсов.** `show networks` печатает сканы по интерфейсам после строки без отступа «Interface name : <имя>». Другие строки без отступа тоже бывают с двоеточием (по-русски «…количество сетей: 2.»), поэтому строка начинает скан, только если значение — имя Wi-Fi-интерфейса (из `show interfaces` и списка адаптеров).

## Приватность

| Что | Решение |
| --- | --- |
| SSID своей сети (`interfaces[].ssid`) | Собирается, маскируется при экспорте (D-006) |
| BSSID своей точки доступа и MAC адаптера | Не собираются (D-010): BSSID — адрес, по которому точку находят в общедоступных базах геолокации; MAC адаптера уже есть в `adapters` |
| Имя профиля, список сохранённых профилей | Не собираются: список сохранённых сетей — история мест |
| Ключи Wi-Fi | Никогда (`key=clear` не вызывается) |
| Соседние сети | Только диапазон, канал, сигнал, тип радио и загрузка — без SSID и BSSID: имена и адреса соседних сетей указывают на место |

## `interfaces[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | Имя интерфейса — связь с `adapters.adapters[].name` |
| `description` | string | Модель адаптера |
| `interfaceGuid` | string | `{…}` в нижнем регистре, как `adapters.adapters[].interfaceGuid` |
| `connected` | bool | Есть строка SSID |
| `ssid` | string \| null | Личные данные (D-006) |
| `bandGHz` | string \| null | `2.4` \| `5` \| `6`; `null` на Windows 10 (там нет строки диапазона — анализатор берёт его из канала) |
| `channel` | int \| null | |
| `radioType` | string \| null | `802.11n` (Wi-Fi 4), `802.11ac` (5), `802.11ax` (6/6E), `802.11be` (7) |
| `authentication`, `cipher` | string \| null | `WPA2-Personal`, `WPA3-Personal`, …; `CCMP`, `GCMP`, … (значения для открытой сети локализованы) |
| `receiveRateMbps`, `transmitRateMbps` | number \| null | Скорость линка |
| `signalPercent` | int \| null | Качество сигнала по оценке Windows |
| `rssiDbm` | int \| null | Только Windows 11 24H2+ |

## `drivers[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `interfaceName` | string | |
| `driver`, `vendor`, `provider` | string | |
| `version` | string \| null | |
| `date` | string \| null | `yyyy-MM-dd`; `netsh` пишет дату в формате локали, разбираются `dd.MM.yyyy` и `M/d/yyyy` |
| `radioTypesSupported` | string[] \| null | |
| `bandsSupportedGHz` | string[] \| null | Есть с Windows 11; `null`, если `netsh` их не перечисляет |
| `wpa3Supported` | bool | WPA3 в списке методов проверки подлинности |

## `neighbors`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `networkCount` | int | Сколько сетей (SSID) видно, включая свою |
| `bss[]` | array | По одной записи на точку доступа (BSSID), отсортированы по интерфейсу, диапазону, каналу, сигналу |
| `bss[].interfaceName` | string \| null | Чей это скан; `null`, если имя интерфейса не удалось сопоставить |
| `bss[].connected` | bool | Это точка, к которой подключён ПК |
| `bss[].bandGHz`, `channel`, `signalPercent`, `radioType` | | |
| `bss[].channelUtilizationPercent` | int \| null | Загрузка канала, которую сообщает точка доступа (BSS Load); есть не у всех точек и только на Windows 11 24H2+ |
| `bss[].connectedStations` | int \| null | Клиентов у точки (BSS Load) |
