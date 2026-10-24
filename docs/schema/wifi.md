# Модуль `wifi`

Версия модуля 1.0.0. Файл: `collectors/wifi.ps1`. Права администратора не нужны.

**Статусы:**
- `skipped` — службы WLAN AutoConfig (`WlanSvc`) нет или она не запущена, либо `netsh` не видит ни одного Wi-Fi-интерфейса.
- Без разрешения на доступ к местоположению — ошибка `AccessDenied` у источника. Windows 11 24H2+ требует его для данных WLAN, `netsh` тогда отвечает отказом со ссылкой на `ms-settings:privacy-location`.

Модуль собирает факты, не делая выводов. «Слабый Wi-Fi» считает анализатор (этап 2):
- сигнал < 50 %;
- загруженный канал 2,4 ГГц — по `neighbors.bss` (сколько точек на том же и соседних каналах, `channelUtilizationPercent`);
- линк ниже возможностей — `interfaces[].radioType` и `bandGHz` против `drivers[].radioTypesSupported` и `bandsSupportedGHz`.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `interfaces` | `netsh wlan show interfaces` |
| `drivers` | `netsh wlan show drivers` |
| `neighbors` | `netsh wlan show networks` (`mode=bssid`) — результаты последнего сканирования, новое не запускается |

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

## Приватность

| Что | Решение |
| --- | --- |
| SSID своей сети (`interfaces[].ssid`) | Собирается, маскируется при экспорте (D-006) |
| BSSID своей точки доступа и MAC адаптера | Не собираются: BSSID — адрес, по которому точку находят в общедоступных базах геолокации; MAC адаптера уже есть в `adapters` |
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
| `bss[]` | array | По одной записи на точку доступа (BSSID), отсортированы по диапазону, каналу, сигналу |
| `bss[].connected` | bool | Это точка, к которой подключён ПК |
| `bss[].bandGHz`, `channel`, `signalPercent`, `radioType` | | |
| `bss[].channelUtilizationPercent` | int \| null | Загрузка канала, которую сообщает точка доступа (BSS Load); есть не у всех точек и только на Windows 11 24H2+ |
| `bss[].connectedStations` | int \| null | Клиентов у точки (BSS Load) |
