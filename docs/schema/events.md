# Модуль `events`

Версия модуля 1.1.0 (1.1.0 — по ревью 002: провайдеры драйверов и по имени службы, RasClient в Application, запрос частями). Файл: `collectors/events.ps1`. Права администратора не нужны: журналы System, Application и используемые Operational-журналы читаются обычным пользователем.

Модуль собирает факты, не делая выводов. Что значит конкретное событие, какие ID считать разрывом линка, ошибкой адаптера или DNS, — определяет анализатор (этап 2) по своему каталогу событий. Этот модуль даёт ему счётчики и время.

| Источник (`errors[].source`) | Что читается |
| --- | --- |
| `System` | События провайдеров из списка ниже, все уровни |
| `Application` | Провайдер `RasClient`: подключения и ошибки встроенного VPN (SSTP, L2TP, IKEv2) — например, 20227 «подключение не удалось». Код ошибки RAS лежит в данных события и не собирается (D-011) |
| `Microsoft-Windows-WLAN-AutoConfig/Operational` | Все события: подключение, отключение, ошибки подлинности Wi-Fi |
| `Microsoft-Windows-NetworkProfile/Operational` | Только 10000 (сеть подключена) и 10001 (отключена): остальное — служебные смены состояния, сотни в неделю |
| `Microsoft-Windows-NCSI/Operational` | Все: 4042 — смена доступности интернета по оценке Windows |
| `Microsoft-Windows-Dhcp-Client/Admin`, `Microsoft-Windows-Dhcpv6-Client/Admin` | Все |
| `Get-NetAdapter`, `Win32_NetworkAdapter` | Имена файлов драйверов и имена служб физических адаптеров — для списка провайдеров |
| `Get-WinEvent -ListLog` | Состояние журналов для `logs[]` |

Период — 7 дней (`periodDays`, `since`).

**Провайдеры в System:**
- компоненты Windows: `Tcpip`, `Tcpip6`, `NDIS`, `Microsoft-Windows-NDIS`, `NetBT`, `Microsoft-Windows-Dhcp-Client`, `Microsoft-Windows-DHCPv6-Client`, `Microsoft-Windows-DNS-Client` (таймауты разрешения имён), `Microsoft-Windows-WLAN-AutoConfig`, `Microsoft-Windows-Iphlpsvc`, `Microsoft-Windows-NlaSvc`, `Microsoft-Windows-WWAN-SVC-EVENTS`, `RasSstp`, `Rasman`, `RemoteAccess`, `WinDivert`;
- драйверы физических адаптеров (Windows считает физическими и минипорты VPN-клиентов). Драйвер пишет под именем своей **службы**; у многих оно совпадает с именем файла (`Netwtw10.sys` → `Netwtw10`), у части — нет (у Realtek, например, файл `rt…x64.sys`, служба без `x64`). Поэтому берутся оба имени: имя файла из `Get-NetAdapter -Physical` и `ServiceName` из `Win32_NetworkAdapter` (`PhysicalAdapter = TRUE`). Лишнее имя в XPath ничего не стоит.

Виртуальные адаптеры не берутся: коммутатор Hyper-V один пишет тысячи событий в неделю.

Отбор делается запросом XPath на стороне журнала. Весь System за неделю может содержать десятки тысяч событий несетевых провайдеров (коммутатор Hyper-V, сторонние службы) и читаться секунды; выборка обычно — сотни или тысяча событий и 2–3 с. Отсутствующий провайдер в XPath не роняет запрос (в отличие от `-FilterHashtable`); недопустимые символы в имени провайдера отбрасываются. Журнал отвергает XPath больше чем с ~21 условием на провайдера («The specified query is invalid»), поэтому System читается частями по 15 провайдеров.

## Приватность

Текст сообщений и данные событий (`Properties`, `EventData`) не собираются: в них имена хостов (таймауты DNS), IP- и MAC-адреса (конфликт адресов), SSID (WLAN, NetworkProfile), имена пользователей. Хранятся только журнал, провайдер, ID, уровень и время. DNS-Client/Operational не читается: это журнал запросов, то есть история посещений, и по умолчанию он выключен.

## `logs[]`

`{ logName, exists, enabled, readOk }` — по каждому журналу, который модуль пытался прочитать. `readOk = false` — чтение упало, ошибка в `errors`. Пустой журнал — не ошибка.

## `providers[]`, `applicationProviders[]`

Списки провайдеров System и Application, по которым шёл отбор (строки, по алфавиту).

## `groups[]`

Отсортированы по журналу, провайдеру, ID.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `logName`, `provider`, `eventId` | string, string, int | |
| `level` | string | `Critical` \| `Error` \| `Warning` \| `Information` \| `Verbose` (уровень 0 «LogAlways» — `Information`) |
| `count` | int | Событий за период |
| `firstTime`, `lastTime` | string | ISO 8601 UTC |
| `times[]` | string[] | Время событий, новые первыми, не более 200 — для графика разрывов |
| `timesTruncated` | bool | Событий больше, чем в `times` |
