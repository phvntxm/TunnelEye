# Модуль `events`

Версия модуля 1.0.0. Файл: `collectors/events.ps1`. Права администратора не нужны: журнал System и используемые Operational-журналы читаются обычным пользователем.

Модуль собирает факты, не делая выводов. Что значит конкретное событие, какие ID считать разрывом линка, ошибкой адаптера или DNS, — определяет анализатор (этап 2) по своему каталогу событий. Этот модуль даёт ему счётчики и время.

| Источник (`errors[].source`) | Что читается |
| --- | --- |
| `System` | События провайдеров из списка ниже, все уровни |
| `Microsoft-Windows-WLAN-AutoConfig/Operational` | Все события: подключение, отключение, ошибки подлинности Wi-Fi |
| `Microsoft-Windows-NetworkProfile/Operational` | Только 10000 (сеть подключена) и 10001 (отключена): остальное — служебные смены состояния, сотни в неделю |
| `Microsoft-Windows-NCSI/Operational` | Все: 4042 — смена доступности интернета по оценке Windows |
| `Microsoft-Windows-Dhcp-Client/Admin`, `Microsoft-Windows-Dhcpv6-Client/Admin` | Все |
| `Get-NetAdapter` | Имена драйверов физических адаптеров — для списка провайдеров |
| `Get-WinEvent -ListLog` | Состояние журналов для `logs[]` |

Период — 7 дней (`periodDays`, `since`).

**Провайдеры в System:**
- компоненты Windows: `Tcpip`, `Tcpip6`, `NDIS`, `Microsoft-Windows-NDIS`, `NetBT`, `Microsoft-Windows-Dhcp-Client`, `Microsoft-Windows-DHCPv6-Client`, `Microsoft-Windows-DNS-Client` (таймауты разрешения имён), `Microsoft-Windows-WLAN-AutoConfig`, `Microsoft-Windows-Iphlpsvc`, `Microsoft-Windows-NlaSvc`, `Microsoft-Windows-WWAN-SVC-EVENTS`, `RasSstp`, `Rasman`, `RemoteAccess`, `WinDivert`;
- драйверы физических адаптеров по имени файла драйвера (`Netwtw10`, `rt640x64`, `e1dexpress`, …) — так они называются как провайдеры событий.

Виртуальные адаптеры не берутся: коммутатор Hyper-V один пишет тысячи событий в неделю.

Отбор делается запросом XPath на стороне журнала. Весь System за неделю может содержать десятки тысяч событий несетевых провайдеров (коммутатор Hyper-V, сторонние службы) и читаться секунды; выборка обычно — сотни или тысяча событий и 2–3 с. Отсутствующий провайдер в XPath не роняет запрос (в отличие от `-FilterHashtable`); недопустимые символы в имени провайдера отбрасываются.

## Приватность

Текст сообщений и данные событий (`Properties`, `EventData`) не собираются: в них имена хостов (таймауты DNS), IP- и MAC-адреса (конфликт адресов), SSID (WLAN, NetworkProfile), имена пользователей. Хранятся только журнал, провайдер, ID, уровень и время. DNS-Client/Operational не читается: это журнал запросов, то есть история посещений, и по умолчанию он выключен.

## `logs[]`

`{ logName, exists, enabled, readOk }` — по каждому журналу, который модуль пытался прочитать. `readOk = false` — чтение упало, ошибка в `errors`. Пустой журнал — не ошибка.

## `providers[]`

Список провайдеров System, по которым шёл отбор (строки, по алфавиту).

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
