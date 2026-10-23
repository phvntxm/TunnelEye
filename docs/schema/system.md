# Модуль `system`

Версия модуля 1.0.0. Файл: `collectors/system.ps1`. Права администратора не нужны.

Каждая секция собирается отдельным источником: если источник упал, секция равна `null`, а в `errors` появляется запись с этим `source`.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `os` | `Win32_OperatingSystem` + реестр `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| `computer` | `Win32_ComputerSystem` |
| `boot` | `boot` (`Win32_OperatingSystem`, реестр Power) |
| `pendingReboot` | `pendingReboot` (реестр) |
| `hotfixes` | `Win32_QuickFixEngineering` |
| `networkProfiles` | `Get-NetConnectionProfile` |

## `os`

| Поле | Тип | Пример | Примечание |
| --- | --- | --- | --- |
| `caption` | string | `Майкрософт Windows 11 Pro` | Локализован |
| `productName` | string | `Windows 10 Pro` | Из реестра; на Windows 11 всё ещё пишет «Windows 10» |
| `family` | string \| null | `Windows 11` | По сборке: ≥ 22000 → 11, ≥ 10240 → 10 |
| `editionId` | string | `Professional` | |
| `displayVersion` | string \| null | `25H2` | Нет на старых сборках Windows 10 |
| `version` | string | `10.0.26200` | |
| `build` | int | `26200` | |
| `ubr` | int \| null | `9711` | Номер накопительного обновления |
| `architecture` | string | `x64` | `x64` \| `x86` \| `arm64` |
| `installationType` | string | `Client` | |
| `installDate` | timestamp | | |
| `osLanguage` | string \| null | `ru-RU` | Язык установки ОС |
| `uiLanguage` | string | `en-US` | Язык интерфейса пользователя |

## `computer`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | Имя ПК. Личные данные: маскируется при экспорте |
| `partOfDomain` | bool | |
| `domain` | string \| null | Только для ПК в домене |
| `workgroup` | string \| null | Только для ПК вне домена |
| `timeZone` | string | Идентификатор Windows, например `Russian Standard Time` |

## `boot`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `lastBootUpTime` | timestamp | |
| `uptimeSec` | int | |
| `fastStartupEnabled` | bool \| null | При быстром запуске «выключение» — это гибернация: uptime и состояние драйверов сохраняются, адаптеры не переинициализируются |

## `pendingReboot`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `componentServicing` | bool | Ключ `Component Based Servicing\RebootPending` |
| `windowsUpdate` | bool | Ключ `WindowsUpdate\Auto Update\RebootRequired` |
| `fileRenameOperations` | bool | `PendingFileRenameOperations` не пуст. Шумный признак: часто выставлен без реальной надобности |

## `hotfixes[]`

Отсортированы от новых к старым.

| Поле | Тип | Пример |
| --- | --- | --- |
| `id` | string | `KB5127648` |
| `description` | string | `Security Update` |
| `installedOn` | date \| null | `2026-10-19` (`yyyy-MM-dd`, без времени) |
| `installedOnRaw` | string \| null | `10/19/2026`, как отдал WMI |

## `networkProfiles[]`

| Поле | Тип | Значения |
| --- | --- | --- |
| `name` | string | Имя сети (для Wi-Fi обычно SSID). Личные данные: маскируется при экспорте |
| `interfaceAlias` | string | Локализован (`Беспроводная сеть`) |
| `interfaceIndex` | int | Связь с модулем `adapters` |
| `category` | string | `Public` \| `Private` \| `DomainAuthenticated` |
| `ipv4Connectivity` | string | `Disconnected` \| `NoTraffic` \| `Subnet` \| `LocalNetwork` \| `Internet` |
| `ipv6Connectivity` | string | Те же значения |
| `domainAuthenticationKind` | string | `None` \| `Ldap` \| `Tls` |

Без подключённых сетей `networkProfiles` — пустой массив, а не ошибка.
