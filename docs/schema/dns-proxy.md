# Модуль `dns-proxy`

Версия модуля 1.0.0. Файл: `collectors/dns-proxy.ps1`. Права администратора не нужны.

Учётные данные из строк прокси (`user:password@`) удаляются при сборе; поле `userInfoRemoved` показывает, что они были.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `dnsServers` | `Get-DnsClientServerAddress` |
| `dnsClients` | `Get-DnsClient` |
| `dnsGlobal` | `Get-DnsClientGlobalSetting` |
| `doh.knownServers` | `Get-DnsClientDohServerAddress` (нет на Windows 10 → `null` без ошибки) |
| `doh.interfaces` | `DoH interface settings` (реестр `Dnscache\InterfaceSpecificParameters`) |
| `doh.policy` | `DoH policy` (реестр) |
| `nrpt` | `Get-DnsClientNrptPolicy` (эффективная политика: GPO, VPN) |
| `dnsCache` | `Get-DnsClientCache` |
| `hosts` | `hosts` |
| `proxy.user` | `HKCU Internet Settings` |
| `proxy.machine` | `HKLM Internet Settings` |
| `proxy.winhttp` | `WinHttpSettings` (реестр) + `netsh winhttp show proxy` (только `raw`) |
| `proxy.environment` | `environment` |

## DNS

### `dnsServers[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `interfaceIndex`, `interfaceAlias` | | |
| `addressFamily` | string | `IPv4` \| `IPv6` |
| `serverAddresses` | string[] | `fec0:0:0:ffff::1..3` — заглушки Windows для интерфейсов без IPv6 DNS, а не настоящие серверы |

### `dnsClients[]`

`interfaceIndex`, `interfaceAlias`, `connectionSpecificSuffix` (string \| null), `connectionSpecificSuffixSearchList` (string[]), `registerThisConnectionsAddress` (bool), `useSuffixWhenRegistering` (bool).

### `dnsGlobal`

`suffixSearchList` (string[]), `useDevolution` (bool), `devolutionLevel` (int).

Суффиксы DNS часто содержат корпоративные домены — личные данные для экспорта.

### `doh`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `knownServers[]` | `{ serverAddress, dohTemplate, allowFallbackToUdp, autoUpgrade }` \| null | Серверы, для которых Windows знает DoH-шаблон (встроенные и добавленные). Не означает, что DoH включён |
| `interfaces[]` | см. ниже | Где DoH реально настроен |
| `policy.dohPolicy` | int \| null | GPO «Configure DNS over HTTPS»: 0/1 — запрещён, 2 — разрешён, 3 — обязателен |
| `policy.enableAutoDoh` | int \| null | `Dnscache\Parameters\EnableAutoDoh` |

`doh.interfaces[]`: `interfaceGuid` (связь с `adapters[].interfaceGuid`), `settings` (`Interface` \| `Profile`), `addressFamily`, `serverAddress`, `dohFlags` (int \| null), `dohTemplate` (string \| null). Разбор проверен только на пустом случае: на машине разработки DoH по интерфейсам не настроен.

### `nrpt[]`

`namespace`, `nameServers` (string[]), `queryPolicy`, `dnsSecEnabled`, `directAccessEnabled`, `nameEncoding`. Отсутствующее у объекта свойство — `null`.

### `dnsCache` (D-003)

Только агрегаты: имён из кэша нет, кроме подозрительных.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `total` | int | Записей в кэше |
| `fromHosts` | int | Записей с именами из hosts — Windows загружает весь hosts в кэш |
| `byStatus[]` | `{ status, statusName, count }` | `0 Success`, `9003 NameError` (NXDOMAIN), `9501 NoRecords`, `9002 ServerFailure`, `9701 RecordDoesNotExist`; неизвестный код — `statusName = null` |
| `byType[]` | `{ type, typeName, count }` | `1 A`, `28 AAAA`, `5 CNAME`, `12 PTR`, … |
| `suspicious[]` | `{ name, type, data }` | Ответы A/AAAA с адресом-«чёрной дырой» (`0.0.0.0`, `127.x`, `::`, `::1`) для имён **не** из hosts — признак блокировки или подмены на стороне DNS-сервера. Не более 200 |
| `suspiciousTruncated` | bool | Список обрезан |

## `hosts`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `path` | string | Из `Tcpip\Parameters\DataBasePath` |
| `exists` | bool | |
| `sizeBytes` | int \| null | |
| `lastWriteTime` | timestamp \| null | |
| `entries[]` | `{ address, names[] }` | Комментарии и пустые строки пропущены |

## `proxy`

### `user`, `machine`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `proxyEnable` | bool \| null | |
| `proxyServer` | string \| null | `host:port` или `http=…;https=…` |
| `proxyOverride` | string \| null | Список исключений |
| `autoConfigUrl` | string \| null | PAC |
| `userInfoRemoved` | bool | Из строк удалены учётные данные |
| `connectionSettings` | object \| null | Только `user`: разобранный `DefaultConnectionSettings` — то, что реально применяется: `flags`, `proxyEnabled`, `autoConfigEnabled`, `autoDetect` (WPAD), `proxyServer`, `bypassList`, `autoConfigUrl` |
| `proxySettingsPerUser` | int \| null | Только `machine`: политика; `0` — настройки HKLM действуют для всех пользователей |

`user` — куст HKCU учётной записи, от которой запущен сбор. При повышении прав через UAC другой учётной записью администратора это не куст интерактивного пользователя.

### `winhttp`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `direct` | bool | Без прокси |
| `proxyServer` | string \| null | |
| `bypassList` | string \| null | |
| `raw` | string \| null | Вывод `netsh winhttp show proxy` (локализован) |

### `environment[]`

`{ scope, name, value, userInfoRemoved }` для заданных `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` в областях `Machine` и `User`.

Доступность прокси («мёртвый прокси») модуль не проверяет — это сетевое действие, оно относится к модулю `connectivity` (D-002).
