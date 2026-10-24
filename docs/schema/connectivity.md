# Модуль `connectivity`

Версия модуля 1.0.1 (1.0.1 — у промежуточных хопов трассировки `rttMs = null`). Файлы: `collectors/connectivity.ps1`, цели внешних тестов — `collectors/connectivity-targets.json`. Права администратора не нужны.

Модуль собирает факты, не делая выводов. «Мёртвый прокси», «Проблемы MTU», «DNS-подмена», «трафик мимо туннеля» считает анализатор (этап 2).

## Режимы (D-002)

| Режим | Когда | Что уходит в сеть |
| --- | --- | --- |
| Локальный | Всегда | Эхо-запросы и подбор MTU до шлюзов по умолчанию; PTR-запрос к DNS-серверам интерфейсов с частными, link-local и loopback адресами; TCP-подключение к прокси на таких адресах. За пределы локальной сети — ничего |
| Внешний | Только с явным `-AllowExternal` на запуск (CLI: `connectivity.ps1 -AllowExternal` или `Invoke-Snapshot.ps1 -AllowExternal`; GUI — согласие на запуск, этап 2) | Эхо-запросы, сравнение ответов DNS, трассировка и MTU пути до целей из конфига; проверка DNS-серверов и прокси с публичными адресами |

Флаг нельзя включить конфигом или умолчанием, согласие не запоминается. Режим записан в данных модуля (`externalAllowed`, `externalConsentSource`) и в заголовке снимка (`snapshot.json` → `externalAllowed`).

**Что считается локальным** (одна функция `Test-TargetAllowed`, покрыта тестами):
- адреса классов `loopback`, `private` (RFC 1918, `fec0::/10`), `linkLocal`, `uniqueLocal` — классы как в `connections`, функция `Get-AddressClass` общего модуля;
- шлюзы по умолчанию — всегда, это next hop в своём сегменте;
- из имён хостов — только `localhost`. Другие имена не резолвятся ради классификации и считаются внешними.

Адреса CGNAT (`100.64.0.0/10`) и публичные — внешние. Multicast, broadcast и неуказанные адреса не проверяются никогда. Заглушки Windows `fec0:0:0:ffff::1..3` (D-007) не проверяются.

## Путь проверки — обязательно для интерпретации

ICMP, DNS-запросы и TCP-подключения **не идут через HTTP/SOCKS-прокси**: при VPN-клиенте в режиме прокси (без TUN) внешние тесты меряют прямой путь провайдера, а не путь через VPN. В режиме TUN часть ядер (стек gVisor и подобные) **сами отвечают на ICMP**: RTT ~0–1 мс до «внешнего» узла и MTU туннеля вместо пути. Поэтому у каждой проверки есть `viaInterfaceIndex`/`viaInterfaceAlias` — интерфейс, через который идёт маршрут к цели (`Find-NetRoute`, запрос к таблице маршрутов, пакетов не отправляет). Плюс общий `context`.

## Как проверяется

- **Пинг, MTU, трассировка** — `System.Net.NetworkInformation.Ping`: статусы (`Success`, `TimedOut`, `PacketTooBig`, `TtlExpired`, `DestinationUnreachable`, …) не локализованы, права админа не нужны.
- **MTU (только IPv4).** Размер данных эхо-запроса с флагом Don't Fragment, `mtu = maxPayload + 28`.
  - Сначала базовый запрос на 32 байта: нет ответа — `status = noEchoReply`, поиск не начинается.
  - Затем 1472 (MTU 1500, обычный случай — 2 пробы), иначе двоичный поиск.
  - `PacketTooBig` — сразу «не проходит»; `TimedOut` повторяется (всего 3 попытки), прежде чем размер считается непроходящим. Так один потерянный ответ не занижает MTU.
- **DNS** — собственный минимальный клиент по UDP. `Resolve-DnsName` к молчащему серверу ждёт ~7 с даже с `-QuickTimeout`, а его ошибки локализованы. Таймаут 1,5 с.
  - Живость DNS-сервера — PTR-запрос его собственного адреса, 2 попытки. Любой ответ, включая NXDOMAIN и коды ошибок, означает «отвечает». TCP 53 признаком не служит: многие домашние роутеры его не слушают.
- **Прокси** — TCP-подключение к порту, без отправки данных.
- **Трассировка** — эхо-запросы с растущим TTL, 1 запрос на хоп, до 30 хопов, остановка после 5 молчащих хопов подряд. Только ICMP, как `tracert`.
- **Бюджет модуля — 100 с** (меньше таймаута оркестратора 120 с). Что не успело — `reason`/`status = budget`, одна ошибка `budget = Timeout`, модуль `partial`.

## Цели внешних тестов

`collectors/connectivity-targets.json` (схема `tunneleye.connectivity-targets/1`) — только крупные нейтральные сервисы. Пользователь дописывает свои в `%LOCALAPPDATA%\TunnelEye\connectivity-targets.json` в том же формате, списки объединяются без повторов. `ping`, `trace`, `mtu`, `dns.servers` — только IP-адреса (цель не ищется через DNS), `dns.names` — имена хостов; неверные записи отбрасываются с ошибкой `connectivity-targets.json`. Списка «часто блокируемых» сервисов в репозитории нет.

## Данные

| Поле | Тип | Примечание |
| --- | --- | --- |
| `externalAllowed` | bool | |
| `externalConsentSource` | string \| null | `cli` \| `gui`; `null` без согласия |
| `windowsConnectivity[]` | `{ interfaceIndex, interfaceAlias, networkCategory, ipv4, ipv6 }` | Оценка самой Windows (NCSI): `Internet` \| `LocalNetwork` \| `Subnet` \| `NoTraffic` \| `Disconnected`. Читается, а не проверяется. Имя сети (SSID) не собирается |
| `context` | object | `systemProxyEnabled` (прокси HKCU включён); `externalIPv4Via`, `externalIPv6Via` — `{ viaInterfaceIndex, viaInterfaceAlias }` маршрута к документационным адресам `192.0.2.1` / `2001:db8::1`: через какой интерфейс пошёл бы произвольный внешний трафик. Подробности — в `routing`, `dns-proxy` |
| `gateways[]` | object | `{ address, family, interfaceIndex, interfaceAlias, viaInterfaceIndex, viaInterfaceAlias, ping, mtu }` |
| `dnsServers[]` | object | `{ address, interfaceIndex, addressClass, tested, reason, responds, status, rcode, rttMs, viaInterfaceIndex, viaInterfaceAlias }`; один адрес — одна запись |
| `proxies[]` | object | `{ source, enabled, scheme, host, port, addressClass, tested, reason, status, viaInterfaceIndex, viaInterfaceAlias }`; `source`: `user` \| `machine` \| `winhttp`; `status`: `open` \| `refused` \| `timeout` \| `error` |
| `external` | object \| null | `null` без согласия |

`reason` у непроверенного: `local` (проверен), `externalNotAllowed`, `invalidTarget`, `noPort`, `budget`.

**`ping`** (у шлюзов и внешних целей): `{ sent, received, lossPercent, rttMinMs, rttAvgMs, rttMaxMs, status }`.

**`mtu`**: `{ maxPayload, mtu, status, probes, timeoutsCountedAsFail }`; `status`: `ok` \| `noEchoReply`. Для IPv6-шлюзов `mtu = null`: в IPv6 DF не применяется.

**`external`:**
- `userTargetsFile` — bool, был ли пользовательский файл целей (путь не пишется);
- `ping[]` — `{ target, viaInterfaceIndex, viaInterfaceAlias, result }`;
- `dns[]` — по имени: `{ name, results[{ server, source (config|interface), status, rcode, addresses[], rttMs }], distinctAnswerSets, sinkholeServers[], nxdomainServers[], failedServers[] }`.
  - `status`: `answer` \| `nxdomain` \| `rcode` \| `timeout` \| `error` \| `skipped`.
  - `sinkholeServers` — ответили неуказанным или loopback-адресом.
  - `distinctAnswerSets` — сколько разных наборов адресов (CDN законно отдают разные — взвешивает анализатор).
  - Запрашиваются записи A.
- `trace[]` — `{ target, viaInterfaceIndex, viaInterfaceAlias, status (reached|stoppedAfterTimeouts|maxHops|unreachable|budget), hops[{ ttl, address, rttMs, status }] }`; у молчащего хопа `address = null`; `rttMs` есть только у последнего хопа (`Success`): для `TtlExpired` .NET времени не сообщает (всегда 0), поэтому `null`;
- `mtu[]` — `{ target, viaInterfaceIndex, viaInterfaceAlias, result }`, только IPv4.

**Личные данные** (маскируются при экспорте, ТЗ): адреса шлюзов, DNS-серверов, прокси, адреса хопов трассировки (провайдер, город). Ответы DNS на имена из конфига — адреса публичных сервисов, не история пользователя.
