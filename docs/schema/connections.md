# Модуль `connections`

Версия модуля 1.0.0. Файл: `collectors/connections.ps1`. Права администратора не нужны: без них модуль `ok` (владелец соединения известен и без них).

Модуль собирает факты, не делая выводов. Анализатор (этап 2) использует его для правил:
- **«Открытые порты»** — `tcpListeners` и `udpEndpoints` на всех интерфейсах + профиль сети из `system` + правила из `firewall`;
- **«Трафик мимо туннеля»** — локальный адрес соединения сопоставляется с интерфейсом по `routing.addresses`. Соединения процессов VPN-клиентов и ядер прокси (`vpn.clients`, включая `owners`) через физический интерфейс — это сам туннель, не утечка (D-009).

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `tcpListeners`, `tcpConnections`, `publicConnections` | `Get-NetTCPConnection` |
| `udpEndpoints` | `Get-NetUDPEndpoint` |
| имена процессов | `Get-Process` (только имя; пути и командные строки не собираются) |

Таблица соединений — мгновенный снимок: между запусками она меняется.

## Приватность (D-009)

Публичный удалённый адрес не попадает в снимок никогда. Соединения с ним сводятся в `publicConnections` — счётчики с числом уникальных адресов, без самих адресов. Удалённые адреса остальных классов (loopback, частные сети, CGNAT, link-local и т. д.) хранятся полностью: это локальные прокси, шлюз, машины в сети, а не история посещений. Локальные адреса — личные данные, маскируются при экспорте.

## Классы адресов (`localClass`, `remoteClass`)

| Класс | Диапазоны |
| --- | --- |
| `unspecified` | `0.0.0.0`, `::` |
| `loopback` | `127.0.0.0/8`, `::1` |
| `private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fec0::/10` |
| `cgnat` | `100.64.0.0/10` (провайдерский NAT, Tailscale) |
| `linkLocal` | `169.254.0.0/16`, `fe80::/10` |
| `uniqueLocal` | `fc00::/7` |
| `multicast` | `224.0.0.0/4`, `ff00::/8` |
| `broadcast` | `255.255.255.255` |
| `public` | всё остальное |

IPv4, отображённые в IPv6 (`::ffff:a.b.c.d`), классифицируются по IPv4-части.

## `tcpListeners[]`

Слушающие TCP-порты, отсортированы по адресу и порту: `{ localAddress, localPort, localClass, processId, process }`. `localClass = unspecified` — порт открыт на всех интерфейсах.

## `udpEndpoints[]`

Все UDP-точки (у UDP нет состояний и удалённой стороны): `{ localAddress, localPort, localClass, processId, process }`.

## `tcpConnections[]`

TCP-соединения в любом состоянии, кроме `Listen`, с непубличной удалённой стороной.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `state` | string | `Established`, `TimeWait`, `CloseWait`, `SynSent`, `Bound`, … |
| `localAddress`, `localPort` | string, int | |
| `remoteAddress`, `remotePort` | string, int | `0.0.0.0`/`::` и порт 0 у `Bound` |
| `remoteClass` | string | Не бывает `public` |
| `processId` | int | 0 у `TimeWait` (Idle) |
| `process` | string \| null | Имя процесса; `null`, если процесс уже завершился |

## `publicConnections[]`

Счётчики соединений с публичной удалённой стороной. Ключ — `process` + `processId` + `localAddress` + `remotePort`.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `process`, `processId` | | |
| `localAddress` | string | По нему виден интерфейс: физический или туннель |
| `remotePort` | int | 443, 53, 853 (DoT), порты VPN-протоколов, … |
| `connections` | int | Число соединений |
| `uniqueRemoteAddresses` | int | Число разных публичных адресов (сами адреса не хранятся) |
| `byState[]` | `{ state, count }` | |
