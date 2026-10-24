# Модуль `routing`

Версия модуля 1.1.0 (1.1.0: `routeSelection`, `interfaceMetric` и `effectiveMetric` в маршрутах). Файл: `collectors/routing.ps1`. Права администратора нужны только для списка подключений ICS; без них модуль `partial` с единственной ошибкой `HNetCfg.HNetShare = AccessDenied`.

Модуль собирает факты, не делая выводов. Признаки «двух шлюзов», петель, ICS и мостов считает анализатор (этап 2), сопоставляя `routes`, `interfaces` и модуль `adapters` по `interfaceIndex`.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `routes` | `Get-NetRoute` (активная таблица, compartment по умолчанию) |
| `persistentRoutes` | `Get-NetRoute -PolicyStore PersistentStore` |
| `routeSelection` | `Find-NetRoute <цель>` — отдельный источник на каждую цель |
| `interfaces` | `Get-NetIPInterface` |
| `addresses` | `Get-NetIPAddress` |
| `ipEnableRouter` | `IPEnableRouter` (реестр `Tcpip\Parameters`) |
| `bridge` | `bridge` (`Get-NetAdapter`, `Get-NetAdapterBinding -ComponentID ms_bridge`) |
| `ics.service` | `SharedAccess` (служба и реестр) |
| `ics.connections` | `HNetCfg.HNetShare` (COM, только с правами админа) |

ТЗ называет источником также `Get-NetIPConfiguration`; это составной командлет поверх тех же данных, поэтому адреса берутся напрямую из `Get-NetIPAddress`, шлюзы — из маршрутов `0.0.0.0/0` и `::/0`, DNS — в модуле `dns-proxy`.

## `routes[]`, `persistentRoutes[]`

Отсортированы по семейству, индексу интерфейса, префиксу.

| Поле | Тип | Пример / значения |
| --- | --- | --- |
| `addressFamily` | string | `IPv4` \| `IPv6` |
| `destinationPrefix` | string | `0.0.0.0/0`, `::/0`, `10.0.0.0/8` |
| `nextHop` | string | `192.168.1.1`; `0.0.0.0` / `::` — on-link |
| `interfaceIndex` | int | |
| `interfaceAlias` | string | Локализовано |
| `routeMetric` | int | Метрика маршрута |
| `interfaceMetric` | int \| null | Метрика интерфейса того же индекса и семейства (из `interfaces`) |
| `effectiveMetric` | int \| null | `routeMetric + interfaceMetric` — по ней Windows выбирает маршрут; `null`, если метрика интерфейса неизвестна |
| `protocol` | string | `NetMgmt` (статический/VPN), `Dhcp`, `Local`, `RouterAdvertisement`, … |
| `publish` | string | `No` \| `Age` \| `Yes` |

## `routeSelection[]`

Какой маршрут Windows реально выбирает для цели. `Find-NetRoute` — запрос к локальной таблице маршрутов, пакеты не отправляются (не нарушает правило «никаких запросов наружу»).

Цели:

| `kind` | `target` | Зачем |
| --- | --- | --- |
| `externalIPv4` | `192.0.2.1` | Путь произвольного адреса в интернете. Документационный префикс (RFC 5737) не встречается в реальных таблицах, поэтому побеждает маршрут по умолчанию или широкий маршрут VPN |
| `externalIPv6` | `2001:db8::1` | То же для IPv6 (RFC 3849) |
| `gateway` | next hop каждого маршрута `0.0.0.0/0` и `::/0` | Через какой интерфейс доступен сам шлюз |

| Поле | Тип | Примечание |
| --- | --- | --- |
| `kind`, `target` | string | |
| `reachable` | bool \| null | `false` — маршрута нет (Windows: «сеть недоступна», 1231); `null` — поиск упал, ошибка в `errors` |
| `sourceAddress` | string \| null | Адрес источника, который Windows выберет |
| `interfaceIndex`, `interfaceAlias` | | Выбранный интерфейс |
| `destinationPrefix`, `nextHop` | string \| null | Выбранный маршрут |
| `routeMetric`, `interfaceMetric`, `effectiveMetric` | int \| null | Как в `routes` |

При неудачном поиске запись содержит только `kind`, `target` и `reachable = null`.

## `interfaces[]`

По одной записи на интерфейс и семейство адресов.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `interfaceIndex`, `interfaceAlias`, `addressFamily` | | |
| `connectionState` | string | `Connected` \| `Disconnected` |
| `interfaceMetric` | int \| null | `null` бывает у TUN-адаптеров (замечено у Wintun) |
| `automaticMetric` | bool \| null | |
| `forwarding` | bool \| null | Пересылка пакетов между интерфейсами |
| `dhcp` | bool \| null | |
| `ignoreDefaultRoutes` | bool \| null | |
| `weakHostSend`, `weakHostReceive` | bool \| null | Weak host model: важно для утечек мимо туннеля |
| `nlMtu` | int \| null | MTU сетевого уровня |

## `addresses[]`

| Поле | Тип | Значения |
| --- | --- | --- |
| `interfaceIndex`, `interfaceAlias`, `addressFamily` | | |
| `ipAddress` | string | IPv6 link-local — с `%<зона>`. Личные данные: маскируется при экспорте |
| `prefixLength` | int | |
| `prefixOrigin` | string | `Manual` \| `WellKnown` \| `Dhcp` \| `RouterAdvertisement` \| `Other` |
| `suffixOrigin` | string | `Manual` \| `WellKnown` \| `Dhcp` \| `Link` \| `Random` \| `Other` |
| `addressState` | string | `Preferred` \| `Deprecated` \| `Tentative` \| `Duplicate` \| `Invalid` |
| `skipAsSource` | bool | |

## `ipEnableRouter`

bool \| null — глобальная IP-маршрутизация (`IPEnableRouter = 1`); `null`, если значение не задано.

## `bridge`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `adapters[]` | `{ name, interfaceIndex, status }` | Минипорт MAC Bridge (`componentId = ms_bridgemp`) |
| `members[]` | `{ name, interfaceIndex }` | Адаптеры с включённой привязкой `ms_bridge` |

## `ics`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `service.status` | string | Служба SharedAccess: `Running` \| `Stopped` |
| `service.startType` | string | |
| `service.scopeAddress` | string \| null | Адрес, который ICS назначает частной стороне (обычно `192.168.137.1`). Без прав админа частная сторона находится по совпадению с `addresses[].ipAddress` |
| `connections` | array \| null | `null` без прав админа |
| `connections[].name`, `deviceName`, `guid` | string | |
| `connections[].sharingEnabled` | bool | |
| `connections[].sharingType` | string \| null | `Public` (раздающая сторона) \| `Private` (получающая) \| `null`, если общий доступ выключен |
