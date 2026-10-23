# Модуль `routing`

Версия модуля 1.0.0. Файл: `collectors/routing.ps1`. Права администратора нужны только для списка подключений ICS; без них модуль `partial` с единственной ошибкой `HNetCfg.HNetShare = AccessDenied`.

Модуль собирает факты, не делая выводов. Признаки «двух шлюзов», петель, ICS и мостов считает анализатор (этап 2), сопоставляя `routes`, `interfaces` и модуль `adapters` по `interfaceIndex`.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `routes` | `Get-NetRoute` (активная таблица, compartment по умолчанию) |
| `persistentRoutes` | `Get-NetRoute -PolicyStore PersistentStore` |
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
| `nextHop` | string | `192.168.31.1`; `0.0.0.0` / `::` — on-link |
| `interfaceIndex` | int | |
| `interfaceAlias` | string | Локализовано |
| `routeMetric` | int | Метрика маршрута. Итоговая метрика = `routeMetric` + `interfaces[].interfaceMetric` того же интерфейса и семейства |
| `protocol` | string | `NetMgmt` (статический/VPN), `Dhcp`, `Local`, `RouterAdvertisement`, … |
| `publish` | string | `No` \| `Age` \| `Yes` |

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
