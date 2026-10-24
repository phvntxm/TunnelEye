# Модуль `firewall`

Версия модуля 1.0.0. Файл: `collectors/firewall.ps1`. Без прав администратора модуль `partial`:
- WFP не читается (`netsh wfp show state = AccessDenied`, `wfp = null`);
- фильтры портов читаются частично, адресные фильтры не читаются совсем (`Get-NetFirewallPortFilter` / `Get-NetFirewallAddressFilter = AccessDenied`).

Правила при этом собираются полностью.

Модуль собирает факты, не делая выводов. «Открытые порты», «Конфликт VPN и блокировок / антивируса», kill switch VPN-клиентов и «остатки» считает анализатор (этап 2). Для этого он сопоставляет:
- `rules` — с модулем `connections`;
- провайдеров и фильтры WFP — с `vpn.clients` (по `serviceName`, имени провайдера и callout-драйвера) и между собой (слой, подуровень, действие, вес).

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `profiles` | `Get-NetFirewallProfile -PolicyStore ActiveStore` |
| `rules` | `Get-NetFirewallRule -PolicyStore ActiveStore` + `Get-NetFirewallApplicationFilter`, `Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter` (`-All`, соединяются по `InstanceID`) |
| `products` | `SecurityCenter2 FirewallProduct` (CIM `root/SecurityCenter2`) |
| `services` | `Win32_Service` (`mpssvc`, `BFE`) |
| `wfp` | `netsh wfp show state` (только с правами админа) → `wfpstate.xml` |

`ActiveStore` — действующая политика: локальные правила, групповые политики и динамические правила вместе.

## `profiles[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | `Domain` \| `Private` \| `Public` |
| `enabled` | bool | |
| `defaultInboundAction`, `defaultOutboundAction` | string | `Block` \| `Allow` \| `NotConfigured` |
| `allowInboundRules`, `allowLocalFirewallRules`, `notifyOnListen`, `logAllowed`, `logBlocked` | string | `True` \| `False` \| `NotConfigured` (как в командлете) |
| `disabledInterfaceAliases` | string[] | Интерфейсы, на которых профиль выключен |
| `logFileName` | string \| null | Папка профиля заменена на `%USERPROFILE%` |

## `rules[]`

Отсортированы по `name`.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | Идентификатор правила. Windows вшивает путь к программе в имя (`TCP Query User{guid}C:\users\<имя>\…`) — папка профиля заменена на `%USERPROFILE%` |
| `displayName`, `displayGroup` | string | Локализованы; `displayGroup` может быть `null` |
| `enabled` | bool | |
| `direction` | string | `Inbound` \| `Outbound` |
| `action` | string | `Allow` \| `Block` |
| `profiles` | string[] | `Any` или список из `Domain`, `Private`, `Public` |
| `edgeTraversalPolicy` | string | `Block` \| `Allow` \| `DeferToUser` \| `DeferToApp` |
| `policyStoreSourceType` | string | `Local` \| `GroupPolicy` \| `Dynamic` \| … |
| `primaryStatus` | string | `OK` \| `Inactive` \| `Error` |
| `program` | string \| null | `Any`, `System` или путь (папка профиля скрыта); `null` — фильтр приложения не прочитан |
| `service`, `package` | string \| null | Служба; SID пакета (AppContainer) |
| `protocol` | string \| null | `TCP`, `UDP`, `Any`, номер |
| `localPorts`, `remotePorts` | string[] \| null | `Any`, номера, диапазоны, `RPC`, … |
| `localAddresses`, `remoteAddresses` | string[] \| null | Личные данные: маскируются при экспорте |

`null` в фильтрах означает «не прочитано» (частичное чтение без админа), а не «любой».

## `products[]`

Сторонние брандмауэры, зарегистрированные в Центре безопасности Windows (антивирусы с брандмауэром). На Windows Server пространства имён нет: секция `null`, ошибка `NotSupported`.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `displayName` | string | |
| `productState` | int | Как сообщает Центр безопасности |
| `enabled` | bool \| null | Байт 2 `productState` = `0x10` |
| `upToDate` | bool \| null | Байт 3 = `0x00` |

## `services[]`

`{ name, state, startMode }` для `BFE` (Base Filtering Engine, основа WFP) и `mpssvc` (брандмауэр Windows).

## `wfp`

`null` без прав администратора. `netsh` умеет писать состояние только в файл: он создаётся во временной папке под уникальным именем и удаляется сразу после разбора.

**Не собираются:**
- сессии WFP (в них имена пользователей);
- подключённые конечные точки (это история соединений);
- контексты провайдеров и IPsec SA — от них только счётчик `providerContextCount`;
- статистика IKE/IPsec;
- данные провайдеров;
- **значения условий фильтров** (адреса, пути приложений): от условия остаются поле и тип сравнения.

### `wfp.providers[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `providerKey` | string | Имя константы (`FWPM_PROVIDER_MPSSVC_WF`) или GUID в фигурных скобках |
| `name` | string \| null | Локализовано, может быть ссылкой на ресурс (`@bfe.dll,-1217`) |
| `serviceName` | string \| null | Служба провайдера — связь с `vpn.clients[].services` |
| `flags` | string[] | `FWPM_PROVIDER_FLAG_PERSISTENT`, `FWPM_PROVIDER_FLAG_DISABLED` |

### `wfp.subLayers[]`

`{ subLayerKey, name, providerKey, weight (int), flags[] }`. Вес подуровня определяет порядок арбитража между подуровнями.

### `wfp.callouts[]`

`{ calloutKey, calloutId, name, providerKey, applicableLayer, flags[] }`. Callout — драйвер, который смотрит или меняет трафик на слое (VPN, антивирусы, WinDivert). Флаг `FWPM_CALLOUT_FLAG_REGISTERED` — драйвер загружен.

### `wfp.filters[]`

Отсортированы по `filterId`.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `filterId` | int | |
| `filterKey` | string | |
| `name` | string \| null | Фильтры брандмауэра носят имя правила; папка профиля скрыта |
| `providerKey` | string \| null | `null` — фильтр без провайдера (так делает, например, WinDivert) |
| `layerKey`, `subLayerKey` | string | |
| `action` | string | `FWP_ACTION_PERMIT` \| `FWP_ACTION_BLOCK` \| `FWP_ACTION_CALLOUT_TERMINATING` \| `FWP_ACTION_CALLOUT_INSPECTION` \| `FWP_ACTION_CALLOUT_UNKNOWN` |
| `calloutKey` | string \| null | Для действий `FWP_ACTION_CALLOUT_*` — какой callout вызывается |
| `weight` | string \| null | Заданный вес, десятичной строкой (64-битные значения не помещаются в точные числа JSON); `null` — `FWP_EMPTY`, вес назначает BFE |
| `effectiveWeight` | string \| null | Итоговый вес внутри подуровня, десятичной строкой |
| `flags` | string[] | `FWPM_FILTER_FLAG_PERSISTENT`, `…_BOOTTIME`, `…_INDEXED`, … |
| `conditions[]` | `{ fieldKey, matchType }` | Без значений |

`providerContextCount` — int, число контекстов провайдеров (IPsec и VPN-политики).

Объём: тысяча с лишним фильтров WFP — порядка 1 МБ JSON; это основная часть модуля под админом.
