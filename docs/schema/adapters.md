# Модуль `adapters`

Версия модуля 1.0.0. Файл: `collectors/adapters.ps1`. Права администратора не нужны.

Модуль собирает факты и ничего не классифицирует: TAP, Wintun, Hyper-V, остатки VPN и т.п. распознаёт анализатор (этап 2) по `componentId`, `interfaceDescription`, `driver.provider` и `driverPackages`.

| Секция | Источник (`errors[].source`) | Если источник упал |
| --- | --- | --- |
| `adapters` | `Get-NetAdapter -IncludeHidden` | `null` |
| `adapters[].bindings` | `Get-NetAdapterBinding -IncludeHidden -AllBindings` | `null` у всех адаптеров |
| `adapters[].advancedProperties` | `Get-NetAdapterAdvancedProperty -IncludeHidden -AllProperties` | `null` у всех адаптеров |
| `adapters[].driver.infName/isSigned/signer` | `Win32_PnPSignedDriver` (класс `NET`) | `null` |
| `devices` | `Get-PnpDevice -Class Net` | `null` |
| `driverPackages`, `driverPackagesRaw` | `pnputil /enum-drivers` | `null` |

## `adapters[]`

Отсортированы по `interfaceIndex`.

| Поле | Тип | Пример / значения |
| --- | --- | --- |
| `name` | string | `Беспроводная сеть` (локализовано) |
| `interfaceDescription` | string | `Intel(R) Wi-Fi 6E AX210 160MHz` |
| `interfaceIndex` | int | Связь с `routing`, `dns-proxy`, `system.networkProfiles` |
| `interfaceGuid` | string \| null | `{7e05e5a1-…}`, нижний регистр |
| `macAddress` | string \| null | `E8-62-BE-F0-5E-97`. Личные данные: маскируется при экспорте |
| `status` | string | `Up` \| `Disconnected` \| `Disabled` \| `Not Present` \| … |
| `adminStatus` | string | `Up` \| `Down` |
| `mediaConnectionState` | string | `Connected` \| `Disconnected` \| `Unknown` |
| `virtual`, `hidden`, `hardwareInterface`, `connectorPresent`, `endpointInterface` | bool | |
| `componentId` | string \| null | `Wintun`, `tap0901`, `root\ftvnic_a`, `PCI\VEN_8086&…` |
| `pnpDeviceId` | string \| null | Связь с `devices[].instanceId` |
| `mediaType`, `physicalMediaType` | string \| null | `802.3`, `Native 802.11`, `IP`, … |
| `ndisPhysicalMedium` | int \| null | Код NDIS_PHYSICAL_MEDIUM |
| `mtuSize` | int \| null | |
| `receiveLinkSpeedBps`, `transmitLinkSpeedBps` | int \| null | бит/с |
| `driver` | object | См. ниже |
| `bindings` | array \| null | См. ниже |
| `advancedProperties` | array \| null | См. ниже |

### `driver`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `provider` | string \| null | `Intel`, `WireGuard LLC` |
| `version` | string \| null | |
| `date` | date \| null | `yyyy-MM-dd`. Встроенные драйверы Microsoft датированы `2006-06-21` — правило «устаревший драйвер» должно их исключать |
| `description` | string \| null | |
| `fileName` | string \| null | `Netwtw14.sys` |
| `ndisVersion` | string \| null | `6.60` |
| `infName` | string \| null | `oem101.inf`; связь с `driverPackages[].publishedName` |
| `isSigned` | bool \| null | `null` — подпись не найдена (нет записи в `Win32_PnPSignedDriver`) |
| `signer` | string \| null | |

### `bindings[]`

| Поле | Тип | Пример |
| --- | --- | --- |
| `componentId` | string | `ms_tcpip`, `ms_tcpip6`, `ms_server`, `ms_bridge`, `ms_ndiscap`, … |
| `displayName` | string | Локализовано |
| `enabled` | bool | |

Привязки содержат и NDIS LWF (фильтры) — их используют модули `services` и `vpn`.

### `advancedProperties[]`

Все свойства, включая служебные (`DriverDesc`, `InfPath`, …).

| Поле | Тип | Пример |
| --- | --- | --- |
| `keyword` | string | `*EEE`, `*JumboPacket`, `*LsoV2IPv4`, `EnableGreenEthernet` |
| `displayName` | string \| null | Локализовано |
| `displayValue` | string \| null | Локализовано |
| `registryValue` | string[] | Сырое значение — использовать в правилах вместо `displayValue` |

## `devices[]`

Все устройства класса Net, включая отсутствующие (`present = false`) — остатки удалённого ПО.

| Поле | Тип | Значения |
| --- | --- | --- |
| `instanceId` | string | |
| `friendlyName` | string \| null | |
| `manufacturer` | string \| null | |
| `status` | string | `OK` \| `Error` \| `Degraded` \| `Unknown` |
| `present` | bool | |
| `problem` | string \| null | Код проблемы диспетчера устройств строкой (`CM_PROB_NONE`, …) |
| `problemCode` | int \| null | Тот же код числом |

## `driverPackages[]`

Пакеты драйверов класса Net в хранилище драйверов, в том числе без устройств (остатки VPN).

| Поле | Тип | Пример |
| --- | --- | --- |
| `publishedName` | string | `oem23.inf` |
| `originalName` | string | `ftsvnic.inf` |
| `provider` | string | `Fortinet Inc` |
| `className` | string | Локализовано |
| `classGuid` | string | `{4d36e972-e325-11ce-bfc1-08002be10318}` |
| `driverDate` | date \| null | `null`, если формат даты не распознан |
| `driverVersion` | string \| null | |
| `signer` | string | |

Вывод `pnputil` локализован по языку интерфейса, поэтому поля берутся по позиции и проверяются по форме (`oem<N>.inf`, GUID). Блок класса Net, не прошедший проверку, в `driverPackages` не попадает, а в `errors` появляется запись. `driverPackagesRaw` — исходный текст всех блоков класса Net.
