# Модуль `hardware`

Версия модуля 1.1.0 (1.1.0 — по ревью 003: `system.hypervisorPresent`, флаг виртуализации с учётом гипервизора). Файл: `collectors/hardware.ps1`. Без прав администратора модуль `partial` с единственной ошибкой `Get-StorageReliabilityCounter = AccessDenied`: счётчики SMART дисков читаются только с правами админа. Всё остальное собирается полностью.

Модуль собирает факты, не делая выводов. Узкие места (мало RAM, одноканальная память, HDD как системный диск, слабый CPU) и варианты апгрейда считает анализатор (этап 5) по своей базе моделей. Сетевая карта — в модуле `adapters` (модель, драйвер, скорость линка), здесь не дублируется.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `system` | `Win32_ComputerSystem` |
| `cpus` | `Win32_Processor` |
| `memory.modules` | `Win32_PhysicalMemory` |
| `memory.arrays` | `Win32_PhysicalMemoryArray` |
| `board` | `Win32_BaseBoard` |
| `bios` | `Win32_BIOS` |
| `gpus` | `Win32_VideoController` + реестр класса видеоадаптеров (`display class`) |
| `disks` | `Get-PhysicalDisk`, `Get-Partition` (системный диск), `Get-StorageReliabilityCounter` (только с правами админа) |
| `slots` | `Win32_SystemSlot` |

## Приватность (D-012)

Серийные номера (BIOS, платы, дисков, модулей памяти), UUID системы и машинно-специфичная часть PnP-идентификаторов не собираются: они однозначно указывают на конкретное устройство. Модели и номера деталей (part number, модели дисков) — сведения о железе, а не о человеке; они нужны для подбора апгрейда и при экспорте не маскируются (решение владельца).

Пустые значения и заглушки SMBIOS (`To Be Filled By O.E.M.`, `Default string`, `x.x`, `Unknown`, `0` и т. п.) записываются как `null`.

## `system`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `manufacturer`, `model` | string \| null | Производитель и модель ПК (у самосборных — обычно плата) |
| `pcSystemType` | string \| null | `Desktop` \| `Mobile` \| `Workstation` \| `Slate` \| … — десктоп или ноутбук важен для правил (энергосбережение адаптера, апгрейд) |
| `systemType` | string | `x64-based PC`, … |
| `hypervisorPresent` | bool \| null | Работает гипервизор (Hyper-V, VBS, WSL 2): Windows сама гость гипервизора |
| `totalPhysicalMemoryBytes` | int64 | Видимая Windows память |

## `cpus[]`

`{ name, manufacturer, cores, logicalProcessors, maxClockMhz, socket, l2CacheKb, l3CacheKb, architecture, virtualizationFirmwareEnabled, virtualizationSource }`. `architecture`: `x86` \| `x64` \| `ARM` \| `ARM64`.

- `socket` — `SocketDesignation` из SMBIOS. **Ненадёжно:** часто это не сокет, а метка на плате (`U3E1`, `CPU 1`, `SOCKET 0`). Сокет для совместимости — по модели CPU в базе этапа 5.
- `virtualizationFirmwareEnabled` — включена ли виртуализация (VT-x / AMD-V) в BIOS. Под работающим гипервизором Windows — гость, и флаги виртуализации `Win32_Processor` могут читаться как `False`; гипервизор без включённой виртуализации не работает, поэтому при `system.hypervisorPresent = true` пишется `true` и `virtualizationSource = 'hypervisor'`, иначе — значение CIM и `'cim'`.

## `memory`

`modules[]` — по одному на установленный модуль, отсортированы по банку и слоту:

| Поле | Тип | Примечание |
| --- | --- | --- |
| `bankLabel`, `deviceLocator` | string \| null | Банк и слот. Каналы видны по `bankLabel` (например, `CHANNEL A`/`B`): одноканальный режим — анализатор |
| `capacityBytes` | int64 | |
| `speedMts` | int \| null | Номинальная скорость модуля, МТ/с |
| `configuredSpeedMts` | int \| null | Скорость, на которой модуль работает сейчас. Меньше номинала, указанного в `partNumber`, — признак выключенного профиля XMP/EXPO (анализатор, по базе моделей) |
| `type` | string \| null | `DDR3` \| `DDR4` \| `DDR5` \| `LPDDR4` \| … (SMBIOS type 17) |
| `formFactor` | string \| null | `DIMM` \| `SODIMM` \| … |
| `manufacturer`, `partNumber` | string \| null | |

`arrays[]` — массивы системной памяти (`Use = 3`): `{ maxCapacityBytes, slots }` — максимум, который поддерживает плата, и число слотов. Свободные слоты = `slots` − число модулей.

## `board`, `bios`

`board`: `{ manufacturer, product, version }`. Модель платы определяет чипсет: чипсет напрямую в WMI не виден (через PnP — только безымянный «мост PCI — ISA»), его выводит анализатор по модели.

`bios`: `{ manufacturer, version, releaseDate (yyyy-MM-dd), smbiosVersion }` — версия BIOS важна для поддержки новых CPU.

## `gpus[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string \| null | |
| `vendorId`, `deviceId` | string \| null | Из PnP-идентификатора (`VEN_`, `DEV_`), без части экземпляра |
| `memoryBytes` | int64 \| null | Видеопамять |
| `memorySource` | string \| null | `registry` — `HardwareInformation.qwMemorySize` из ключа драйвера (точно); `cim` — `AdapterRAM` (32-битное поле: всё, что больше 4 ГБ, показывается как ~4 ГБ). Ключ драйвера сопоставляется с картой по имени (`DriverDesc` = `name`): у двух одинаковых карт имя одно, размер верный, но привязка к конкретной карте неоднозначна |
| `driverVersion`, `driverDate` | string \| null | |

Ключ класса видеоадаптеров читается по подразделам: его подраздел `Properties` закрыт для обычного пользователя, и перечисление `Get-ChildItem` целиком падает.

## `disks[]`

Отсортированы по `deviceId`.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `deviceId` | string | Номер диска |
| `friendlyName` | string \| null | Модель |
| `mediaType` | string | `HDD` \| `SSD` \| `SCM` \| `Unspecified` |
| `busType` | string | `NVMe` \| `SATA` \| `USB` \| `RAID` \| `SAS` \| … |
| `sizeBytes` | int64 | |
| `spindleSpeed` | int \| null | Обороты HDD; 0 у SSD |
| `healthStatus` | string | `Healthy` \| `Warning` \| `Unhealthy` |
| `operationalStatus` | string[] | |
| `firmwareVersion` | string \| null | |
| `isSystem` | bool \| null | На этом диске раздел Windows; `null`, если не удалось определить |
| `reliability` | object \| null | `null` без прав админа; иначе `{ temperatureC, temperatureMaxC, wearPercent, powerOnHours, readErrorsTotal, writeErrorsTotal }` — что сообщает диск (у многих полей бывает `null`) |

## `slots[]`

Слоты расширения по SMBIOS (`Win32_SystemSlot`): `{ designation, usage, maxDataWidth }`. `usage`: `Available` \| `InUse` \| `Unknown` \| `Other`. `designation` — как его подписал производитель платы (например, `M.2 Slot`, `PCIE x4 slot`); что за слот, анализатор определяет по подписи и `maxDataWidth`. Таблица SMBIOS у многих плат неполная — для апгрейда это подсказка, а не перечень.
