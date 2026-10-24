# Модуль `vpn`

Версия модуля 1.1.0 (1.1.0: `owners` у процессов общих сигнатур). Файлы: `collectors/vpn.ps1`, сигнатуры — `collectors/vpn-signatures.json`. Права администратора не нужны: без них модуль `ok`; с ними дополнительно определяется, какому клиенту принадлежат ядра прокси (`owners`).

Модуль собирает факты, не делая выводов. «Конфликт VPN», «остатки старых VPN», kill switch и split tunneling сторонних клиентов считает анализатор (этап 2): сопоставляет `clients` с модулями `adapters` и `routing` по `interfaceIndex`, а с модулем `firewall` — по фильтрам WFP. Признаки: маршруты `0.0.0.0/1` + `128.0.0.0/1` или широкий маршрут через туннель — полный туннель; отдельные префиксы — split tunneling; блокирующие фильтры WFP клиента — kill switch.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `builtIn.profiles` | `Get-VpnConnection`, `Get-VpnConnection -AllUserConnection` |
| `builtIn.services` | `Win32_Service` |
| `clients` | `vpn-signatures.json` + `Win32_Service`, `Win32_SystemDriver`, `Get-NetAdapter`, `Get-Process`, `Uninstall` (реестр) |
| `clients[].processes[].owners` | `Win32_Process` (только с правами админа) |

Если упал один источник инвентаря, сопоставление идёт по остальным; ошибка источника — в `errors`, статус `partial`.

## `builtIn.profiles[]`

Встроенные VPN-профили Windows (телефонная книга RAS). Конфигурация EAP (XML) и общие ключи не собираются.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | Имя профиля. Личные данные: часто содержит название организации |
| `guid` | string \| null | Нижний регистр, без скобок |
| `allUserConnection` | bool | `true` — профиль для всех пользователей (в т. ч. Always On / device tunnel) |
| `serverAddress` | string | Адрес или имя сервера. Личные данные |
| `servers[]` | `{ serverAddress, friendlyName }` | Дополнительные серверы |
| `tunnelType` | string | `Pptp` \| `L2tp` \| `Sstp` \| `Ikev2` \| `Automatic` |
| `authenticationMethod` | string[] | `Pap`, `Chap`, `MsChapv2`, `Eap`, `MachineCertificate` |
| `encryptionLevel` | string | `NoEncryption` \| `Optional` \| `Required` \| `Maximum` \| `Custom` |
| `l2tpIPsecAuth` | string \| null | Способ, не значение: `Psk` \| `Certificate` |
| `connectionStatus` | string | `Connected` \| `Disconnected` \| … |
| `splitTunneling` | bool | Раздельное туннелирование |
| `routes[]` | `{ destinationPrefix, routeMetric }` | Маршруты профиля (при split tunneling) |
| `dnsSuffix` | string \| null | Маскируется при экспорте (D-006) |
| `idleDisconnectSeconds` | int | |
| `rememberSignIn` | bool | Windows хранит данные входа (`RememberCredential`); сами данные не собираются |
| `useWindowsSignIn` | bool | Вход с учётной записью Windows (`UseWinlogonCredential`) |
| `proxy` | object \| null | `proxyServer`, `autoConfigUrl`, `bypassProxyForLocal`, `userInfoRemoved` — `user:password@` удаляется, как в `dns-proxy` |

## `builtIn.services[]`

Службы встроенного VPN: `RasMan`, `RemoteAccess`, `IKEEXT`, `PolicyAgent`, `SstpSvc` — `{ name, state, startMode }`.

## `clients[]`

Сторонние VPN-клиенты, прокси-туннели и средства обхода DPI, найденные по сигнатурам. Запись есть, только если совпал хотя бы один элемент. Порядок — как в файле сигнатур.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `id`, `name` | string | Из сигнатуры |
| `kind` | string | `vpn` \| `mesh` (Tailscale, ZeroTier, Radmin, Hamachi) \| `proxy-tunnel` (v2rayN, Hiddify, NekoRay, ядра xray/sing-box) \| `dpi-bypass` (GoodbyeDPI и аналоги) \| `driver` (TAP-Windows, Wintun, WinDivert) |
| `generic` | bool | Общая сигнатура (драйвер или ядро без привязки к клиенту): получает только элементы, не совпавшие ни с одной конкретной |
| `software[]` | `{ displayName, displayVersion, publisher, scope }` | Записи «Программы и компоненты»; `scope`: `machine` \| `user` (HKCU учётной записи, от которой запущен модуль) |
| `services[]`, `drivers[]` | см. ниже | Службы и драйверы-службы |
| `adapters[]` | `{ name, interfaceDescription, interfaceIndex, componentId, status }` | `status` как в `Get-NetAdapter`, включая `Not Present` |
| `processes[]` | `{ name, count }`; у общих сигнатур ещё `owners` | Только имя процесса и число экземпляров; пути и командные строки не собираются |

Служба или драйвер:

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name`, `displayName` | string | |
| `state` | string | `Running` \| `Stopped` \| … |
| `startMode` | string | `Auto` \| `Manual` \| `Disabled` \| `Boot` \| `System` |
| `imagePath` | string \| null | Путь к файлу без аргументов. Папка профиля `C:\Users\<имя>` заменена на `%USERPROFILE%` |
| `imageExists` | bool \| null | Файл существует. `false` у службы — признак остатка удалённого ПО |
| `hasArguments` | bool | У службы есть аргументы командной строки (сами аргументы не собираются: могут содержать токены) |

## Сигнатуры

`collectors/vpn-signatures.json`, схема `tunneleye.vpn-signatures/1`. Новый клиент добавляется без правки кода. Поля записи: `id`, `name`, `kind`, `generic` (необязательно) и шаблоны — регулярные выражения .NET без учёта регистра, `null` — не проверять:

| Шаблон | С чем сравнивается |
| --- | --- |
| `services`, `drivers` | Имя службы |
| `adapters` | Имя адаптера, описание, `componentId` |
| `processes` | Имя процесса |
| `software` | `DisplayName` записи удаления |

Ядра прокси (`xray`, `sing-box`) запускаются разными клиентами, поэтому они в общей записи `proxy-core`.

## `owners` — чей это процесс

Есть у процессов общих сигнатур (`generic = true`). `null` — без прав администратора (пути процессов других учётных записей скрыты, связь ищет анализатор); с правами — массив, пустой, если владелец не найден.

| Поле | Тип | Значения |
| --- | --- | --- |
| `clientId` | string | `id` конкретного клиента из `clients` |
| `evidence` | string | `parentProcess` — один из предков процесса (до 3 уровней) — процесс клиента; `imagePath` — исполняемый файл лежит в папке клиента (папка его службы или его процесса, кроме системных папок Windows) |

Родитель, запущенный позже потомка, не учитывается: это повторно использованный PID. Пути нужны только для сопоставления и в снимок не попадают.
