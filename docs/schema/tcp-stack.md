# Модуль `tcp-stack`

Версия модуля 1.0.0. Файл: `collectors/tcp-stack.ps1`. Без прав администратора модуль `partial` с единственной ошибкой `Get-NetTransportFilter = AccessDenied`. Это список того, какой шаблон TCP к каким портам применяется; по умолчанию он один — `Automatic` для всего.

Модуль собирает факты, не делая выводов. Отклонения от значений Windows по умолчанию — выключенная автонастройка окна, нестандартный congestion provider, ручные твики в реестре — оценивает анализатор (этап 2), вместе с качеством TCP из захвата (этап 3).

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `settings` | `Get-NetTCPSetting` |
| `transportFilters` | `Get-NetTransportFilter` (только с правами админа) |
| `offload` | `Get-NetOffloadGlobalSetting` |
| `netshGlobal` | `netsh int tcp show global` |
| `registry.global` | `registry tweaks` |
| `registry.interfaces` | `registry interface tweaks` |

## `settings[]`

Шаблоны TCP (`Internet`, `InternetCustom`, `Datacenter`, `DatacenterCustom`, `Compat`, `Automatic`), отсортированы по имени. У шаблона `Automatic` Windows не сообщает значений, все поля, кроме имени, `null`. Перечисления хранятся строками, как их пишет командлет; поля, которые Windows не сообщает, — `null`.

| Поле | Примечание |
| --- | --- |
| `settingName` | |
| `autoTuningLevelLocal`, `autoTuningLevelEffective`, `autoTuningLevelGroupPolicy` | Автонастройка окна приёма: `Normal`, `Disabled`, `HighlyRestricted`, `Restricted`, `Experimental`; `effective`: `Local` \| `GroupPolicy` |
| `scalingHeuristics` | |
| `congestionProvider` | `CUBIC`, `NewReno`, `CTCP`, `DCTCP`, `LEDBAT`, `BBR2` |
| `ecnCapability` | `Enabled` \| `Disabled` \| … |
| `timestamps` | RFC 1323 |
| `initialRtoMs`, `minRtoMs`, `delayedAckTimeoutMs`, `delayedAckFrequency`, `maxSynRetransmissions`, `initialCongestionWindowMss` | int \| null |
| `cwndRestart`, `nonSackRttResiliency`, `memoryPressureProtection`, `automaticUseCustom` | |
| `dynamicPortRangeStartPort`, `dynamicPortRangeNumberOfPorts` | Диапазон эфемерных портов |

## `transportFilters[]`

`null` без прав админа. `{ settingName, protocol, localPortStart, localPortEnd, remotePortStart, remotePortEnd, destinationPrefix }`.

## `offload`

Глобальные разгрузки — строки `Enabled` \| `Disabled` (у `networkDirectAcrossIPSubnets` — `Allowed` \| `Blocked`):
- `receiveSideScaling`, `receiveSegmentCoalescing`, `chimney`, `taskOffload`;
- `networkDirect`, `networkDirectAcrossIPSubnets`, `packetCoalescingFilter`.

Настройки разгрузок по адаптерам — в `adapters.adapters[].advancedProperties`.

## `netshGlobal`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `values[]` | `{ label, value }` | Строки «метка : значение» по порядку. Метки и значения локализованы (под сборщиком на русской Windows — по-русски), набор строк зависит от версии Windows, поэтому они не сопоставляются с полями. Есть то, чего нет в командлетах: Fast Open, HyStart, Proportional Rate Reduction, Pacing Profile |
| `raw` | string | Исходный текст |

## `registry`

Только значения из белого списка, которые реально заданы. В том же ключе `Tcpip\Parameters` лежат имя ПК, домен и DNS-серверы — они не собираются. Отсутствие значения означает умолчание Windows.

`global[]` — `{ scope, values[{ name, value }] }`:

| `scope` | Ключ | Значения |
| --- | --- | --- |
| `tcpip` | `Services\Tcpip\Parameters` | `Tcp1323Opts`, `TcpWindowSize`, `GlobalMaxTcpWindowSize`, `DefaultTTL`, `MaxUserPort`, `TcpTimedWaitDelay`, `TcpMaxDataRetransmissions`, `TcpMaxConnectRetransmissions`, `EnablePMTUDiscovery`, `EnablePMTUBHDetect`, `SackOpts`, `TcpNumConnections`, `DisableTaskOffload`, `EnableTCPChimney`, `EnableRSS`, `EnableTCPA`, `TcpAckFrequency`, `TCPNoDelay`, `TcpDelAckTicks`, `DeadGWDetectDefault`, `EnableDca`, `KeepAliveTime`, `KeepAliveInterval` |
| `tcpip6` | `Services\Tcpip6\Parameters` | `DisabledComponents` — отключение IPv6 через реестр (`0xFF` — полностью, `0x20` — предпочитать IPv4, …) |
| `afd` | `Services\AFD\Parameters` | `DefaultReceiveWindow`, `DefaultSendWindow`, `FastSendDatagramThreshold`, `FastCopyReceiveThreshold`, `IgnorePushBitOnReceives`, `NonBlockingSendSpecialBuffering` |
| `multimedia` | `Multimedia\SystemProfile` | `NetworkThrottlingIndex` (по умолчанию 10; `0xFFFFFFFF` — твик), `SystemResponsiveness` |
| `qosPolicy` | `Policies\Microsoft\Windows\Psched` | `NonBestEffortLimit` (резерв полосы QoS), `TimerResolution` |

`value` — число (DWORD/QWORD), строка или hex-строка (двоичные).

`interfaces[]` — `{ interfaceGuid, addressFamily, values[{ name, value }] }` из `Tcpip\Parameters\Interfaces\{guid}` (IPv4) и `Tcpip6\...` (IPv6). Собираются только интерфейсы, где задано что-то из `TcpAckFrequency`, `TCPNoDelay`, `TcpDelAckTicks`, `MTU`, `TcpWindowSize`. `interfaceGuid` в нижнем регистре, связь — с `adapters.adapters[].interfaceGuid`. `MTU = 0` пишут некоторые VPN-клиенты, это не твик.
