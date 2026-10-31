# Правила детекта и факты (`tunneleye.rule/1`, `facts/1`)

Модель — D-014. Ядро: `src/Argus.Core`. Правила: `rules/*.json`, по файлу на правило, имя файла = `id`. Новое правило на существующих фактах — без правки кода; новый факт — правка ядра и новая версия набора фактов. Язык условий закрыт: расширение — только через ревью.

## Файл правила

```json
{
  "schema": "tunneleye.rule/1",
  "id": "dead-proxy",
  "level": "critical",
  "experimental": false,
  "facts": [ "proxies" ],
  "thresholds": { "name": 20 },
  "condition": { "from": "proxies", "where": { ... }, "having": { "count": { "gte": 1 } } },
  "text": {
    "title":   { "ru": "...", "en": "..." },
    "why":     { "ru": "...", "en": "..." },
    "details": { "ru": "...", "en": "..." },
    "fix":     { "ru": "...", "en": "..." }
  }
}
```

| Поле | Обязательно | Смысл |
| --- | --- | --- |
| `schema` | да | `tunneleye.rule/1` |
| `id` | да | `[a-z][a-z0-9-]*`, совпадает с именем файла |
| `level` | да | `critical` (Критично) \| `important` (Важно) \| `advice` (Совет) \| `info` (Инфо) |
| `experimental` | нет | `true` — не подтверждено на стенде: уровень не выше `advice`, на светофор не влияет (D-014) |
| `facts` | да | Факты, которые нужны правилу. Хотя бы один недоступен — результат «не проверено» с причиной |
| `thresholds` | нет | Именованные пороги: `"$threshold.<имя>"` в условии. Меняются в расширенном режиме (этап 6) |
| `condition` | да | Условие, см. ниже. `from` — один из `facts` |
| `text` | да | `title`, `why`, `fix` обязательны, `details` — по желанию; каждый текст — `ru` и `en` (тест). Тексты — для пользователя: простым языком, нейтрально |

Неизвестные ключи — ошибка. Правило с ошибкой не загружается, ошибка попадает в `ruleErrors` анализа; остальные правила работают.

## Условие

- `from` — имя факта, его элементы перебираются.
- `where` — предикат элемента. Без него подходят все элементы.
- `having` — `{"count": {"<op>": n}}` над числом подошедших (`eq`, `ne`, `lt`, `lte`, `gt`, `gte`). Без него — «хотя бы один».

Срабатывание несёт **доказательства**: подошедшие элементы со ссылками на источник в снимке (`routing.routes[3]`).

### Предикаты

| Предикат | Вид |
| --- | --- |
| Все | `{"allOf": [p, p, ...]}` |
| Любой | `{"anyOf": [p, p, ...]}` |
| Не | `{"not": p}` |
| Проверка поля | `{"path": "<путь>", "<оператор>": <значение>}` — ровно один оператор |

`path` — путь внутри элемента: `a.b`, `list[0].x`.

### Операторы

| Оператор | Значение | Смысл |
| --- | --- | --- |
| `eq`, `ne` | число, строка, bool | Равно / не равно |
| `lt`, `lte`, `gt`, `gte` | число или строка | Порядок |
| `in`, `notIn` | список | Входит / не входит |
| `match` | строка | Регулярное выражение .NET, без учёта регистра, таймаут 200 мс |
| `exists` | `true` \| `false` | Поле есть и не `null` / поля нет или `null` |
| `olderThanDays`, `newerThanDays` | число | Дата ISO в поле старше / новее N дней **относительно времени снимка** (`createdAt`), а не времени анализа |

**Семантика — трёхзначная логика (Клини):** результат проверки — `True`, `False` или `Unknown`; элемент совпадает только при `True`.
- Отсутствующее поле и `null` дают `Unknown` для **любого** оператора, кроме `exists` (он всегда `True`/`False`): «нет поля» ≠ `false`. `ne`/`notIn` на отсутствующем поле тоже `Unknown`.
- `not Unknown = Unknown` — `{"not": {"path": "enabled", "eq": true}}` у элемента без `enabled` **не совпадает**.
- `allOf`: есть `False` → `False`, иначе есть `Unknown` → `Unknown`, иначе `True`. `anyOf`: есть `True` → `True`, иначе есть `Unknown` → `Unknown`, иначе `False`.
- Сказать «нет поля — тоже подходит» можно только явно: `{"anyOf": [{"path": "x", "exists": false}, ...]}`.
- Числа сравниваются как decimal: `1` = `1.0` (JSON-ридер отдаёт `int`, `long` и `decimal` вперемешку).
- Строки сравниваются порядково, без учёта регистра.
- Значения разных типов никогда не равны (`1` ≠ `"1"`).
- `"$threshold.<имя>"` вместо значения (и внутри списков `in`) — порог правила. Неизвестный порог — ошибка загрузки. Порог-строка годится и для `match` (шаблон проверяется при загрузке): так список чувствительных имён hosts лежит в `thresholds` и в расширенном режиме меняется как порог.
- Сравнить два поля элемента нельзя (`apGeneration lt cardGeneration`) — такие сравнения считает факт и отдаёт готовым полем (`accessPointBelowCard`).

## Результат анализа (`tunneleye.analysis/1`)

`tunneleye analyze <snapshot.json> [--rules <каталог>] [--json <файл>]` (`src/TunnelEye.Cli`). JSON:
- `schema`, `facts` (версия набора фактов), `snapshotId`;
- `ruleErrors[]` — правила, которые не загрузились;
- `evaluationErrors[]` — факты и правила, упавшие при вычислении (исключение провайдера факта, таймаут регулярного выражения, неожиданные данные): упавший факт — только его правила «не проверено», остальные работают;
- `results[]`: `{ ruleId, level, experimental, status, reason, limitations[], evidence[{ values, sources[] }] }`.

| `status` | Смысл |
| --- | --- |
| `found` | Найдено, есть доказательства |
| `notFound` | Проверено, не найдено |
| `notChecked` | Нужный факт недоступен или правило упало; `reason`: `module-missing:<модуль>`, `module-failed:<модуль>`, `module-skipped:<модуль>`, `section-missing:<путь>`, `external-not-allowed` (нет согласия на внешние тесты, D-002), `wfp-not-collected` (WFP читается только под админом), `unknown-fact`, `fact-error:<тип исключения>`, `rule-error:<тип исключения>` |

`limitations[]` — что внутри доступных фактов проверить не удалось. Например:
- `elevated-as-other-user:user-proxy-not-checked` (D-015);
- `reachability-unknown:…`;
- `proxy-not-tested:<source>:<причина>` — действующий прокси, доступность которого не проверялась (`externalNotAllowed`, `module-failed:connectivity`, …);
- `ipv6-not-tested:<причина>` — полный туннель IPv4, маршрут IPv6 мимо него, а внешней проверки IPv6 не было;
- `dns-path-not-tested:<причина>` — полный туннель, а путь к DNS-серверу физического адаптера не проверялся;
- `firewall-filters-not-read`, `third-party-firewall`, `network-profile-unknown:…` — открытость порта не определить;
- `ics-connections-not-read` — служба ICS работает, список подключений без админа не читается;
- `wfp-providers-not-checked:<причина>`, `form-factor-unknown:<причина>`, `wifi-scan-not-read`, `vpn-clients-unknown:<причина>`, `tunnel-detection-unavailable:<причина>`, `full-tunnel-unknown:<причина>`.

`notFound` с непустыми `limitations` у правила «Критично» — это «проверено не всё», а не зелёный (светофор, часть 2.3).

Модель отчёта (светофор, «проверено не всё», тексты для пользователя) — этап 2.3, `tunneleye.report/1`.

## Факты `facts/1`

У каждого элемента — `Values` (поля ниже) и `Evidence` (пути в снимке).

### `adapters`

Модуль `adapters`; `vpn` — по желанию (без него туннель определяется только по описанию — ограничение `tunnel-detection-by-description`).

| Поле | Тип | Смысл |
| --- | --- | --- |
| `name`, `interfaceIndex`, `description`, `componentId`, `status`, `virtual` | | Из `adapters.adapters[]` |
| `isTunnel` | bool | Адаптер принадлежит VPN-клиенту, прокси-туннелю или драйверу туннеля в `vpn.clients` (кроме обхода DPI), или описание/`componentId` похожи на туннель (TAP, Wintun, WireGuard, WAN Miniport, PPP, VPN) |
| `clientId`, `clientKind` | string \| null | Чей адаптер по `vpn.clients` |
| `interfaceGuid`, `hardwareInterface`, `physicalMedium`, `mtu` | | Из `adapters.adapters[]` (`ndisPhysicalMedium`, `mtuSize`) |
| `driverProvider`, `driverVersion`, `driverDate` | | `driver.provider/version/date`; у встроенных драйверов Microsoft дата `2006-06-21` |

### `routeSummary`

Модуль `routing`; факт `adapters` — для признака туннеля. По одному элементу на семейство адресов, где есть маршрут по умолчанию. Маршруты интерфейсов в состоянии `Disconnected` не считаются.

| Поле | Тип | Смысл |
| --- | --- | --- |
| `family` | string | `IPv4` \| `IPv6` |
| `defaultRoutes` | int | Маршрутов `0.0.0.0/0` / `::/0` |
| `gateways` | int | Из них — со шлюзом (не on-link) на разных **не-туннельных** интерфейсах |
| `gatewayInterfaces` | string[] | Их интерфейсы |
| `metricSpread` | decimal \| null | Разница эффективных метрик этих шлюзов; `null`, если метрика какого-то неизвестна или шлюз один |
| `selectedInterfaceIndex` | int \| null | Интерфейс, который Windows выбирает для внешнего адреса (`routeSelection`) |
| `selectedIsTunnel` | bool \| null | Выбран туннель — полный VPN-туннель. Тогда два маршрута по умолчанию — норма |

### `proxies`

Модуль `dns-proxy`; `connectivity`, `connections` — по желанию. Без обоих — ограничение `reachability-unknown`. По элементу на запись прокси (строка `ProxyServer` может содержать несколько).

| Поле | Тип | Смысл |
| --- | --- | --- |
| `source` | string | `user` \| `machine` \| `winhttp` |
| `effective` | bool | Настройка действует. `user`: `ProxyEnable`. `machine`: `ProxyEnable` **и** политика `ProxySettingsPerUser = 0` (иначе HKLM не используется). `winhttp`: не «прямой доступ» |
| `scheme`, `host`, `port` | | Разбор `ProxyServer`; порт вне 1–65535 — `null` |
| `isLoopback` | bool | `127.x`, `::1`, `localhost` |
| `tcpStatus` | string \| null | TCP-проверка из `connectivity.proxies` (`open` \| `refused` \| `timeout` \| `error`); `null` — не проверялся |
| `listening` | bool \| null | Для loopback — есть ли в `connections.tcpListeners` слушатель на этом порту, **который обслуживает хост**: для IPv4-хоста — тот же адрес или `0.0.0.0`; для `::1` — `::1` или `::`; для `localhost` — любой из них. Сокет на `::` в Windows по умолчанию только IPv6 (`IPV6_V6ONLY`) и `127.0.0.1` не обслуживает. `null` — неизвестно |

При `host.elevatedAsOtherUser = true` записи `user` не строятся — ограничение `elevated-as-other-user:user-proxy-not-checked` (D-015). Действующий прокси без TCP-проверки и без данных о слушателе — ограничение `proxy-not-tested:<source>:<причина>`.

### `leftovers`

Модуль `vpn`.

| `kind` | Когда |
| --- | --- |
| `tunnelDriverWithoutAdapter` | Драйвер TAP-Windows установлен, адаптера нет. **Не Wintun:** он создаёт адаптер только на время туннеля и ставится с приложениями — драйвер без адаптера норма (найдено на реальном снимке) |
| `tapAdapterWithoutClient` | Адаптер TAP-Windows, а клиента, который пользуется TAP (OpenVPN), не установлено |
| `adapterNotPresent` | Адаптер VPN-клиента в состоянии `Not Present` (устройство удалено, драйвер зарегистрирован) |
| `serviceWithoutFile` | Служба или драйвер VPN-клиента (`vpn.clients[].services/drivers`) с `imageExists = false` |
| `wfpProviderWithoutService` | Сторонний провайдер WFP, чьей службы (`serviceName`) нет среди служб и драйверов модуля `services`: удалённый VPN или брандмауэр оставил его в постоянном хранилище WFP. `filters` — сколько у него фильтров. Нужны `firewall.wfp` (админ) и `services`, иначе ограничение `wfp-providers-not-checked` |

Поля: `kind`, `clientId`, `clientName`, `detail` (драйвер, описание адаптера, имя службы), `status`, `filters`.

### `missingFiles`

Модуль `services`; `vpn` — по желанию. Программа, чей файл удалён (`imageExists = false`), — следы удалённого ПО: `kind` = `service` \| `driver` \| `autostart` (включённый) \| `task` (действие сторонней задачи, кроме выключенной). Пути под `\WindowsApps\` не учитываются: файлы пакетных приложений и псевдонимов не читаются, проверка говорит «нет файла» о существующих (найдено на реальном снимке). Поля: `kind`, `name`, `imagePath`, `state`, `startMode`, `clientId` — VPN-клиент из `vpn.clients`, если служба его (такие — в `vpn-leftovers`).

### `tunnels`

Модуль `routing`, факт `adapters`. Туннельные адаптеры (`isTunnel`), которые подняты или несут маршруты подключённого интерфейса.

| Поле | Смысл |
| --- | --- |
| `name`, `interfaceIndex`, `description`, `clientId`, `clientKind`, `status` | Из факта `adapters` |
| `capturesDefaultIPv4` | Есть `0.0.0.0/0` или его половина `0.0.0.0/1` / `128.0.0.0/1` (OpenVPN def1) |
| `capturesDefaultIPv6` | Есть `::/0`, `::/1` или `8000::/1` |
| `selectedIPv4`, `selectedIPv6` | Windows выбирает этот интерфейс для внешнего адреса (`routeSelection`) |

Туннель без маршрута по умолчанию (WAN Miniport, mesh-сеть без выходного узла) несёт только свои префиксы и с другими не спорит.

### `tunnelCoverage`

Модуль `routing`, факт `adapters`; `connectivity` — по желанию. Один элемент.

| Поле | Смысл |
| --- | --- |
| `ipv4ViaTunnel`, `ipv6ViaTunnel` | Внешний адрес семейства идёт через туннель (полный туннель) |
| `ipv4InterfaceIndex`, `ipv6InterfaceIndex` | Выбранный интерфейс |
| `ipv6Reachable` | Маршрут к внешнему IPv6 вообще есть |
| `ipv6ExternalReached` | Внешний эхо-запрос IPv6 из `connectivity.external.ping` получил ответ через **не**туннельный интерфейс. Маршрута мало: VPN-клиент может блокировать такой трафик фильтрами WFP. `null` — внешних тестов или IPv6-целей не было |

### `dnsServers`

Модуль `dns-proxy`; факты `adapters`, `tunnelCoverage`, модуль `connectivity` — по желанию. По элементу на DNS-сервер интерфейса, без заглушек `fec0:0:0:ffff::1..3` (D-007) и без повторов на одном интерфейсе (HANDOFF).

| Поле | Смысл |
| --- | --- |
| `address`, `family`, `interfaceIndex`, `interfaceAlias`, `addressClass` | Адрес без зоны и его класс (как в `connections`) |
| `interfaceIsTunnel`, `interfaceUp` | По факту `adapters` |
| `viaInterfaceIndex`, `viaTunnel` | Через какой интерфейс маршрут к серверу (`connectivity.dnsServers[].via*`) — известно только для проверенных серверов; иначе `null`, не угадывается |
| `responds` | Сервер ответил на проверку `connectivity` |
| `fullTunnel` | `tunnelCoverage.ipv4ViaTunnel` |
| `nrptCatchAll` | В NRPT есть правило для «.» — все имена идут на его серверы; `null`, если NRPT не прочитан |

### `hostsEntries`

Модуль `dns-proxy`. По элементу на имя в hosts: `address`, `name`, `addressClass` (`unspecified`/`loopback` — блокировка, `private` — машина в локальной сети, `public` — имя закреплено за интернет-адресом). Какие имена чувствительные — список в правиле (D-007).

### `bridges`, `connectionSharing`

Модуль `routing`.
- `bridges`: сетевой мост Windows (MAC Bridge, `routing.bridge.adapters`) — `name`, `status`, `members` (число адаптеров с привязкой `ms_bridge`), `memberNames`. Мосты виртуальных машин сюда не входят.
- `connectionSharing`: ICS — подключения с включённым общим доступом (`name`, `sharingType` `Public`/`Private`). Без админа список не читается: при работающей службе SharedAccess частная сторона ищется по адресу ICS (`scopeAddress`) на интерфейсе (`inferred = true`), ограничение `ics-connections-not-read`.

### `traces`, `dnsAnswers` — только с внешними тестами

Модуль `connectivity`; без согласия (`external = null`) факты недоступны, `reason = external-not-allowed`.
- `traces` — по трассировке: `target`, `status`, `reached`, `hops`, `repeatedAddresses` — адресов, которые возвращаются после другого узла (A, B, A): пакет ходит по кругу. Один роутер на двух TTL подряд — не повтор. Петля проверяется **только** по трассировке (ответ на план 006, п. 6).
- `dnsAnswers` — по имени внешней проверки DNS, по DNS-серверам без системного резолвера (у hosts и DoH свои правила): `servers`, `sinkholeServers` (ответ `0.0.0.0`/`::`/`127.x`/`::1`), `nxdomainServers`, `answeredServers` (настоящий адрес), `failedServers`. Разные наборы адресов признаком не считаются (CDN).

### `snapshotInfo`

Один элемент: `elevated`, `elevatedAsOtherUser`, `externalAllowed` — для находок «Инфо».

### `wifiLinks`

Модуль `wifi` (`skipped` без Wi-Fi-адаптера — правила «не проверено» с `module-skipped:wifi`). По элементу на подключённый интерфейс.

| Поле | Смысл |
| --- | --- |
| `name`, `signalPercent`, `channel`, `radioType` | Из `wifi.interfaces[]` |
| `bandGHz` | Из `netsh`, на Windows 10 — по каналу (1–14 → `2.4`) |
| `linkGeneration`, `apGeneration`, `cardGeneration` | Поколение Wi-Fi линка, своей точки (`neighbors.bss[connected]`) и лучшее из `drivers[].radioTypesSupported`: b 1, a 2, g 3, n 4, ac 5, ax 6, be 7 |
| `accessPointBelowCard` | Точка слабее карты — ограничивает роутер |
| `linkBelowAccessPoint` | Линк слабее и точки, и карты — причина на стороне клиента |
| `overlappingNetworks` | Только на 2,4 ГГц: точек доступа других сетей в пределах 4 каналов; `null` без скана |
| `channelUtilizationPercent` | Загрузка канала, которую сообщает своя точка |

### `exposedPorts`

Модуль `connections`; `system`, `firewall` — по желанию. По элементу на TCP-порт на всех интерфейсах (`0.0.0.0`/`::`) и процесс: `port`, `process`, `addresses`, `allowingRules`, и:
- `publicNetwork` — подключённая сеть в профиле `Public`;
- `inboundAllowed` — брандмауэр Windows пропускает входящие на порт в профиле `Public`: профиль выключен или разрешает входящие по умолчанию, либо подходит включённое разрешающее правило для `Public`/`Any` и не подходит запрещающее (запрет сильнее, как в Windows). Правило сопоставляется трёхзначно: протокол TCP/Any; порт, диапазон или Any; программа Any или процесс слушателя; правило пакета (AppContainer) и правило только для loopback-адресов не подходят; непрочитанный фильтр (`null` без админа — адресные фильтры не читаются, а широкое правило может быть ограничено `127.0.0.1`) и правило службы без явного порта — «неизвестно». Итог `null` — ограничение `firewall-filters-not-read`; при стороннем брандмауэре — `third-party-firewall`.

Слушающий порт сам по себе не проблема: входящие в `Public` по умолчанию блокируются (HANDOFF).

### `wfpLayers`

Модуль `firewall`, нужен `firewall.wfp` (только под админом, иначе `wfp-not-collected`). По элементу на слой WFP, где есть сторонний владелец фильтра с завершающим callout-действием (`FWP_ACTION_CALLOUT_TERMINATING`/`_UNKNOWN`; инспекция только смотрит). Владелец — провайдер фильтра, иначе провайдер callout, иначе сам callout (у WinDivert провайдера нет). Владельцы Microsoft — константы `FWPM_PROVIDER_*`, имена-ссылки на ресурсы (`@…dll`), имена с Microsoft/Windows — не учитываются. Поля: `layerKey`, `thirdPartyOwners`, `owners`, `filters`.

### `interfaceMtu`

Модуль `routing`, факт `adapters`; `connectivity`, `tcp-stack` — по желанию. По элементу на поднятый физический адаптер (не туннель: у туннеля MTU меньше по устройству, PPPoE — адаптер PPP) с подключённым IPv4: `nlMtu` (MTU интерфейса), `adapterMtu`, `gatewayMtu` (MTU до шлюза из `connectivity.gateways`, если измерен), `registryMtu` (MTU, заданный вручную в `Tcpip\Parameters\Interfaces`; `0` пишут VPN-клиенты — не твик, не учитывается).

### `adapterProperties`

Модуль `adapters`, факт `adapters`; `hardware` — по желанию. По элементу на дополнительное свойство поднятого физического адаптера: `adapter`, `interfaceIndex`, `keyword`, `value` (сырое `registryValue[0]`; `displayValue` локализован), `displayValue`, `formFactor` (`hardware.system.pcSystemType`), `isDesktop` (`Desktop`/`Workstation` — да, `Mobile`/`Slate` — нет, иначе `null` и ограничение `form-factor-unknown`). Какие ключевые слова — энергосбережение, решает правило.

## Правила `rules/`

| Правило | Уровень | Факт | Экспериментальное |
| --- | --- | --- | --- |
| `vpn-conflict` | Критично | `tunnels`: ≥ 2 разных активных клиентов с маршрутом по умолчанию | |
| `dead-proxy` | Критично | `proxies` | |
| `two-gateways` | Важно | `routeSummary` | |
| `ipv6-bypass` | Важно | `tunnelCoverage`: полный туннель IPv4 и подтверждённый внешний IPv6 мимо него | |
| `hosts-sensitive` | Важно | `hostsEntries`: имя из списка чувствительных, адрес не loopback и не неопределённый | |
| `network-bridge` | Важно | `bridges` | |
| `mtu-low` | Важно | `interfaceMtu` < 1500 | |
| `dns-spoofing` | Важно | `dnsAnswers` | |
| `dns-leak` | Совет | `dnsServers` | да: спросит ли Windows этот сервер, зависит от приоритета интерфейсов и VPN-клиента |
| `wfp-conflict` | Совет | `wfpLayers` ≥ 2 сторонних владельцев | да (ответ на план 006, п. 5) |
| `routing-loop` | Совет | `traces` | да (п. 5–6) |
| `connection-sharing` | Совет | `connectionSharing` | да: так же работает «Мобильный хот-спот» |
| `open-ports` | Совет | `exposedPorts` | да: часть портов открывает сама Windows |
| `wifi-link-below-capability` | Совет | `wifiLinks` | да |
| `hosts-sensitive-blocked` | Совет | `hostsEntries`: чувствительное имя, loopback или неопределённый адрес | |
| `ndis-filter-leftover` | Совет | `leftovers`: фильтр NDIS без службы | да |
| `hosts-pinned` | Совет | `hostsEntries`: публичный адрес, имя не из списка | |
| `vpn-leftovers` | Совет | `leftovers` | |
| `missing-files` | Совет | `missingFiles` без `clientId` | |
| `outdated-driver` | Совет | `adapters`: физический, дата старше 1095 дней, не `2006-06-21` | |
| `adapter-power-saving` | Совет | `adapterProperties`: EEE/Green Ethernet на десктопе | |
| `wifi-weak-signal`, `wifi-crowded-channel`, `wifi-router-limits` | Совет | `wifiLinks` | |
| `not-elevated`, `external-not-run`, `elevated-as-other-user` | Инфо | `snapshotInfo` | |

Экспериментальные — не выше «Совет» и не влияют на светофор (D-014), пока не подтверждены на стенде.

## Тестовые снимки `tests/snapshots/`

Синтетические (D-014). `clean.json` — полный снимок всех 13 модулей с внешними тестами и WFP: на нём каждое правило реально проверено (`notFound`, не `notChecked`). Остальные — **наложения**:

```json
{ "schema": "tunneleye.test-overlay/1", "base": "clean", "patch": { "modules": { "...": {} } } }
```

`patch` вливается в `base` (база может быть сама наложением): объекты — по ключам, массивы, значения и `null` — заменяют. Так в файле только сама проблема, а база растёт в одном месте. Наложения читает тестовый код (`TestData.LoadTree`), CLI — нет. Регресс: каждый проблемный снимок даёт ровно свою находку, у каждого правила есть снимок, на чистых (`clean`, `clean-wifi`, `full-tunnel`, …) — ничего.


### Уточнения ревью 008

- `tunnels`: добавлены `clientKey` (`clientId` либо `adapter:<interfaceIndex>`) и `otherClientsCapturingDefault` — число других различных клиентов с поднятым адаптером и маршрутом по умолчанию. `vpn-conflict` требует `status = Up` и хотя бы одного такого клиента.
- `hosts-sensitive` исключает `addressClass = loopback | unspecified`; эти записи проверяет `hosts-sensitive-blocked` («Совет»). Оба правила и `hosts-pinned` используют одинаковый список чувствительных имён.
- `leftovers.kind = ndisFilterWithoutService`: сторонний зарегистрированный фильтр NDIS без службы в `services.services` и `services.drivers`. Поля `clientName` — componentId, `detail` — имя службы, `filterRunType` — тип запуска. Встроенные `ms_*` исключены. При недоступных списках — ограничение; обязательность сама по себе не признак остатка. Правило `ndis-filter-leftover` экспериментальное («Совет»).
- `elevated-as-other-user` («Инфо») проверяет `snapshotInfo.elevatedAsOtherUser`.
- Ручное разворачивание тестового снимка: `powershell -NoProfile -File tests/Expand-Overlay.ps1 tests/snapshots/vpn-conflict.json .local/expanded.json`.
