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

**Семантика:**
- Отсутствующее поле и `null` проваливают **любой** оператор, кроме `exists: false`: «нет поля» ≠ `false`, и `ne`/`notIn` на отсутствующем поле — тоже ложь.
- Числа сравниваются как decimal: `1` = `1.0` (JSON-ридер отдаёт `int`, `long` и `decimal` вперемешку).
- Строки сравниваются порядково, без учёта регистра.
- Значения разных типов никогда не равны (`1` ≠ `"1"`).
- `"$threshold.<имя>"` вместо значения (и внутри списков `in`) — порог правила. Неизвестный порог — ошибка загрузки.

## Результат анализа (`tunneleye.analysis/1`)

`tunneleye analyze <snapshot.json> [--rules <каталог>] [--json <файл>]` (`src/TunnelEye.Cli`). JSON:
- `schema`, `facts` (версия набора фактов), `snapshotId`;
- `ruleErrors[]`;
- `results[]`: `{ ruleId, level, experimental, status, reason, limitations[], evidence[{ values, sources[] }] }`.

| `status` | Смысл |
| --- | --- |
| `found` | Найдено, есть доказательства |
| `notFound` | Проверено, не найдено |
| `notChecked` | Нужный факт недоступен; `reason`: `module-missing:<модуль>`, `module-failed:<модуль>`, `module-skipped:<модуль>`, `unknown-fact` |

`limitations[]` — что внутри доступных фактов проверить не удалось. Например, `elevated-as-other-user:user-proxy-not-checked` (D-015) или `reachability-unknown:…`.

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
| `scheme`, `host`, `port` | | Разбор `ProxyServer` |
| `isLoopback` | bool | `127.x`, `::1`, `localhost` |
| `tcpStatus` | string \| null | TCP-проверка из `connectivity.proxies` (`open` \| `refused` \| `timeout` \| `error`); `null` — не проверялся |
| `listening` | bool \| null | Для loopback — есть ли в `connections.tcpListeners` слушатель на этом порту (`127.0.0.1`, `0.0.0.0`, `::`, `::1`); `null` — неизвестно |

При `host.elevatedAsOtherUser = true` записи `user` не строятся — ограничение `elevated-as-other-user:user-proxy-not-checked` (D-015).

### `leftovers`

Модуль `vpn`.

| `kind` | Когда |
| --- | --- |
| `tunnelDriverWithoutAdapter` | Драйвер TAP-Windows установлен, адаптера нет. **Не Wintun:** он создаёт адаптер только на время туннеля и ставится с приложениями — драйвер без адаптера норма (найдено на реальном снимке) |
| `tapAdapterWithoutClient` | Адаптер TAP-Windows, а клиента, который пользуется TAP (OpenVPN), не установлено |
| `adapterNotPresent` | Адаптер VPN-клиента в состоянии `Not Present` (устройство удалено, драйвер зарегистрирован) |

Поля: `kind`, `clientId`, `clientName`, `detail` (драйвер или описание адаптера), `status`. На этапе 2.2 добавятся службы с удалённым файлом и провайдеры WFP без клиента.
