# Схема снимка TunnelEye

Версии: модуль `tunneleye.module/1`, снимок `tunneleye.snapshot/1`. Несовместимое изменение — новая версия схемы и запись в `docs/DECISIONS.md`.

## Конверт модуля

Каждый модуль сбора выдаёт ровно один JSON-объект:

```json
{
  "schema": "tunneleye.module/1",
  "module": "routing",
  "version": "1.0.0",
  "status": "partial",
  "elevated": false,
  "startedAt": "2026-10-23T10:15:02.123Z",
  "durationMs": 840,
  "errors": [
    { "source": "Get-NetRoute", "kind": "AccessDenied", "message": "…", "fatal": false }
  ],
  "data": { }
}
```

| Поле | Тип | Смысл |
| --- | --- | --- |
| `schema` | string | Версия схемы конверта |
| `module` | string | Имя модуля = имя файла `collectors/<module>.ps1`, `[a-z][a-z0-9-]*` |
| `version` | string \| null | Версия модуля (semver); `null`, если конверт создан оркестратором |
| `status` | string | `ok` \| `partial` \| `failed` \| `skipped` |
| `elevated` | bool | Модуль работал с правами администратора |
| `startedAt` | string | Время старта, ISO 8601 UTC с миллисекундами |
| `durationMs` | integer | Длительность |
| `errors` | array | Ошибки по источникам (всегда массив, может быть пустым) |
| `data` | object \| null | Данные модуля; структура — в `docs/schema/<module>.md` |

### Статусы

| Статус | Когда | `data` | `errors` |
| --- | --- | --- | --- |
| `ok` | Все источники отработали | есть | пусто |
| `partial` | Часть источников упала или пропущена без прав админа | есть | не пусто |
| `failed` | Данных нет: модуль упал, завис, выдал мусор | `null` | не пусто |
| `skipped` | Модуль неприменим (нет Wi-Fi-адаптера и т.п.) | `null` | причина |

Без прав админа модуль, которому они не нужны, остаётся `ok`. Пропущенный админский источник даёт ошибку `AccessDenied` → `partial`. Урезанный режим снимка в целом виден по `host.elevated`.

### Ошибки

| Поле | Смысл |
| --- | --- |
| `source` | Источник: командлет, утилита, ключ реестра; `collector` — тело модуля; `orchestrator` — оркестратор |
| `kind` | `AccessDenied` \| `NotSupported` \| `NotFound` \| `Timeout` \| `Exception` |
| `message` | Техническое сообщение (не строка интерфейса; может быть локализовано Windows) |
| `fatal` | `true`, если из-за ошибки модуль не выдал данных |

Ошибка привязана к источнику, поэтому анализатор отличает «данных нет» от «проблем нет»: если источник упал, соответствующее поле `data` равно `null`, а не `[]`.

## Снимок

Оркестратор (`collectors/Invoke-Snapshot.ps1`) пишет каталог:

```
snapshot-YYYYMMDD-HHMMSS/
  snapshot.json          весь снимок
  modules/<module>.json  конверт каждого модуля как есть
```

```json
{
  "schema": "tunneleye.snapshot/1",
  "snapshotId": "guid",
  "createdAt": "…Z",
  "tool": { "name": "TunnelEye", "version": "0.1.0" },
  "host": { "osBuild": "26200.1234", "psVersion": "5.1…", "culture": "ru-RU", "uiCulture": "ru-RU", "elevated": false, "elevatedAsOtherUser": null },
  "externalAllowed": false,
  "summary": { "ok": 11, "partial": 1, "failed": 0, "skipped": 1, "durationMs": 95000 },
  "modules": { "system": { } }
}
```

`host.elevatedAsOtherUser` — сбор шёл под учётной записью другого администратора (UAC, D-015): `HKCU` и `%LOCALAPPDATA%` не пользователя. GUI передаёт `Invoke-Snapshot.ps1 -LaunchingUserSid <SID>`; в снимок пишется только результат сравнения с SID процесса, сам SID — нет. `null` — SID не передан (запуск не из GUI).

`progress.jsonl` в каталоге снимка — ход запуска, по JSON-объекту на строку, дописывается по мере работы (процесс под UAC не отдаёт stdout окну):
- `{"event":"start","modules":[…],"elevated":…,"elevatedAsOtherUser":…,"externalAllowed":…,"time":…}`;
- `{"event":"moduleStart","module":"…","index":0,"total":13,"time":…}`;
- `{"event":"moduleEnd","module":"…","index":0,"total":13,"status":"ok","durationMs":…,"time":…}`;
- `{"event":"end","snapshot":"snapshot.json","ok":…,"partial":…,"failed":…,"skipped":…,"durationMs":…,"time":…}`.

Оркестратор можно запускать и через `powershell.exe -File`: каталог сборщиков (`-CollectorPath`) по умолчанию определяется в теле скрипта — в Windows PowerShell 5.1 `$PSScriptRoot` в умолчаниях параметров при `-File` пуст.

`externalAllowed` — было ли на этот запуск дано явное согласие на внешние тесты связи (D-002, `Invoke-Snapshot.ps1 -AllowExternal`); подробности — в модуле `connectivity`. Совместимое добавление поля, версия схемы снимка прежняя.

`modules` — объект в порядке запуска; ключ = имя модуля, значение — конверт. Модуль, который упал, завис (таймаут), не создал файл или выдал невалидный конверт, заменяется конвертом `failed` с ошибкой от `orchestrator`.

## Соглашения для `data`

- Ключи — camelCase. Словари с ключами из данных запрещены: вместо `{"Ethernet": {...}}` — массив `[{"name": "Ethernet", ...}]`.
- Каждое поле присутствует всегда; неизвестное значение — `null`.
- Списки — всегда массивы, даже из 0 или 1 элемента.
- Enum — строкой (`"Up"`, а не `2`).
- Время — ISO 8601 UTC `yyyy-MM-ddTHH:mm:ss.fffZ`; длительности — мс; размеры — байты; скорости — бит/с.
- Поля проецируются явно (`[ordered]@{ name = $a.Name; ... }`), объекты командлетов целиком не сериализуются: так схема стабильна и в JSON не утекает лишнее.
- Разобранный вывод `netsh` и других локализованных утилит сопровождается исходным текстом в поле `raw`.
- Никогда не пишутся: пароли, ключи Wi-Fi, содержимое пакетов, история браузера (в т.ч. полный DNS-кэш — см. D-003).

## Как писать модуль

```powershell
# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'routing' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    $routes = Invoke-Source -Context $ctx -Source 'Get-NetRoute' -AsList -ScriptBlock {
        Get-NetRoute -ErrorAction Stop | ForEach-Object { [ordered]@{ destinationPrefix = $_.DestinationPrefix } }
    }
    [ordered]@{ routes = $routes }
}
```

- `Invoke-Source` — один источник; ошибки записываются в `errors` и не выходят наружу. `-AsList` — всегда массив при успехе, `null` при падении. `-RequiresAdmin` — пропуск без прав.
- `Invoke-NativeCommand` — консольная утилита с таймаутом; кодировка вывода (OEM / UTF-8 / UTF-16) определяется автоматически.
- `Invoke-AllowNotFound { ... }` — для командлетов `Net*`, которые сообщают «список пуст» ошибкой ObjectNotFound (нет сети, пустое хранилище, протокол не установлен): это пустой результат, остальные ошибки пробрасываются.
- `New-SkipResult 'причина'` — модуль неприменим.
- Тело модуля должно вернуть ровно один словарь; лишний вывод в конвейер делает модуль `failed`.
- Массивы не присваивать через `$x = if (...) { @(...) }`: выражение `if` разворачивает массив (`@()` → `$null`, один элемент → скаляр). Писать `$x = $null; if (...) { $x = @(...) }`.
- Чтобы вспомогательные функции модуля можно было тестировать, перед `Invoke-Collector` ставится `if ($MyInvocation.InvocationName -eq '.') { return }`: dot-source загружает функции без сбора.
- Файлы `.ps1`/`.psm1` — только ASCII (PowerShell 5.1 читает файлы без BOM как ANSI).

## Тесты

```powershell
Invoke-Pester tests\collectors
```

Pester 3.4 встроен в Windows 10/11. Для модуля `<module>` — `tests/collectors/<Module>.Tests.ps1`: валидный конверт (`Get-EnvelopeProblems`), camelCase (`Get-NonCamelCaseKeys`), отсутствие секретов, поведение без админа.
