# Модуль `services`

Версия модуля 1.0.0. Файл: `collectors/services.ps1`. Права администратора не нужны: без них модуль `ok`.

Модуль собирает факты, не делая выводов. «Лишние службы» — службы и адаптеры от удалённого ПО, остатки старых VPN — считает анализатор (этап 2). Признаки:
- `imageExists = false` у службы, драйвера, автозапуска или задачи;
- совпадение с `vpn.clients`;
- NDIS-фильтр со службой, которой нет;
- `filterRunType = mandatory` у фильтра стороннего производителя.

| Секция | Источник (`errors[].source`) |
| --- | --- |
| `services` | `Win32_Service` |
| `drivers` | `Win32_SystemDriver` |
| `autostart` | `Run keys` (реестр), `Startup folders` |
| `scheduledTasks` | `Get-ScheduledTask` |
| `ndisFilters` | `NetService class` (реестр `Control\Network\{4d36e974-…}`), `Get-NetAdapterBinding` |

## Общие правила приватности

- Пути — без аргументов командной строки (в аргументах бывают токены и пути конфигов). Есть только флаг `hasArguments`.
- Папка профиля `C:\Users\<имя>` заменяется на `%USERPROFILE%`, SID пользователя (`S-1-5-21-…`) — на `%USERSID%`, в том числе внутри имён и путей задач.
- Учётные записи хранятся классом (`account`), не именем.
- `company` — поле CompanyName из версии файла (не подпись: проверка Authenticode для сотен файлов слишком долгая). Пустое у файлов без ресурса версии.

Классы учётных записей: `localSystem`, `localService`, `networkService`, `virtualService` (`NT SERVICE\…`), `interactive`, `users`, `administrators`, `authenticatedUsers`, `userAccount` (любая другая — пользователь или служебная учётка), `null` — не задана (так у пользовательских служб `…_<суффикс>`).

## `services[]`

Все службы, отсортированы по имени.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name`, `displayName` | string | |
| `state` | string | `Running` \| `Stopped` \| … |
| `startMode` | string | `Auto` \| `Manual` \| `Disabled` |
| `serviceType` | string | `Own Process` \| `Share Process` \| … |
| `account` | string \| null | Класс учётной записи |
| `imagePath` | string \| null | Исполняемый файл (`svchost.exe` у общих служб) |
| `imageExists` | bool \| null | `false` — файл удалён: признак остатка |
| `hasArguments` | bool | |
| `company` | string \| null | |

## `drivers[]`

Все драйверы-службы (`Win32_SystemDriver`): `name`, `displayName`, `state`, `startMode` (`Boot` \| `System` \| `Auto` \| `Manual` \| `Disabled`), `serviceType` (`Kernel Driver` \| `File System Driver`), `imagePath`, `imageExists`, `company`.

## `autostart[]`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `name` | string | Имя значения реестра или файла в папке «Автозагрузка» |
| `location` | string | `HKLM\Run`, `HKLM\RunOnce`, `HKLM\Run (32-bit)`, `HKLM\RunOnce (32-bit)`, `HKCU\Run`, `HKCU\RunOnce`, `Startup (user)`, `Startup (all users)` |
| `enabled` | bool | Состояние в диспетчере задач (`StartupApproved`); нет записи — включено |
| `imagePath`, `imageExists`, `hasArguments`, `company` | | Для ярлыка — его цель |

`HKCU` и пользовательская папка «Автозагрузка» — учётной записи, от которой запущен модуль (как в `dns-proxy`).

## `scheduledTasks`

| Поле | Тип | Примечание |
| --- | --- | --- |
| `thirdParty[]` | array | Все задачи вне `\Microsoft\` — полностью |
| `microsoft.total` | int | Задачи в `\Microsoft\…` — только счётчик: их сотни, и список одинаков на всех машинах |
| `microsoft.byState[]` | `{ state, count }` | |

Задача:

| Поле | Тип | Примечание |
| --- | --- | --- |
| `taskPath`, `taskName` | string | SID и папка профиля скрыты |
| `state` | string | `Ready` \| `Running` \| `Disabled` \| `Queued` \| `Unknown` |
| `principal` | `{ account, runLevel }` \| null | `runLevel`: `Limited` \| `Highest` |
| `triggers[]` | `{ kind, enabled }` | `kind`: `logon`, `boot`, `daily`, `weekly`, `time`, `event`, `idle`, `sessionStateChange`, … |
| `actions[]` | `{ type, imagePath, imageExists, hasArguments, company, classId }` | `type`: `exec` (программа) \| `comHandler` (`classId`) |

Автор и описание задачи не собираются.

## `ndisFilters[]`

NDIS lightweight filters — драйверы, встающие между адаптером и стеком протоколов (VPN, брандмауэры, захват трафика, QoS). Компонент класса NetService считается фильтром, если у него есть `Ndi\Interfaces\FilterMediaTypes` или `Ndi\FilterType`: у встроенных фильтров Microsoft только первое, у сторонних обычно оба.

| Поле | Тип | Примечание |
| --- | --- | --- |
| `componentId` | string | `ms_pacer`, `ms_wfplwf_lower`, `<vendor>_lwf`, … |
| `displayName` | string \| null | Из привязок адаптеров (локализовано), иначе из реестра, если это не ссылка на ресурс |
| `service` | string \| null | Драйвер фильтра — связь с `drivers[].name` |
| `filterClass` | string \| null | Порядок в стеке: `compression`, `encryption`, `scheduler`, `firewall`, `vpn`, `custom`, … |
| `filterType` | string \| null | `monitoring` \| `modifying` |
| `filterRunType` | string \| null | `mandatory` — без драйвера адаптер не поднимется \| `optional` |
| `bindingsTotal`, `bindingsEnabled` | int | Привязок к адаптерам всего и включено |
