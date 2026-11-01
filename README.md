# TunnelEye

**Диагностика сети Windows-ПК в один клик.** TunnelEye, на движке Argus, видит, что творится в ваших туннелях: конфликты VPN и обходов блокировок, утечки DNS, кривые маршруты, лишние адаптеры и службы — и объясняет простым языком, что с этим делать.

> Статус: в разработке, этап 2. Модули сбора, анализатор, CLI и первая версия окна WPF готовы; идёт проверка интерфейса и стенда.

## Что умеет (план)

- **Один клик** — снимок системы и сети, отчёт с проблемами по приоритету и конкретными шагами.
- **Захват трафика старт/стоп** — встроенным `pktmon`, без установки драйверов; анализ ретрансмитов, штормов, утечек DNS мимо туннеля.
- **Конфликты VPN, обходов и антивирусов** — на уровне маршрутов, DNS и фильтров WFP.
- **Исправления с бэкапом и откатом** — ничего не меняется без подтверждения.
- **Апгрейд железа** — узкие места и варианты под разный бюджет.
- **Расширенный режим** — для тех, кто разбирается: сырые данные, фильтры, сравнение снимков, CLI.

Всё работает локально. Данные о вашем ПК никуда не отправляются.

## Требования

- Windows 10 (1903+) или Windows 11, x64
- Права администратора для полного сбора

## Сборка

C# / .NET Framework 4.8 / WPF. Для сборки нужен .NET SDK и targeting pack .NET Framework 4.8; для запуска — Windows с .NET Framework 4.8.

```powershell
dotnet build src/TunnelEye.sln
dotnet test src/TunnelEye.sln
src/TunnelEye.Cli/bin/Debug/net48/tunneleye.exe analyze snapshot.json --lang ru --html report.html --report-json report.json --mask
```

HTML открывается офлайн. `--mask` заменяет личные данные псевдонимами; полный исходный снимок сохраняется. Английский язык: `--lang en`. [Формат отчёта и параметры экспорта](docs/schema/report.md).

EN: Build with `dotnet build src/TunnelEye.sln`. Analyze a saved snapshot with the command above; use `--lang en` for English and `--mask` to mask personal data in the exports.

## Запуск окна

```powershell
src/TunnelEye.App/bin/Debug/net48/TunnelEye.exe
```

Можно открыть сохранённый снимок или начать диагностику. Согласие на внешние тесты даётся на один запуск; экспорт по умолчанию скрывает личные данные. [Подробности и проверки окна](docs/GUI.md).

EN: Start the executable above to run the WPF app. Open a snapshot or run diagnostics; external tests require consent for each run. Personal data is masked in exports by default.

## Для разработчиков

[Подготовка репозитория и проверка перед коммитом](CONTRIBUTING.md).

EN: [Repository setup and pre-commit checks](CONTRIBUTING.md).

## Лицензия

[Apache License 2.0](LICENSE). При распространении копий и форков обязательно сохранять файлы `LICENSE` и `NOTICE`.

### Название

«TunnelEye» и «Argus» в контексте этого проекта — названия, принадлежащие автору. Форки, распространяемые публично, должны использовать другое название.
