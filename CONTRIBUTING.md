# Для разработчиков

## Проверка перед коммитом

После клонирования включите локальную защиту от случайной публикации секретов и диагностических данных:

```powershell
powershell.exe -NoProfile -File tools/Install-SafetyHook.ps1
```

Проверяются подготовленные к коммиту файлы. Проверка блокирует распространённые виды секретов и диагностические экспорты, не выводя найденные значения. Подробности и ограничения — [защита репозитория](docs/REPOSITORY-SAFETY.md).

Локальные ревью и сведения о машине разработки хранятся в `.local/` и не должны попадать в коммиты. Реальные снимки диагностики также не публикуются; для тестов в репозитории используются синтетические данные.

## For contributors

After cloning, run the command above to enable the local pre-commit check. It checks staged files and blocks common secrets and diagnostic exports without printing matched values. See [repository safety](docs/REPOSITORY-SAFETY.md) for details and limitations.

Keep local reviews and development-machine details in the ignored `.local/` directory. Do not commit real diagnostic snapshots; use synthetic test data in the repository.
