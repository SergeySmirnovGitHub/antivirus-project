# vtscan — домашний сканер файлов на VirusTotal

CLI-утилита: считает SHA-256 файлов и проверяет их по базе VirusTotal (70+ антивирусных движков). Первый этап учебного антивируса.

## Установка
Нужен Python 3.10+.
```bash
pip install -r requirements.txt
```

## API-ключ (бесплатно)
1. Регистрация: https://www.virustotal.com/gui/join-us
2. Профиль → **API key**, скопировать.
3. Скопировать `.vtkey.example` в `.vtkey` и вставить ключ одной строкой.
   (Также можно передать `--api-key` или через переменную `VT_API_KEY`.)

Лимит бесплатного ключа: ~4 запроса/мин, 500/день → между файлами пауза ~16 сек.

## Использование
```bash
python vtscan.py C:\путь\к\файлу.exe      # один файл
python vtscan.py C:\Downloads             # папка
python vtscan.py C:\Downloads -r          # рекурсивно
python vtscan.py файл.exe --upload        # догрузить неизвестный файл на анализ
python vtscan.py C:\Downloads --json      # вывод в JSON
```

## Чтение результата
`[+] ЧИСТО` · `[!] ВРЕДОНОСНЫЙ` · `[?] ПОДОЗРИТЕЛЬНЫЙ` · `[ ] НЕИЗВЕСТЕН` (нет в базе) · `[x] ОШИБКА`.
Код возврата 1 — найден вредоносный файл.

## Тест (безвредный)
Создай `eicar.txt` со строкой:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
`python vtscan.py eicar.txt` → должен показать ВРЕДОНОСНЫЙ.

## Дальнейшие этапы
См. `CLAUDE.md` — там полный roadmap (ClamAV, фоновое слежение, драйвер ядра).
