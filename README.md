# Vless Wizard

**Vless Wizard** — графический мастер для автоматической настройки **3x-ui** панелей через SSH.  
Программа подключается к серверу, устанавливает 3x-ui (если нужно) и помогает управлять конфигурациями.

Подробная документация — на [Wiki проекта](https://github.com/YukiKras/vless-wizard/wiki)

---

## Запуск без сборки (любая платформа)

Требуется **Python 3.10+** и `pip`.

```bash
git clone https://github.com/YukiKras/vless-wizard.git
cd vless-wizard
python3 -m venv venv
source venv/bin/activate        # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Приложение откроется в графическом окне.

---

## Готовые бинарные файлы (скачать)

В разделе [Releases](https://github.com/YukiKras/vless-wizard/releases/latest) доступны:

- `vless-wizard-<версия>-windows.exe` — для Windows (переносимый, не требует Python)
- `vless-wizard-<версия>-linux` — для Linux (исполняемый, не требует Python)

---

## Сборка из исходников (для любой платформы)

Выполните подготовительные шаги:

```bash
git clone https://github.com/YukiKras/vless-wizard.git
cd vless-wizard
python3 -m venv venv
source venv/bin/activate        # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

Затем установите PyInstaller и соберите исполняемый файл:

**Windows:**
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --add-data "3xinstall.sh;." main.py
```

**Linux / macOS:**
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --add-data "3xinstall.sh:." main.py
```

Готовый файл (`main.exe` для Windows, `main` для Linux/macOS) появится в папке `dist/`. Переименуйте его при необходимости.

---

## Лицензия

Проект распространяется под лицензией MIT. Подробнее см. файл [LICENSE](LICENSE).
