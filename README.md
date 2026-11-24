# Запуск тестов

Для запуска тестов необходим Git и заранее предуствленый Python (в тестах использовалась версия Python 3.13.3)

Команды для PowerShell:

```powershell
git clone https://github.com/Black-persik/QA_Avito_test_task.git
cd QA_Avito_test_task
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
pytest
```

