# BackendService
Backend Application

For first time you should follow these steps:

1. cd src
2. python -m venv .venv (or python3 -m venv .venv)
3. .venv\Scripts\activate (for windows) OR .venv/bin/activate (for linux)
4. pip install -r requirements.txt (or pip3 install -r requirements.txt)
5. python app.py (or python3 app.py)

For the next time you should follow these steps:
1. cd src
2. .venv\Scripts\activate (for windows) OR .venv/bin/activate (for linux)
3. python app.py (or python3 app.py)

Follow the steps to update db schema
1. flask db init
2. flask db migrate -m "Updated User model"
3. flask db upgrade