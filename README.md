# BackendService
Backend Application
pip3 install -r requirements.txt
python3 app.py

pip install flask-cors

flask db init
flask db migrate -m "Updated User model"
flask db upgrade