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

🏎️ Race Vehicle Setup Recording System
This project was developed in collaboration with Oxford Brookes University to assist race engineers and drivers in capturing, analyzing, and improving race vehicle setups through lap-based testing and third-party insights.

🔍 Overview
The system enables race engineers to record lap-wise performance parameters of vehicles during test runs. The captured data is stored securely and analyzed internally, while also being sent to a third-party analytics platform — Canopy — which returns performance improvement suggestions. These results are also stored and made accessible through the UI.

<img width="870" alt="image" src="https://github.com/user-attachments/assets/99e19709-952b-4eb7-96f6-d43558069841" />

# Data Flow

# Engineer Input:
Race engineers or drivers complete a lap and log test data (e.g., tire pressure, suspension settings, lap times, telemetry).
Data is entered through the React frontend.

# Backend Processing:
Python Flask API receives the data, performs validation, and saves it into MongoDB.
Simultaneously, the same dataset is sent to the Canopy API.

# Third-party Analysis (Canopy):
Canopy analyzes the test data and returns suggested improvements (e.g., setup tuning tips, anomalies).
The Flask API stores these results back into MongoDB and makes them available via the UI.

# Result Viewing:
Engineers access analysis results directly through the dashboard.
Past tests and corresponding insights are stored for comparison and iterative improvements.
