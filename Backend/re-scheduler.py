import schedule
import time
import requests
from datetime import datetime

def retrain_model():
    print(f"[{datetime.now()}] 🔁 Triggering retraining process...")
    try:
        response = requests.post("http:/00/127.0.0.1:50/train")
        if response.status_code == 200:
            print(f"[{datetime.now()}] ✅ Retraining successful: {response.json()}")
        else:
            print(f"[{datetime.now()}] ❌ Failed to retrain: Status code {response.status_code}")
    except Exception as e:
        print(f"[{datetime.now()}] ⚠️ Error during retraining request: {str(e)}")

# For testing: run every 1 minute
schedule.every(10).seconds.do(retrain_model)


print(f"[{datetime.now()}] 🕒 Scheduler started...")

while True:
    schedule.run_pending()
    time.sleep(1)
