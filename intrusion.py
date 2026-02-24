from datetime import datetime

def is_suspicious_time():
    hour = datetime.now().hour
    return hour >= 22 or hour <= 5