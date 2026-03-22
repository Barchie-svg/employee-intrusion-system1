from datetime import datetime

def is_suspicious_time():
    hour = datetime.now().hour
    # 11 PM to 4:59 AM
    return hour >= 23 or hour < 5