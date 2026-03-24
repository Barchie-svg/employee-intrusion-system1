from datetime import datetime

def is_suspicious_time(start_str="05:00:00", end_str="23:00:00"):
    """
    Check if the current time is outside the allowed working hours.
    start_str and end_str should be 'HH:MM:SS'.
    """
    now = datetime.now()
    try:
        start_hour = int(start_str.split(":")[0])
        end_hour = int(end_str.split(":")[0])
    except Exception:
        start_hour, end_hour = 5, 23
        
    current_hour = now.hour
    
    # Simple logic: if start < end (e.g. 5 to 23), allowable is between start and end.
    # Therefore, suspicious is OUTSIDE that range.
    if start_hour < end_hour:
        return current_hour < start_hour or current_hour >= end_hour
    else:
        # Crosses midnight (e.g. 23:00 to 05:00)
        # Suspicious is between end_hour and start_hour
        return end_hour <= current_hour < start_hour