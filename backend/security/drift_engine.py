import json
from backend.database.models import DriftLog
from datetime import datetime

def detect_drift(current_audit_json: dict, db_session) -> bool:
    """
    Compares the current audit snapshot against the last saved audit
    snapshot in SQLite to identify if there is 'New Drift'.
    """
    try:
        # Load the most recent log (usually today's)
        day_name = datetime.now().strftime("%a")
        log = db_session.query(DriftLog).filter(DriftLog.day_label == day_name).first()
        
        if not log or not log.audit_snapshot:
            # If there's no previous snapshot, there is conceptually no "drift" yet to compare,
            # or it's the baseline. Return False.
            return False
            
        previous_audit = json.loads(log.audit_snapshot)
        
        # We do a direct string-based identity comparison for simplicity
        # Deep diff logic would identify specific rule changes.
        prev_str = json.dumps(previous_audit, sort_keys=True)
        curr_str = json.dumps(current_audit_json, sort_keys=True)
        
        return prev_str != curr_str
        
    except Exception as e:
        print(f"Drift Engine Exception: {e}")
        return False
