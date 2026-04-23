import json
from datetime import datetime
from backend.database.database import SessionLocal
from backend.database.models import DriftLog

def get_letter_grade(score: int) -> tuple:
    """Converts a numeric score to a Letter Grade and qualitative color."""
    if score >= 90: return "A", "emerald"
    elif score >= 70: return "B", "amber"
    else: return "F", "rose"

def generate_compliance_scorecard() -> dict:
    """
    Parses the most recent audit to extract SOC2, HIPAA, and GDPR compliance states.
    Assigns a baseline 100 to each category and subtracts points for violations.
    """
    db = SessionLocal()
    try:
        day_name = datetime.now().strftime("%a")
        log = db.query(DriftLog).filter(DriftLog.day_label == day_name).first()
        
        # Base templates
        results = {
            "GDPR": {"score": 100, "grade": "A", "color": "emerald", "missing_controls": []},
            "HIPAA": {"score": 100, "grade": "A", "color": "emerald", "missing_controls": []},
            "SOC2": {"score": 100, "grade": "A", "color": "emerald", "missing_controls": []}
        }
        
        if not log or not log.audit_snapshot:
            # No audit yet for today, return 100% compliant baseline
            return results
            
        finding = json.loads(log.audit_snapshot)
        json_str = log.audit_snapshot.lower()
        
        # Extract qualitative risk values
        danger_count = json_str.count('"danger"') + json_str.count("'danger'")
        warning_count = json_str.count('"warning"') + json_str.count("'warning'")
        
        # In a real ScoutSuite parsing, we'd map AWS EC2 tags directly to frameworks.
        # For this prototype, a 'danger' rating implies global failure across public exposures.
        has_public_exposure = any(r.get('CidrIp') == '0.0.0.0/0' for perm in finding.get('IpPermissions', []) for r in perm.get('IpRanges', []))
        if finding.get('SecurityRules') and any(r.get('SourceAddressPrefix') in ['*', 'Internet', '0.0.0.0/0'] for r in finding.get('SecurityRules', [])):
             has_public_exposure = True
             
        # Compute dynamic scores
        # Subtract 20 for danger/critical, 10 for warning
        total_penalty = (danger_count * 20) + (warning_count * 10)
        
        if has_public_exposure:
             # Explicit penalty logic for public ingress
             results["GDPR"]["score"] -= 40
             results["GDPR"]["missing_controls"].append("Encryption & Access Control missing, violating GDPR Article 32")
             
             results["HIPAA"]["score"] -= 40
             results["HIPAA"]["missing_controls"].append("Public Ingress violates HIPAA 164.312(a)(1) Access Control")
             
             results["SOC2"]["score"] -= 30
             results["SOC2"]["missing_controls"].append("Public Ingress violates SOC2 CC6.6 Boundary Protection")
             
        # Deduct general penalty
        for framework in ["GDPR", "HIPAA", "SOC2"]:
             results[framework]["score"] -= total_penalty
             results[framework]["score"] = max(0, results[framework]["score"]) # Floor at 0
             
             grade, color = get_letter_grade(results[framework]["score"])
             results[framework]["grade"] = grade
             results[framework]["color"] = color

        return results
    except Exception as e:
        print("Compliance Engine Error:", e)
        return {"error": "Failed to generate compliance scorecard."}
    finally:
        db.close()
