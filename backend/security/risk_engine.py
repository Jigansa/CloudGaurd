import os
import json
import google.generativeai as genai

def calculate_risk_score(findings_json: dict) -> int:
    """
    Counts ScoutSuite 'danger' and 'warning' occurrences in the finding.
    Formula: Score = (Danger * 20) + (Warning * 10). Capped at 100.
    """
    json_str = json.dumps(findings_json).lower()
    danger_count = json_str.count('"danger"') + json_str.count("'danger'") + json_str.count('danger')
    warning_count = json_str.count('"warning"') + json_str.count("'warning'") + json_str.count('warning')
    
    score = (danger_count * 20) + (warning_count * 10)
    return min(score, 100)

def analyze_vulnerability(finding: dict) -> dict:
    """
    Takes a JSON snippet (finding) from ScoutSuite, sends it to Gemini, 
    and returns a structured risk story and remediation hint.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        return {
            "risk_story": "GEMINI_API_KEY is missing or invalid in your .env file.",
            "remediation_hint": "Please configure a valid Google Gemini API key to activate AI threat analysis."
        }
    try:
        genai.configure(api_key=api_key)
        # Use gemini-2.5-flash model
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = f"""Analyze this cloud security vulnerability and provide a 2-sentence "risk_story" explaining the business impact and a 1-sentence "remediation_hint" for the fix. Output EXCLUSIVELY in valid JSON format, without markdown backticks.
        
        Finding JSON:
        {json.dumps(finding, indent=2)}
        """
        
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        # Guard against markdown formatting if Gemini tries to wrap it
        if text.startswith("```json"):
            text = text[7:-3]
        elif text.startswith("```"):
            text = text[3:-3]
            
        return json.loads(text.strip())
        
    except Exception as e:
        print(f"Gemini Exception Caught: {e}")
        return {
            "risk_story": f"AI Engine Error: The Gemini API refused the connection or failed to process the request.",
            "remediation_hint": str(e)
        }
