import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
print(f"Testing with key ending in: ...{api_key[-4:] if api_key else 'None'}")
genai.configure(api_key=api_key)

try:
    models = genai.list_models()
    print("AVAILABLE MODELS:")
    for m in models:
         if 'generateContent' in m.supported_generation_methods:
             print(m.name)
except Exception as e:
    print(f"ERROR: {e}")
