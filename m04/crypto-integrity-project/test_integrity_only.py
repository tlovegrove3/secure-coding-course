from src.crypto_project.integrity import IntegrityService

try:
    service = IntegrityService()
    result = service.secure_data(b"test message")
    print("IntegrityService works!")
    print(f"Result keys: {list(result.keys())}")
except Exception as e:
    print(f"Error in IntegrityService: {e}")
    print(f"Error type: {type(e)}")