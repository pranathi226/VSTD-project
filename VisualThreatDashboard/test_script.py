
import sys
sys.path.insert(0, '.')

print("=== Testing auth.py ===")

try:
    import auth
    print("✓ auth module imported")
    
    # List all functions
    print("\nAll functions in auth.py:")
    for item in dir(auth):
        if not item.startswith('_'):
            print(f"  - {item}")
    
    print("\n=== Checking for required functions ===")
    
    required = ['login_user_api', 'register_user', 'logout_user', 'User', 'update_device_consent', 'get_user_stats']
    
    for func in required:
        if hasattr(auth, func):
            print(f"✓ {func} - FOUND")
        else:
            print(f"✗ {func} - MISSING")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
