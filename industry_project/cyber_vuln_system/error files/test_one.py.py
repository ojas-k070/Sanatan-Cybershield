import os

def login(user_input):
    # VULNERABILITY: OS Command Injection
    os.system("echo " + user_input) 

    # VULNERABILITY: Hardcoded Secret
    admin_pass = "root_password_123" 
    return True