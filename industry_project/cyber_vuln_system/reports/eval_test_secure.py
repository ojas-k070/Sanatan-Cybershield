# VULNERABILITY: Arbitrary Code Execution
# user_input = "__import__('os').system('rm -rf /')"
# eval(user_input) # This is a major security risk

# Secure code: Removed the dangerous eval call.
print("Code executed safely.")