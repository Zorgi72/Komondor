# Intentionally insecure sample for Kodus E2E review
import os
import subprocess

API_KEY = "sk-live-hardcoded-secret-for-review"  # hardcoded secret

def run_user_command(user_input: str):
    # command injection
    os.system("echo " + user_input)
    return subprocess.getoutput("ls " + user_input)

def divide(a, b):
    # crash on zero
    return a / b

def auth(password: str) -> bool:
    # timing-attackable comparison
    return password == os.environ.get("PASSWORD", "admin")

if __name__ == "__main__":
    print(run_user_command("test; cat /etc/passwd"))
    print(divide(1, 0))
