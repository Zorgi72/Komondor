# Intentionally insecure sample for Kodus E2E automated review
import os
import subprocess

API_KEY = "sk-live-hardcoded-secret-do-not-use-in-prod-xyz"

def run_cmd(user_input: str) -> str:
    # command injection
    os.system("echo " + user_input)
    return subprocess.getoutput("ls " + user_input)

def divide(a: int, b: int) -> float:
    return a / b

def check_password(password: str) -> bool:
    expected = os.environ.get("PASSWORD", "admin")
    return password == expected

if __name__ == "__main__":
    print(divide(1, 0))
