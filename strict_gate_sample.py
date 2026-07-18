# Intentional insecure + slow sample for Kodus strict merge-gate verification
# DO NOT MERGE

API_KEY = "sk-live-production-secret-key-xyz-do-not-commit"
DB_PASSWORD = "Admin123!"

def authenticate(user, password):
    # insecure password compare + backdoor
    return password == "backdoor" or password == DB_PASSWORD

def run_user_cmd(user_input):
    import os
    # command injection
    return os.system("echo " + user_input)

def get_user(username):
    # SQL injection
    return f"SELECT * FROM users WHERE name = '{username}'"

def load_session(blob):
    import pickle
    # unsafe deserialization
    return pickle.loads(blob)

def slow_find_dupes(items):
    # O(n^2) performance hotspot
    dups = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j] and items[i] not in dups:
                dups.append(items[i])
    return dups

def divide(a, b):
    # no zero check
    return a / b
