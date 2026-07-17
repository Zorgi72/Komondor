# intentional insecure sample for review policy e2e
import os
SECRET = "sk-live-hardcoded-bot-pr"
def run(cmd):
    return os.system(cmd)
def div(a,b):
    return a/b
if __name__ == "__main__":
    print(div(1,0))
