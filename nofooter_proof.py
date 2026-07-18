PASSWORD="secret123"
def bad(x):
    import os
    return os.system("echo "+x)
