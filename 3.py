# Vulnerable Code
import os

def delete_file(filename):
    os.system(f"rm {filename}")

import os
import subprocess

def delete_file(filename):
    try:
        subprocess.run(["rm", "--", filename], check=True)
        print("File deleted securely.")
    except Exception as e:
        print(f"Error: {e}")
