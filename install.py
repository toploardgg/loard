import subprocess
import sys
import time
import os

LIBS = [
    "colorama",
    "requests",
    "pandas",
    "psutil",
    "scapy",
    "netifaces",
    "tqdm",
    "python-tk"
]

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def bar(p):
    length = 40
    filled = int(p * length)
    b = "#" * filled + "-" * (length - filled)
    print(f"\r[{b}] {int(p*100)}%", end="", flush=True)

def install_libs():
    total = len(LIBS)
    count = 0
    for lib in LIBS:
        count += 1
        for i in range(20):
            time.sleep(0.02)
            bar(((count - 1) + (i / 20)) / total)
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    bar(1)
    print("\n\nLibraries ready.\n")

def main():
    clear()
    print("Checking libraries...\n")
    try:
        import colorama, requests, pandas, psutil, scapy, netifaces, tqdm, tkinter
        libraries_installed = True
    except:
        libraries_installed = False

    if not libraries_installed:
        print("Some libraries missing. Installing...\n")
        install_libs()
    else:
        print("All libraries already installed.\n")
        time.sleep(0.5)

    choice = input("Which script to run? (1) loard.py (2) loardgui.py: ").strip()
    if choice == "1" and os.path.exists("loard.py"):
        os.system(f'"{sys.executable}" loard.py')
    elif choice == "2" and os.path.exists("loardgui.py"):
        os.system(f'"{sys.executable}" loardgui.py')
    else:
        print("File not found or invalid choice")

if __name__ == "__main__":
    main()
