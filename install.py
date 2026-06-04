import subprocess
import sys
import time
import os
import importlib

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

REQUIRED_LIBS = [
    "colorama",
    "requests",
    "pandas",
    "psutil",
    "scapy",
    "tqdm",
]

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def is_lib_installed(lib_name):
    try:
        importlib.import_module(lib_name)
        return True
    except ImportError:
        return False

def install_lib_with_progress(lib):
    sys.stdout.write(f"installing... 0%")
    sys.stdout.flush()
    total_steps = 20
    for step in range(total_steps + 1):
        percent = int(step / total_steps * 100)
        bar_len = 40
        filled = int(bar_len * step / total_steps)
        bar = "#" * filled + "-" * (bar_len - filled)
        sys.stdout.write(f"\rinstalling... [{bar}] {percent}%")
        sys.stdout.flush()
        time.sleep(0.02)
    sys.stdout.write("\r" + " " * 60 + "\r")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", lib],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        return True
    except:
        return False

def check_and_install_all():
    print("Checking libraries...\n")
    failed = False
    for idx, lib in enumerate(REQUIRED_LIBS, 1):
        sys.stdout.write(f"[{idx}/{len(REQUIRED_LIBS)}] {lib}: ")
        sys.stdout.flush()
        if is_lib_installed(lib):
            print(f"{GREEN}installed{RESET}")
        else:
            sys.stdout.write(f"{YELLOW}not found, installing...{RESET}")
            sys.stdout.flush()
            success = install_lib_with_progress(lib)
            if success:
                print(f"\r[{idx}/{len(REQUIRED_LIBS)}] {lib}: {GREEN}OK{RESET}")
            else:
                print(f"\r[{idx}/{len(REQUIRED_LIBS)}] {lib}: {RED}FAILED{RESET}")
                failed = True
        sys.stdout.flush()
    print()
    if failed:
        print(f"{RED}Some libraries failed to install. Please install them manually.{RESET}")
        time.sleep(3)
        return False
    else:
        print(f"{GREEN}All libraries ready.{RESET}")
        return True

def run_loard(args=None):
    script_name = "loard.py"
    if not os.path.exists(script_name):
        print(f"Error: {script_name} not found.")
        return False
    cmd = [sys.executable, script_name]
    if args:
        cmd.extend(args)
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"Error running {script_name}: {e}")
    return True

def main():
    clear()
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--install":
            check_and_install_all()
            return
        elif arg == "--help":
            print("Usage:")
            print("  install.py                - check libs and run loard.py")
            print("  install.py --install      - install missing libraries only")
            print("  install.py --help         - show this help")
            print("\nAny extra arguments are passed directly to loard.py")
            return
        else:
            if check_and_install_all():
                run_loard(sys.argv[1:])
            return
    if check_and_install_all():
        print()
        run_loard()

if __name__ == "__main__":
    main()
