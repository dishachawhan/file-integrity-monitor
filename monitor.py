import os
import hashlib
import json
import argparse
import datetime
from tqdm import tqdm
from colorama import Fore, Style, init

# initialize colorama for colored terminal output
init(autoreset=True)

TARGET_FOLDER = "target_files"
DATABASE_FILE = "database/hashes.json"


def calculate_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def create_baseline():
    file_hashes = {}
    for root, dirs, files in os.walk(TARGET_FOLDER):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, TARGET_FOLDER)
            file_hashes[relative_path] = calculate_hash(file_path)

    with open(DATABASE_FILE, "w") as db:
        json.dump(file_hashes, db, indent=4)

    print("Baseline created successfully.")


def generate_report(results):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"reports/report_{timestamp}.txt"
    with open(report_file, "w") as report:
        report.write("File Integrity Scan Report\n")
        report.write("=================================\n\n")
        for line in results:
            report.write(line + "\n")
    print(f"\nReport saved to {report_file}")


def check_integrity():
    with open(DATABASE_FILE, "r") as db:
        stored_hashes = json.load(db)

    results = []
    current_files = []

    # Gather all files for progress bar
    all_files = []
    for root, dirs, files in os.walk(TARGET_FOLDER):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, TARGET_FOLDER)
            all_files.append((file_path, relative_path))

    print("\nChecking file integrity...\n")

    # Scan files with progress bar
    for file_path, relative_path in tqdm(all_files, desc="Scanning files", unit="file"):
        current_files.append(relative_path)
        current_hash = calculate_hash(file_path)

        if relative_path in stored_hashes:
            if stored_hashes[relative_path] == current_hash:
                status = "SAFE"
                color_status = Fore.GREEN + status + Style.RESET_ALL
            else:
                status = "MODIFIED"
                color_status = Fore.RED + status + Style.RESET_ALL
        else:
            status = "NEW FILE DETECTED"
            color_status = Fore.YELLOW + status + Style.RESET_ALL

        print(f"{relative_path} : {color_status}")
        results.append(f"{relative_path} : {status}")

    # Check for deleted files
    for file in stored_hashes:
        if file not in current_files:
            status = "FILE DELETED"
            color_status = Fore.RED + status + Style.RESET_ALL
            print(f"{file} : {color_status}")
            results.append(f"{file} : {status}")

    generate_report(results)


# Command-line interface
parser = argparse.ArgumentParser(description="File Integrity Monitoring Tool")
parser.add_argument("--init", action="store_true", help="Create baseline hashes")
parser.add_argument("--scan", action="store_true", help="Scan for file changes")
args = parser.parse_args()

if args.init:
    create_baseline()
elif args.scan:
    check_integrity()
else:
    print("Use --init to create baseline or --scan to check integrity")