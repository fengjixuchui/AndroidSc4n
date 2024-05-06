import sys
import subprocess
import os
import textwrap
import re

BANNER = """
__________                     .__              .__                
\______   \ ___________  _____ |__| ______ _____|__| ____   ____   
 |     ___// __ \_  __ \/     \|  |/  ___//  ___/  |/  _ \ /    \  
 |    |   \  ___/|  | \/  Y Y  \  |\___ \ \___ \|  (  <_> )   |  \ 
 |____|    \___  >__|  |__|_|  /__/____  >____  >__|\____/|___|  /
               \/            \/        \/     \/               \/  
Ver 1.0.0.Beta
Created by Github.com/Actuator
"""

def print_help():
    print(BANNER)
    print(textwrap.dedent("""\
        Usage: python dialer.py <apk_file or directory>

        This tool scans APK files for exported activities that have 'android.intent.action.CALL' 
        in their intent filters. It identifies potential vulnerabilities in Android phone dialer apps 
        where dangerous permissions might be exposed.

        Options:
        -h, --help    Show this help message and exit
    """))

def check_dependencies():
    try:
        subprocess.run(['apktool', '--version'], check=True, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Error: apktool is not installed. Please install apktool.")
        sys.exit(1)

def extract_manifest(apk_file, base_dir):
    if os.path.exists(base_dir):
        subprocess.run(['rm', '-rf', base_dir], check=True)
    try:
        subprocess.run(['apktool', 'd', '-f', '-o', base_dir, apk_file], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to extract APK file: {e.stderr.decode()}")
        sys.exit(1)

    manifest_file = os.path.join(base_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_file):
        print("Error: Failed to find the extracted manifest file.")
        sys.exit(1)

    return manifest_file

def find_dangerous_call_activities(manifest_file):
    dangerous_activities = []
    try:
        with open(manifest_file, 'r', encoding='utf-8') as f:
            manifest_content = f.read()

        pattern = r'<activity(?:[^>]|\n)*?\bandroid:exported\s*=\s*(?:"true"|\'true\')(?:[^>]|\n)*?>' \
                  r'(?:(?!</activity>).)*?' \
                  r'<intent-filter(?:[^>]|\n)*?>' \
                  r'(?:(?!</intent-filter>).)*?' \
                  r'<action(?:[^>]|\n)*?\bandroid:name\s*=\s*(?:"android.intent.action.CALL"|\'android.intent.action.CALL\')' \
                  r'(?:[^>]|\n)*?>'
        matches = re.findall(pattern, manifest_content, re.DOTALL)
        for match in matches:
            activity_match = re.search(r'android:name\s*=\s*["\']([^"\']+)', match)
            if activity_match:
                activity_name = activity_match.group(1)
                dangerous_activities.append(activity_name)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
    return dangerous_activities

def analyze_apk(apk_file):
    check_dependencies()
    base_dir = os.path.splitext(apk_file)[0]
    manifest_file = extract_manifest(apk_file, base_dir)
    dangerous_activities = find_dangerous_call_activities(manifest_file)
    if dangerous_activities:
        print(f"Dangerous activities found in {apk_file}:")
        for activity in dangerous_activities:
            print(f" - {activity}")
    else:
        print(f"No dangerous activities found in {apk_file}.")

def main(apk_path):
    if os.path.isfile(apk_path) and apk_path.endswith('.apk'):
        analyze_apk(apk_path)
    elif os.path.isdir(apk_path):
        for root, dirs, files in os.walk(apk_path):
            for file in files:
                if file.endswith('.apk'):
                    apk_file = os.path.join(root, file)
                    analyze_apk(apk_file)
    else:
        print("Error: Please provide a valid APK file or directory.")
        print_help()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_help()
        sys.exit(1)

    argument = sys.argv[1]
    if argument in ("-h", "--help"):
        print_help()
        sys.exit(0)

    main(argument)
