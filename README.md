# Ethical Hacking

This GitHub repository showcases completed courses and assignments from the Ethical Hacking module.

## Environment

Two separate environments were used for different courses: one for the CTF course and another for the remaining courses.

### CTF

* Kali - Attacking machine.
* Linux_1 - File storage.  
* R_1 - VyOS router.
* Win_1 - Jeff's machine.
* Win_2 - Lisa's machine.

For additional details, refer to the [CTF report](/CTF/CTF.pdf).

### Ethical hacking

* [Flare-VM](https://www.mandiant.com/resources/blog/flare-vm-the-windows-malware) - Malware analysis machine that was used in the last two Reverse Engineering labs.
* Kali - Attacking machine that was used in Web Application Security and Software Exploitation. Was also used for most of the Reverse Engineering labs.
* Pfsense - Firewall.
* Wasdat - Web server hosting vulnerable applications for Web Application Security exercises.

For additional details, refer to the [Audit report](/Misc/VLE-environment-audit.pdf).

## [Web Application Security](https://opetussuunnitelmat.peppi.jamk.fi/en/TTV2023SS/course_unit/TTC6500)

This course focused on exploring, exploiting, and addressing common vulnerabilities in web applications, aligning with the [OWASP TOP 10 2021](https://owasp.org/Top10/).

### Used tools

* [Dirb](https://www.kali.org/tools/dirb/)
* [Burp Suite](https://portswigger.net/burp/communitydownload)
* [Nmap](https://nmap.org/)
* [Metasploit Framework](https://www.metasploit.com/)

### Reports

* [A01:2021-Broken Access Control](/WebAppSecurity/A01-2021-Broken-Access-Control.pdf)
* [A02:2021-Cryptographic Failures](/WebAppSecurity/A02-2021-Cryptographic-Failures.pdf)
* [A03:2021-Injection](/WebAppSecurity/A03-2021-Injection.pdf)
* [A04:2021-Insecure Design](/WebAppSecurity/A04-2021-Insecure-Design.pdf)
* [A05:2021-Security Misconfiguration](/WebAppSecurity/A05-2021-Security-Misconfiguration.pdf)
* [A06:2021-Vulnerable and Outdated Components](/WebAppSecurity/A06-2021-Vulnerable-and-Outdated-Components.pdf)
* [A07:2021-Identification and Authentication Failures](/WebAppSecurity/A07-2021-Identification-and-Authentication-Failures.pdf)
* [A08:2021-Software and Data Integrity Failures](/WebAppSecurity/A08-2021-Software-and-Data-Integrity-Failures.pdf)
* [A09:2021-Security Logging and Monitoring Failures](/WebAppSecurity/A09-2021-Security-Logging-and-Monitoring-Failures.pdf)
* [A10:2021-Server-Side Request Forgery](/WebAppSecurity/A10-2021-Server-Side-Request-Forgery.pdf)

## [CTF](https://opetussuunnitelmat.peppi.jamk.fi/en/TTV2023SS/course_unit/TTC6530)

Structured with eight challenges, some featuring multiple parts, the CTF course aimed at uncovering concealed flags. The difficulty level progressed sequentially throughout the course.

### Used tools

* [WPScan](https://wpscan.com/)
* [Metasploit Framework](https://www.metasploit.com/)
* [sqlmap](https://sqlmap.org/)
* [Dirb](https://www.kali.org/tools/dirb/)
* [Burp Suite](https://portswigger.net/burp/communitydownload)

### Report

[CTF report](/CTF/CTF.pdf)

## [Software Exploitation](https://opetussuunnitelmat.peppi.jamk.fi/en/TTV2023SS/course_unit/TTC6520)

The Software Exploitation course featured diverse challenges, concentrating on exploits like buffer overflow, shellcode, and format string exploits within C-based programs.

### Used tools

* [GDB](https://www.sourceware.org/gdb/)
* [Python 3](https://www.python.org/)

### Reports

* [Stack buffer overflow](/SoftwareExploitation/Stack-buffer-overflow.pdf)
* [Shellcode part 1](/SoftwareExploitation/Shellcode-part-1.pdf)
* [Shellcode part 2](/SoftwareExploitation/Shellcode-part-2.pdf)
* [Format string exploit](/SoftwareExploitation/Format-string-exploit.pdf)

## [Reverse Engineering](https://opetussuunnitelmat.peppi.jamk.fi/en/TTV2023SS/course_unit/TTC6510)

In the Reverse Engineering course, assignments revolved around analyzing disassembled compiled programs to find hidden passwords or flags. The last two assignments specifically dealt with real-world examples of malware. 

### Used tools

* [IDA Free](https://hex-rays.com/ida-free/)
* [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
* [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng)
* [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
* [Wireshark](https://www.wireshark.org/)
* [PEID](https://www.aldeid.com/wiki/PEiD)
* [Regshot](https://github.com/Seabreg/Regshot)

### Reports

* [Lab 01](/ReverseEngineering/Lab01.pdf)
* [Lab 02](/ReverseEngineering/Lab02.pdf)
* [Lab 04](/ReverseEngineering/Lab04.pdf)
* [Lab 05](/ReverseEngineering/Lab05.pdf)
* [Lab 06](/ReverseEngineering/Lab06.pdf)
* [Winlab 01](/ReverseEngineering/winlab01.pdf)
* [Winlab 02](/ReverseEngineering/winlab02.pdf)

## Post-quantum cryptography article

An article in which I attempted to explore the current state of cryptography, quantum computers, their potential risks, and the emerging field of post-quantum cryptography (PQC).

### Used tools

[IEEE Xplore](https://ieeexplore.ieee.org/Xplore/home.jsp)

### Article

[PQC](/Misc/Post-quantum-cryptography.pdf)

## VLE environment audit

I examined the security of the virtual learning environment (VLE) used in the aforementioned cybersecurity courses to provide insights into its current state.

### Used tools

* [Greenbone](https://www.greenbone.net/en/) 
* [Nikto](https://cirt.net/Nikto2)
* [Nmap](https://nmap.org/)
 
### Report

[Audit](/Misc/VLE-environment-audit.pdf)

