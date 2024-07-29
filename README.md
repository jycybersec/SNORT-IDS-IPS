# Snort IDS/IPS Custom Rules

## Machines 
- **Security Onion VM "192.168.48.140"**
   - Operating system with Network Intrusion Detection System and Log Monitoring capabilities, acting as an interim by observing network traffic, hosting Snort, Squil, and Squert.
- **Kali Linux VM "192.168.48.129"**
   - Offensive Security operating system, acting as a threat actor by crafting packets using hping3 and establishing a connection via Telnet.
- **Metasploitable Linux VM "192.168.48.130"**
    - Vulnerable Linux operating system acting as the recipient of ICMP and TCP packets. This machine also hosts vulnerable services such as Telnet.


## Process
 - Snort rules can be manually created, by modifying the `local.rules` file in the `/etc/nsm/rules` directory.
 - After the `local.rules` file is modified and saved, the rules will need to be updated by running the following command: `sudo rule-update`.
 - If any errors are encountered, use the `sudo sostat` command, to view Security Onion's services status.

## local.rules

![image](https://github.com/user-attachments/assets/e740e261-740f-44b0-a4d8-bf0ac46a0698)


## ICMP Echo Reply Rule
- **Description**: This rule detects ICMP Echo Reply messages (commonly known as ping replies), containing "Jack Yorgason" (my name). It triggers an alert when such a message is detected, indicating that a device has responded to a ping request. The rule includes a custom message “ICMP Echo Reply Detected” and uses the itype:0 option to specify the ICMP type for Echo Reply.
  
- **Snort Rule**
  ```snort
  alert icmp any any -> any any (itype:0; msg:"ICMP Echo Reply Detected"; content: "Jack Yorgason" classtype:misc-attack; sid:9000011; rev:1;)
  
- **hping3 Command**

![image](https://github.com/user-attachments/assets/4eba27e6-424e-4bcf-817b-678d40f2bbff)

![image](https://github.com/user-attachments/assets/abdf9ee4-ba45-47dc-b679-6fec389049be)

  
- **Sguil Alert**

![image](https://github.com/user-attachments/assets/d202c9d7-881f-4248-b759-4bf993e2f0b3)


## TCP FIN Scan Rule

- **Description**: This rule identifies TCP FIN scan attempts, which are used by attackers to probe for open ports on a target system. The rule triggers an alert when a TCP packet with the FIN flag set is detected. The custom message “TCP FIN Scan Detected” helps in identifying the nature of the alert.
  
- **Snort Rule**
  ```snort
    alert tcp any any -> any any (flags:F; msg:"TCP FIN Scan Detected"; classtype:misc-attack; sid:9000050; rev:1;)
  
- **hping3 Command**

![image](https://github.com/user-attachments/assets/a1d02900-7643-4f64-b32e-af41a47b6c21)


- **Sguil Alert**

![image](https://github.com/user-attachments/assets/d329343f-c80c-460b-86db-1cc243329370)


## TCP XMAS Scan Rule

- **Description**: This rule detects TCP XMAS scans, a type of port scan where the FIN, PSH, and URG flags are set in the TCP header. The rule triggers an alert with the message “Possible XMAS Scan Detected” when such packets are observed, indicating a potential reconnaissance attempt by an attacker.

- **Snort Rule**
  ```snort
    alert tcp any any -> any any (flags:UPF; msg:"Possible XMAS Scan Detected"; classtype:misc-attack; sid:9000010; rev:1;)
  
- **hping3 Command**

![image](https://github.com/user-attachments/assets/960184b6-dfe7-491f-a1a5-1f171b0f2616)

  
- **Squert Alert**

![image](https://github.com/user-attachments/assets/c1bd2f1e-d3b6-4a97-8044-86a3fbba72a0)


## TCP SYN Scan Rule

- **Description**: This rule is designed to detect TCP SYN scans, which are used to identify open ports on a target system by sending SYN packets. The rule triggers an alert with the message “TCP SYN Scan Detected” when a SYN packet is detected, indicating a possible scanning activity.

- **Snort Rule**
  ```snort
  alert tcp any any -> any any (flags:S; msg:"TCP SYN Scan Detected"; classtype:misc-attack; sid:9000050; rev:1;)
  
- **hping3 Command**

![image](https://github.com/user-attachments/assets/c68075f0-ea74-4ad9-8e99-eec967d5d0c3)

  
- **Sguil Alert**

![image](https://github.com/user-attachments/assets/e08c1a20-20b1-4676-b32b-a9c0b43235d9)


## TCP Null Scan Rule

- **Description**: This rule identifies TCP Null scans, characterized by the absence of flags in the TCP header. These scans are employed to detect open ports by leveraging variations in system responses to such packets. The rule blocks the packet and logs the event with the message “Possible Null Scan Blocked,” signaling a potential threat.

- **Snort Rule**
  ```snort
  drop tcp any any -> any any (flags:0; msg:"Possible Null Scan Blocked"; classtype:misc-attack; sid:9000070; rev:1;)
  
- **hping3 Command**

![image](https://github.com/user-attachments/assets/5546b732-9cfd-4dd7-a077-57cf1d2b5151)

  
- **Squert Alert**

![image](https://github.com/user-attachments/assets/4d75cd0b-f23e-46cb-9b41-5458f9d99a27)


## Telnet Port Traffic Rule

- **Description**: This rule identifies traffic on the Telnet port (port 23), which is often used for remote administration but is considered insecure due to the lack of encryption. The rule triggers an alert with the message “Telnet Traffic Detected” when traffic is detected on this port, highlighting potential security risks associated with Telnet usage.

- **Snort Rule**
  ```snort
  alert tcp any any -> any 23 (msg:"Telnet Traffic Detected"; classtype:misc-attack; sid:9000007; rev:1;)
  
- **Telnet Command**

![image](https://github.com/user-attachments/assets/b04f893e-dcad-4986-bb4b-70d6e554e2d6)

  
- **Sguil Alert**

![image](https://github.com/user-attachments/assets/32b1400e-f9f8-426f-a1b6-d5a25905a20a)





