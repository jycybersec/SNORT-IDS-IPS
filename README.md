# SNORT-IDS/IPS
 
    - Security Onion VM "192.168.48.140"
    - Kali Linux VM "192.168.48.129"
    - Metasploitable Linux VM "192.168.48.130"


## Process
 - Snort rules can be manually created, by modifying the `local.rules` file in the `/etc/nsm/rules` directory.
 - After the `local.rules` file is modified and saved, the rules will need to be updated by running the following command: `sudo rule-update`.
 - If any errors are encountered, use the `sudo sostat` command, to view Security Onion's services status.


## ICMP Echo Reply Rule

- Snort Rule
  ```snort
  alert icmp any any -> any any (itype:0; msg:"ICMP Echo Reply Detected"; content: "Jack Yorgason" classtype:misc-attack; sid:9000011; rev:1;)
- hping3 Command

![image](https://github.com/user-attachments/assets/4eba27e6-424e-4bcf-817b-678d40f2bbff)

![image](https://github.com/user-attachments/assets/abdf9ee4-ba45-47dc-b679-6fec389049be)

  
- Sguil Alert

![image](https://github.com/user-attachments/assets/d202c9d7-881f-4248-b759-4bf993e2f0b3)


## TCP FIN Scan Rule

- Snort Rule
  ```snort
    alert tcp any any -> any any (flags:F; msg:"TCP FIN Scan Detected"; classtype:misc-attack; sid:9000050; rev:1;)
- hping3 Command

![image](https://github.com/user-attachments/assets/a1d02900-7643-4f64-b32e-af41a47b6c21)


- Sguil Alert

![image](https://github.com/user-attachments/assets/d329343f-c80c-460b-86db-1cc243329370)


## TCP XMAS Scan Rule

- Snort Rule
  ```snort
    alert tcp any any -> any any (flags:UPF; msg:"Possible XMAS Scan Detected"; classtype:misc-attack; sid:9000010; rev:1;)
- hping3 Command

![image](https://github.com/user-attachments/assets/960184b6-dfe7-491f-a1a5-1f171b0f2616)

  
- Sguert Alert

![image](https://github.com/user-attachments/assets/c1bd2f1e-d3b6-4a97-8044-86a3fbba72a0)


## TCP SYN Scan Rule

- Snort Rule
  ```snort
  alert tcp any any -> any any (flags:S; msg:"TCP SYN Scan Detected"; classtype:misc-attack; sid:9000050; rev:1;)
- hping3 Command

![image](https://github.com/user-attachments/assets/c68075f0-ea74-4ad9-8e99-eec967d5d0c3)

  
- Sguil Alert

![image](https://github.com/user-attachments/assets/e08c1a20-20b1-4676-b32b-a9c0b43235d9)


## TCP Null Scan Rule

- Snort Rule
  ```snort
  drop tcp any any -> any any (flags:0; msg:"Possible Null Scan Blocked"; classtype:misc-attack; sid:9000070; rev:1;)
- hping3 Command

![image](https://github.com/user-attachments/assets/5546b732-9cfd-4dd7-a077-57cf1d2b5151)

  
- Squert Alert

![image](https://github.com/user-attachments/assets/4d75cd0b-f23e-46cb-9b41-5458f9d99a27)


## Telnet Port Traffic Rule

- Snort Rule
  ```snort
  alert tcp any any -> any 23 (msg:"Telnet Traffic Detected"; classtype:misc-attack; sid:9000007; rev:1;)
- Telnet Command

![image](https://github.com/user-attachments/assets/b04f893e-dcad-4986-bb4b-70d6e554e2d6)

  
- Sguil Alert

![image](https://github.com/user-attachments/assets/32b1400e-f9f8-426f-a1b6-d5a25905a20a)


## local.rules File

![image](https://github.com/user-attachments/assets/e740e261-740f-44b0-a4d8-bf0ac46a0698)



