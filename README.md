![image](https://github.com/zaka1200/tp_snort/assets/121964432/255bfaa4-03be-4b65-ab36-3c32dec08194)

# Table of Contents

- [INTRODUCTION](#introduction)
- [OPERATION](#operation)
  - [NETWORK CONFIGURATION](#network-configuration)
  - [INSTALLATION AND CONFIGURATION OF SNORT](#installation-and-configuration-of-snort)
  - [SNORT SERVICE](#snort-service)
  - [SIMULATION OF ATTACKS AND INTRUSIONS](#simulation-of-attacks-and-intrusions)
  - [ARP SPOOFING ATTACK](#arp-spoofing-attack)
- [CONCLUSION](#conclusion)

# INTRODUCTION

Snort is a widely used open-source Intrusion Detection System (IDS). It is designed to monitor and analyze network traffic in real-time to detect malicious activities and potential attacks.

Snort IDS works by inspecting network traffic for signatures, abnormal behaviors, or suspicious traffic patterns. It uses a combination of preconfigured rules and analysis mechanisms to detect various forms of intrusions, such as vulnerability exploitation attempts, port scans, Denial of Service (DoS) attacks, and more.

## Detection Rules

Snort utilizes a flexible rule language to describe the traffic patterns to be detected. The rules can be customized to fit specific monitoring and detection needs.

## Operating Modes

Snort can be used in different modes. In IDS mode, Snort analyzes network traffic and generates alerts when matching detection rules are found. It can also be used in Intrusion Prevention System (IPS) mode, where it can automatically block malicious traffic using preconfigured action rules.

## Community Support

Snort benefits from an active community of users and developers who contribute to its development, share detection rules, and provide technical support.

## Extensions and Integrations

Snort can be extended with additional modules to add extra functionalities, such as preprocessor plugins to analyze and normalize traffic, output modules for integration with other Security Event Management (SIEM) systems, and more.

# OPERATION

## NETWORK CONFIGURATION

In IPCop, the network configuration is based on a zone-based model, which includes three main zones: Green, Orange, and Red.

- Green Zone: The Green zone represents the trusted local network, such as the organization's or home's internal network. In the Green zone, firewall rules are generally more permissive since it is a trusted network.
- Orange Zone: The Orange zone is intended for DMZ networks. DMZ networks are used to host servers accessible from the internet, such as web servers or mail servers. Firewall rules for the Orange zone are configured to allow limited access from the outside while protecting the internal network.
- Red Zone: The Red zone represents the untrusted external network, usually the internet. In the Red zone, incoming and outgoing packets are strictly filtered to ensure the security of the internal network. IPCop is configured to use an internet connection in the Red zone.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/24b8e752-8cb2-4079-a75f-9f4f1dd347f2)


The implementation of Snort IDS will take place in the zone to detect intrusions in the local network.

## INSTALLATION AND CONFIGURATION OF SNORT

![image](https://github.com/zaka1200/tp_snort/assets/121964432/4aa93c3d-dda9-47de-982d-cc8ffd070031)

- Specify the local network and the interface protected by Snort.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/fdcbeb5d-4445-4240-8263-138e3471db4f)

- Configuration of rules: Snort uses detection rules to identify malicious activities. You can configure Snort rules by editing the main configuration file, usually located in the directory /etc/snort/snort.conf. You can customize existing rules or add new rules according to your needs. These will be added to the file /etc/snort/rules/rules.local.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/bfb14322-7eb2-494c-a6cb-b44efa18bc3a)


## SNORT SERVICE

- Starting the Snort service.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/a8ee849b-d9a7-4f60-97aa-cd66c3bb9c27)


- Putting Snort into listening mode.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/39f677ab-08b7-421f-9f8e-1be44e408993)


- Adding rules: You can specify detection rules in the file /etc/snort/rules/local.rules manually or use a GUI to generate them.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/3d3c1087-8d45-452a-b834-1ca46902c023)


## SIMULATION OF ATTACKS AND INTRUSIONS

- IDS configuration: In the targeted machine, the following rules are added.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/fee9f618-2a94-4855-9ea2-31d263038387)

- NMAP scan detection.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/5a17048c-5cee-41da-a913-754a62d2fcbc)

![image](https://github.com/zaka1200/tp_snort/assets/121964432/246f035f-cf2b-4536-8099-2398ca959e5d)

- ICMP flooding DoS attack.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/e3610bec-56db-4355-9f68-5c9117d6f1aa)



## IDS CONFIGURATION
![image](https://github.com/zaka1200/tp_snort/assets/121964432/7d26b0e0-8e28-4a9a-99f0-3107f2929882)


- Detection of the attack: In the targeted machine, consult the snort.log file or view different information about the detected intrusion, including the type of attack, the responsible IP address, and the date.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/ac246121-3e6a-401f-b343-73d4c48bc871)


## ARP Spoofing Attack

![image](https://github.com/zaka1200/tp_snort/assets/121964432/8feb3dfe-7676-4a90-af1f-7e8fedbf0c2d)

![image](https://github.com/zaka1200/tp_snort/assets/121964432/a1502135-1b1c-4954-a2aa-e00e1d8878dc)

- ARP spoofing attack:


-   Without the implementation of Snort, the attacker was able to perform a MITM attack and sniff packets destined for the machine 192.168.10.168.

## IDS CONFIGURATION

![image](https://github.com/zaka1200/tp_snort/assets/121964432/e2914fc7-0b65-44a6-aa36-b1a5d2254776)

- Detection of the attack.

![image](https://github.com/zaka1200/tp_snort/assets/121964432/c26fc03f-66a7-4783-afda-0731a17abc2e)


# CONCLUSION

In conclusion, Snort is a powerful and widely used open-source Intrusion Detection System (IDS). Based on the simulations of attacks, Snort offers several advanced features such as real-time intrusion detection, packet capture, protocol analysis, event logging, integration with other security tools, and much more. It can detect various types of attacks, including port scans, exploitation attempts, DoS attacks, and suspicious activities.

However, it is important to note that Snort is not a complete standalone security solution. It should be used as part of a comprehensive security approach that includes other security measures such as firewalls, antivirus software, regular patching, and good security practices.



