# tp_snort

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



The implementation of Snort IDS will take place in the zone to detect intrusions in the local network.

## INSTALLATION AND CONFIGURATION OF SNORT

- Specify the local network and the interface protected by Snort.
- Configuration of rules: Snort uses detection rules to identify malicious activities. You can configure Snort rules by editing the main configuration file, usually located in the directory /etc/snort/snort.conf. You can customize existing rules or add new rules according to your needs. These will be added to the file /etc/snort/rules/rules.local.

## SNORT SERVICE

- Starting the Snort service.
- Putting Snort into listening mode.
- Adding rules: You can specify detection rules in the file /etc/snort/rules/local.rules manually or use a GUI to generate them.

## SIMULATION OF ATTACKS AND INTRUSIONS

- IDS configuration: In the targeted machine, the following rules are added.
- NMAP scan detection.
- ICMP flooding DoS attack.

## IDS CONFIGURATION

- Detection of the attack: In the targeted machine, consult the snort.log file or view different information about the detected intrusion, including the type of attack, the responsible IP address, and the date.

## ARP Spoofing Attack

- ARP spoofing attack: Without the implementation of Snort, the attacker was able to perform a MITM attack and sniff packets destined for the machine 192.168.10.168.

## IDS CONFIGURATION

- Detection of the attack.

# CONCLUSION

In conclusion, Snort is a powerful and widely used open-source Intrusion Detection System (IDS). Based on the simulations of attacks, Snort offers several advanced features such as real-time intrusion detection, packet capture, protocol analysis, event logging, integration with other security tools, and much more. It can detect various types of attacks, including port scans, exploitation attempts, DoS attacks, and suspicious activities.

However, it is important to note that Snort is not a complete standalone security solution. It should be used as part of a comprehensive security approach that includes other security measures such as firewalls, antivirus software, regular patching, and good security practices.



