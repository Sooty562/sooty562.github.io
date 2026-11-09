---

---

<p><a href="/">← Back to Home</a></p>

# Virtual Homelab

Welcome to one of my virtual homelab environments. This lab consists of three virtual machines connected through a NAT Network, providing an isolated environment for cybersecurity experimentation, network monitoring and digital forensic investigations. This particular lab exists to test and view the results of attacks on the Ubuntu VM made by Kali. The alerts that occur on the Wazuh Server machine and reviewed to see how a particular attack (such as port scanning) is seen from a defenders point of view. How it appears in the logs. 

## Network Topology

The following diagram illustrates the network architecture and connectivity of my virtual lab.

<div align="center">
  <img src="../assets/images/vmtopology.png" alt="Virtual Homelab Network Topology" width="100%">
</div>

### Virtual Machines

| Virtual Machine | Purpose |
|---|---|
| Kali Linux | Penetration testing and security assessments |
| Ubuntu | Linux server and testing environment |
| Wazuh Server | Security monitoring, SIEM and threat detection |

### Network Infrastructure

| Component | Description |
|---|---|
| NAT Network | Virtual network connecting all three VMs |
| Host Laptop | Physical machine hosting the virtual environment |
| Edge Router | Provides network connectivity to the internet |
| Internet | External network connectivity |

