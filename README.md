
---
# DNS-Based Threat Detection & Auto-Blocking System

This project provides an automated DNS security solution that detects malicious domain queries, blocks them in real time, deploys the setup across client machines using Puppet, and monitors system health using Nagios.

----------

## **Features**

-   Detects suspicious DNS queries using VirusTotal API
    
-   Automatically blacklists malicious domains using **dnsmasq**
    
-   Puppet-based deployment to multiple client machines
    
-   Nagios monitoring to ensure:
    
    -   dnsmasq is running
        
    -   Malware detection script is active
        
    -   Puppet agent is active on clients
        

----------

## **Prerequisites**


**Server Prerequisites:**

-   Ubuntu/Debian VM (recommended for Master node)
    
-   Puppet Master installed and running
    
-   Nagios Core installed (preferably from source)
    
-   NRPE plugin installed (to monitor remote nodes)
    

**Client Prerequisites:**

-   Ubuntu/Debian VM (Agent node)
    
-   Puppet Agent installed and connected to Master
    
-   dnsmasq installed and active
    
-   Python3 installed for malware detection script
    
-   NRPE server installed (allows Nagios to run checks remotely)

---

### **Python Script Dependencies**

Add your **VirusTotal API key** in the script:

`VT_API_KEY =  "{api-key}"` 

----------

## How It Works

1.  **dnsmasq** acts as the local DNS resolver on the client
    
2.  A Python script monitors DNS queries and checks suspicious domains via VirusTotal
    
3.  If malicious:
    
    -   Domain is added to `/etc/dnsmasq-blacklist`
        
    -   dnsmasq blocks it by resolving to `0.0.0.0`
        
4.  **Puppet** auto-installs and configures dnsmasq + the script on all client machines
    
5.  **Nagios** monitors:
    
    -   dnsmasq status
        
    -   Python script running status
        
    -   Puppet agent status
        
    -   Basic system health (CPU, Disk, RAM, Load)
        

----------


## **Deployment Flow**

1.  **Puppet Master** pushes configuration and scripts to client nodes.
    
2.  **Client machines** receive configuration via Puppet Agent and apply changes.
    
3.  **dnsmasq** is installed, configured, and started on the client.
    
4.  The **Python malware detection script** is deployed and started on the client.
    
5.  **dnsmasq** resolves DNS queries and the script checks suspicious domains via VirusTotal.
    
6.  **Malicious domains** are added to the blacklist and auto-blocked.
    
7.  **Nagios Server** continuously monitors dnsmasq, the Python script, and Puppet Agent status on each client.
    