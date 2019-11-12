# DDoS Mitigation Solution

This script support Tier1 engineer handle traffic by one execution to take care DDoS attack

[Purpose]

Arbor peakflow system monitor DDoS traffic and make alert with Target IP prefixes and location(DC)
When DDoS traffic is getting into infrastructure, tier1 operator take action urgently and prevent service impact.

[Function]
 - Step1. traffic shift to DDoS protection device and get clean data that is filtered by protection device via VRF
    - Apply ingress traffic filtering at all circuit
    - First filtering policy forward traffic by destination address to DDoS protection device through VRF
    - Script add this destination address(Range : /24 ~ /32), then traffic filtering is enabled
 - Step2. traffic shift to other DC that have huge bandwidth - Accept Full DDoS traffic
    - GRE/IBGP is working between normal DC and huge bandwidth DC
    - Script stop BGP announcement for target IP prefixes from target DC to ISP
    - Script start BGP announcement for target IP prefixes from huge bandwidth DC to ISP
    - DDoS traffic will be shifted to huge bandwidth DC and issue is resolved at normal DC
    - Huge bandwidth DC filter DDoS traffic and send clean traffic to normal DC via GRE tunnel
 - Step3. Blackhole Filtering with BGP community value that is provided by ISP
    - Script announce target IP prefixes via BGP session with Blackhole community that is provided by ISP
    - All DDoS traffic is filtered by ISP side

[Manual]

 1) Run DDoS_Protect_V21.py
 2) Enter TACACS+ account to login router
 3) Select target DC (Script show Prefixes that routers are advertising to ISP)
 4) Select DDoS target IP prefixes
 5) Select 'Step1~3' follow the guide : Guide provide which step select it depends situation
 6) After DDoS attack is finished, rollback traffic
        
[Requirement]
 - Python higher than Version 3
 - tkinter (GUI Toolkit)  

[Supported Vendor]
 - Juniper
 
[Note]
 - When we install other vendor, we need define new function to update standard configuration(VRF, BGP, route-map)
