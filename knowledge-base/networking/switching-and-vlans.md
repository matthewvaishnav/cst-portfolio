# Switching and VLANs

## Overview

Switching operates at Layer 2 (Data Link) of the OSI model and is responsible for forwarding frames based on MAC addresses.

Switches enable communication within a local network and create broadcast domains.

VLANs (Virtual Local Area Networks) allow logical segmentation of a network without requiring separate physical switches.

---

## How Switching Works

Switches maintain a MAC address table (CAM table).

When a frame arrives:

1. The switch learns the source MAC address.
2. It checks the destination MAC address.
3. If known → forwards frame to specific port.
4. If unknown → floods frame to all ports (except source).

This reduces unnecessary traffic compared to hubs.

---

## Broadcast Domains

A broadcast domain is the group of devices that receive broadcast traffic.

By default:
- All ports on a switch belong to one broadcast domain.

Large broadcast domains:
- Increase unnecessary traffic
- Reduce efficiency
- Create security concerns

---

## VLANs (Virtual Local Area Networks)

VLANs logically separate devices into different broadcast domains.

Example:

VLAN 10 → Management  
VLAN 20 → Users  
VLAN 30 → Servers  

Even if devices are connected to the same physical switch, they cannot communicate without routing between VLANs.

---

## Access vs Trunk Ports

### Access Port
- Assigned to a single VLAN
- Connects end devices (PCs, printers)

### Trunk Port
- Carries traffic for multiple VLANs
- Used between switches or to routers
- Uses 802.1Q tagging

---

## Inter-VLAN Routing

Devices in different VLANs cannot communicate directly.

A router or Layer 3 switch is required for inter-VLAN routing.

Common implementation:
- Router-on-a-stick (single trunk link to router)
- Layer 3 switch routing internally

---

## VLAN Benefits

- Improved security through segmentation
- Reduced broadcast traffic
- Easier network management
- Logical grouping of departments/services
- Isolation of lab environments

---

## Example Use Case (Homelab)

In a Proxmox-based lab:

VLAN 10 → Management network  
VLAN 20 → SOC/Monitoring VM  
VLAN 30 → Attack simulation (Kali)  
VLAN 40 → General user testing  

Inter-VLAN routing controlled via firewall rules.

This structure mimics enterprise network segmentation.

---

## Practical Relevance

Switching and VLAN knowledge is essential for:

- Network segmentation
- Firewall policy enforcement
- SOC lab isolation
- Infrastructure scaling
- Reducing lateral movement in security design

Improper VLAN configuration can result in:
- Traffic leakage
- Broadcast storms
- Security exposure

Strong Layer 2 understanding supports both system administration and security roles.
