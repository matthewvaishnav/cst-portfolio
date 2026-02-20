# OSI Model

## Overview

The OSI (Open Systems Interconnection) model is a conceptual framework used to understand how network communication occurs between systems.  

It divides communication into seven logical layers, each responsible for a specific function in the data transmission process.

Understanding the OSI model is essential for troubleshooting, packet analysis, and network design.

---

## The 7 Layers

### 7. Application
- User-facing network services
- Examples: HTTP, FTP, SMTP, DNS

### 6. Presentation
- Data formatting and translation
- Encryption / decryption
- Compression

### 5. Session
- Manages communication sessions
- Session establishment and termination

### 4. Transport
- End-to-end communication
- Segmentation and reassembly
- Flow control
- Protocols: TCP, UDP

### 3. Network
- Logical addressing (IP)
- Routing between networks
- Routers operate at this layer

### 2. Data Link
- MAC addressing
- Frame formatting
- Switches operate at this layer

### 1. Physical
- Physical transmission of bits
- Cables, voltage levels, connectors

---

## Encapsulation Process

When data is transmitted:

Application Data  
→ Transport adds segment header  
→ Network adds IP header  
→ Data Link adds frame header  
→ Physical transmits bits  

Each layer adds its own header information.

---

## Practical Relevance

In real-world troubleshooting:

- If a device has no link light → Physical layer issue
- If IP configuration is wrong → Network layer issue
- If packets drop intermittently → Transport issue
- If web page fails but ping works → Application layer issue

The OSI model provides a structured method for isolating network problems.
