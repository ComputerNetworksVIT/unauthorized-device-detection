# Unauthorized Device Detection Web Application

## Description
This project is a **lightweight web-based network security tool** that detects and flags **unauthorized devices** connected to a **local Wi-Fi or LAN network**.  

It scans the network for all connected devices, retrieves their **IP and MAC addresses**, and compares them with a **whitelist** of authorized devices.  
Unknown devices are flagged as **unauthorized** and shown on a simple web dashboard, where the admin can easily **whitelist** trusted devices.

This project demonstrates how real-time network monitoring can be achieved using basic network commands (Ping & ARP) and Flask web integration.

---

## Language & Dependencies
**Language:** Python  
**Frontend:** HTML, CSS, JavaScript  
**Framework:** Flask  
**Dependencies:**  
- flask  
- flask-cors  
- python-nmap *(optional, for advanced scanning)*  

---

## Installation
Instructions for installing dependencies:

```bash
# Step 1: Install required packages
pip install flask flask-cors python-nmap

```

## Usage
How to run your project:
```bash
# Step 1: Connect your laptop to a local Wi-Fi or mobile hotspot
# Step 2: Open Command Prompt and navigate to the project folder
cd "C:\Users\jayan\OneDrive\Desktop\CN project\Unauthorized-Device-Detector"

# Step 3: Run the application
python app.py

```
# Step 4: Open your browser and go to:
http://127.0.0.1:5000/

# You will now see a live dashboard displaying connected devices.
# Unknown devices will appear as 'Unauthorized' and can be whitelisted.

##Authors
```bash
#Aanya Patni 24BCE1897
#Palak Malapani 24BCE5268
#Jayant Bedi 24BCE1832
```
