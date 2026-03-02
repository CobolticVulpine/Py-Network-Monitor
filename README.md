# Py-Network-Monitor
Py-Network-Monitor: A python script that creates a GUI using tkinter to display 
a devices IP, Hostname, Vendor, OS, Risk and Status as well as providing a counter
of online, offline and total number of devices.

Risk is determained by the number of open ports on the device
ports can be added or deleted using the "HIGH_RISK_PORTS" list in "netmon.py"

HIGH_RISK_PORTS = [21, 23, 3389, 139, 445, 1433, 3306, 5900, 5432, 137, 138]

# Requirements
In order to run the script you will need to install Nmap
which can be downloaded at:

https://nmap.org/download.html

You will also need to run
in Terminal/CMD:

"pip install -r requirements.txt"
