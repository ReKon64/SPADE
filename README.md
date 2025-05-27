# SPADE

**Scalable Plug-and-play Auto Detection Engine**

SPADE is a modular vulnerability scanning framework that leverages external tools like `nmap`, `curl`, and others. It uses Python class decorators and reflection to auto-register modules for execution, making it easy to extend and customize.

## ✨ Features

- 🔌 Plug-and-play modules via class decorators
- 🔍 Built-in support for external tools (e.g. `nmap`)
- 🧠 Reflection-based auto-discovery of scanners
- 📦 Designed for packaging and easy execution via `pipx`
- 💬 Minimal boilerplate for writing custom scan modules

## 🚀 Getting Started

# TODO
# Separate prefix for TCP ? How do I make the other methods wait for it? just que them and sleep em? 

1. Create a convention for findings. 
2. Provide clear documentation for writing scanners and finding returning cleaner
3. Create the report class

# Establish a uniform schema for plugin results
# ?
# 1. Plugins key -> plugin name -> command -> result 1, result 2 

# UDP fails to pass scan entry data even if the plugin res are empty
# But TCP and UDP are finally decoupled in execution. Dunno about result handling though
2025-05-27 16:51:23,670 - INFO - UDP scan completed. Results saved to /tmp/tmppfx8jkw7.xml
2025-05-27 16:51:23,670 - INFO - [+] Starting port-specific enumeration
2025-05-27 16:51:23,670 - DEBUG - [*] Service scan used entry data : []
2025-05-27 16:51:23,670 - INFO - [+] No services found to enumerate
2025-05-27 16:51:23,670 - INFO - [+] Completed UDP port-specific enumeration
2025-05-27 16:51:26,033 - REAL-TIME - SYN Stealth Scan Timing: About 51.44% don
#
2025-05-27 16:51:23,670 - INFO - UDP scan completed. Results saved to /tmp/tmppfx8jkw7.xml
#

# Make it accept multiple targets, multiple 1target xmls and overlaying them for overwriting target IPs
# Generic product exploit search is broken [Fixed?]
# Implement prefix for unknown services for extensibility.
# Add OS type at the head where hostname etc. lies
# FIX THREADING IT USES 16 THREADS PER PORT FUCKKK
# Test SMB crawling
# Fingerprint all the things
# Brute all the things !11!
# generic prod search -> exploits -> ai fix exploit -> try to run it
# find names / roles -> ask AI if it makes sense
# Credentialed enumeration...
# Guest enumeration ...
# If HTTP returns a domain name / vhost , bruteforce
# Write a github copilot prompt schema on how to write commit msgs
NMAP -> Results -> NMAP Protocol Specific Scanners (SMB TOO) -> BruteForce -> FeroxBust -> FingerPrint -> Check Exploits -> Build into one "big" NMAP report
-> Create to do list for the tester -> Add AI fingerprinting magic for git clout