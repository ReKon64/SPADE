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

# Maybe use topology for everything? Would solve the issue of udp blocking tcp
# Generic product is broken
# Add OS type at the head where hostname etc. lies
# Create plugin execution order mechanism. Maybe a config file even
# FIX THREADING IT USES 16 THREADS PER PORT FUCKKK
# Test SMB crawling
# Fingerprint
# Brute all the things !11!
# Credentialed enumeration...
# Guest enumeration ...
# If HTTP returns a domain name / vhost , bruteforce
# Write a github copilot prompt schema on how to write commit msgs
NMAP -> Results -> NMAP Protocol Specific Scanners (SMB TOO) -> BruteForce -> FeroxBust -> FingerPrint -> Check Exploits -> Build into one "big" NMAP report
-> Create to do list for the tester -> Add AI fingerprinting magic for git clout