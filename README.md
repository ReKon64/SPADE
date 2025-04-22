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
1. Create a convention for findings. 
2. Provide clear documentation for writing scanners and finding returning cleaner
3. Build upon "base exploit" class to make the structure and finding fetching clearer
4. Create the report class

5. Decide if I want "findings" list into a dictionary. Quicker lookup, cleaner code


NMAP -> Results -> NMAP Protocol Specific Scanners (SMB TOO) -> BruteForce -> FeroxBust -> FingerPrint -> Check Exploits -> Build into one "big" NMAP report
-> Create to do list for the tester -> Add AI fingerprinting magic for git clout