# SPADE

**Scalable Plug-and-play Auto Detection Engine**

SPADE is a modular vulnerability scanning framework that leverages external tools like `nmap`, `curl`, and others. It uses Python class decorators and reflection to auto-register modules for execution, making it easy to extend and customize.

## ✨ Features

- 🔌 Plug-and-play modules via class decorators
- 🔍 Built-in support for external tools (e.g. `nmap`)
- 🧠 Reflection-based auto-discovery of scanners
- 📦 Designed for packaging and easy execution via `pipx`
- 💬 Lax plugin development guidelines

## 🚀 Getting Started

# 🚀 SPADE

**Scalable Plug-and-play Auto Detection Engine**

---

![SPADE Banner](https://img.shields.io/badge/SPADE-v1.0-purple?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9+-green.svg?style=flat-square)
![License](https://img.shields.io/badge/license-AGPL%203.0-yellow?style=flat-square)

---


SPADE is a modular vulnerability scanning framework that leverages external tools like `nmap`, `curl`, and more. It uses Python class decorators and reflection to auto-register modules for execution, making it easy to extend and customize.

---

## ✨ Features

- 🔌 **Plug-and-play modules** via class decorators
- 🔍 **Built-in support** for external tools (e.g. `nmap`, `feroxbuster`)
- 🧠 **Reflection-based auto-discovery** of plugins and their arguments
- 📦 **Modern dependency management**: All dependencies are declared in `pyproject.toml` and handled by [Poetry](https://python-poetry.org/) ensuring reliable and reproducible installs
- 🚀 **Easy installation** via `pipx` (and soon Docker)
- 🤖 **AI-ready**: Built-in AI integrated plugins (WIP)
- 💬 **Lax plugin development guidelines** for rapid prototyping

---

## 🧐 Why?

I developed this project with a few key goals in mind:

- There’s a gap between heavyweight vuln scanners like Nessus and simple automation tools — SPADE aims to fix that by streamlining recon without taking all control away from the user.
- Most frameworks require you to learn a bunch of internal functions on top of the language itself, which slows down rapid development and scripting. SPADE is intentionally lax: you can break the rules and hack in your own logic easily.
- Many tools are still packaged improperly and can break at any moment. SPADE is packaged for `pipx` for reliability, and will be available as a Docker image in the future.

---

## 🚀 Getting Started

```bash
# Install with pipx (recommended)
pipx install spade
```

---

## 🧩 Extending SPADE

- Add your own scanner by creating a new Python file in `scanners/extensions/`
- Use the `@Scanner.extend` decorator to register your plugin
- See the dev guide and existing plugins for examples

---

## 📦 Packaging & Development

- SPADE uses a modern dependency system (`pyproject.toml`) for reproducible builds
- Install with [Poetry](https://python-poetry.org/), pip, or pipx
- Docker support is planned

---

## 🔮 What’s Next?

- Credentialed enumeration
- Built-in AI plugins

---

## 🤝 Contributing

Pull requests, issues, and suggestions are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

AGPL 3.0 License © 2025 [ReKon64](https://github.com/ReKon64)

---

> _SPADE: You won't need to open twelve terminals anymore._