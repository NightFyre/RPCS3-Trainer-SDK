# 🎮 RPCS3 Trainer SDK 
*A modern toolkit for developing trainers, mods, and game enhancements for the RPCS3 emulator.*

---

## ✨ Overview

**RPCS3 Trainer SDK** is a C++ development kit that empowers developers, modders, and reverse engineers to create trainers, patches, and enhancements for PlayStation 3 games running in the **RPCS3** emulator.
It modernizes cheat development with memory tools, runtime hooks, and UI overlay support making it easier than ever to build feature-rich trainers.
    
---

## 🔑 Features
- 🛠 **Memory Tools** – Read and write PS3 game memory.  
- 🎮 **Trainer Core** – Build trainers with overlays, hotkeys, and menu systems.  
- 📦 **Game Module SDKs** – Extend functionality with game-specific add-ons.  

---

## 🚀 Getting Started

### Prerequisites
- Visual Studio (2019 or later) or any C++17-compatible compiler  
- RPCS3 emulator (latest stable or nightly build)  

---

### 🧩 Game Module SDKs

The **RPCS3-Trainer-SDK** supports modular extensions through **Game Module SDKs** — standalone repositories designed to integrate game-specific logic, memory maps, and utilities.

Each Game Module SDK includes:

* Predefined headers and helper classes for trainer integration
* Example source files for implementing custom features
* Lightweight documentation for setup and usage

📦 **Official Game Module SDK Repository:**
➡️ [RPCS3-Trainer-Modules](https://github.com/NightFyre/RPCS3-Trainer-Modules)

Developers can clone or include any module directly within their project’s `/modules/` directory.
To contribute new modules, follow the guidelines in the **Modules Repository**.

---

## 🤝 Contributing
Contributions are welcome!  
- 🐛 Open issues for bugs or feature requests.  
- 🍴 Fork the repo, make improvements, and submit a PR.  
- 📚 Add new starter projects under `/examples` to help others learn.  
- 🧹 Keep changes focused and provide clear descriptions/tests where applicable.

---

### References & Credits
- [RPCS3](https://github.com/RPCS3/rpcs3) - The PlayStation 3 Emulator
- [GameHacking.org](https://gamehacking.org/system/ps3) - A valuable resource for game hacking techniques.
- [A General Guide for Making Cheats & Trainers for RPCS3](https://www.unknowncheats.me/forum/playstation/729023-rpcs3-guide-cheats-trainers.html)

---

## 📜 License
This project is licensed under the MIT License.
For educational and single-player purposes only. Please use responsibly.

---

### Disclaimer
1. *This framework is intended for educational and single-player use.*  
2. *Use cheats responsibly and respect the terms of use of the games you are modifying.*