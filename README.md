# CloakBox - VM Detection Bypass 🛡️

**Bypass virtual machine detection using a custom VirtualBox fork**

![GitHub all releases](https://img.shields.io/github/downloads/Batlez/CloakBox/total?style=for-the-badge)

Created by **Vektor T13** | Maintained by **kdmeena** |⚡Works in 2025! |⏱️ Setup time: ~30 minutes

## 📥 Download
- **Primary**: [GitHub Releases](https://github.com/Kdmeenaa/CloakBox/releases)
- **Virus Scan**: [VirusTotal Scan](https://www.virustotal.com/gui/file/17ba6063ba20eba0ffc6538609d0cd216e015efd146e6e82e7de33e743cd8905/detection)

## 🎯 What it bypasses
✅ Examity | ✅ Respondus | ✅ Safe Exam Browser | ✅ ProctorU | ✅ Pearson VUE | ✅ Lockdown Browser | ✅ Honorlock | ✅ Guardian

<details>
<summary>Click ME to see pictures of Cloakbox bypassing</summary>
<img width="1920" height="1021" alt="1" src="https://github.com/user-attachments/assets/1af2116c-e69a-4379-bc39-655fad572164" />
<img width="1920" height="1018" alt="2" src="https://github.com/user-attachments/assets/a505ffd0-56dc-4e1b-8502-07ab5c20c52e" />
<img width="1920" height="1021" alt="3" src="https://github.com/user-attachments/assets/22487ead-923f-4547-a1ea-a01b788a60c8" />
<img width="1019" height="760" alt="4" src="https://github.com/user-attachments/assets/449757c6-12b3-4b73-8143-1c95123f3fab" />
<img width="1021" height="760" alt="5" src="https://github.com/user-attachments/assets/21845d07-daad-4f07-a10a-18062891fb22" />

</details>
<details>
<summary>Fix "Windows version not showing" when creating a VM</summary>

**Disable** SV-IOV setting in your motherboard's BIOS, it should be under: PCI Configuration
</details>

## ⚡ Quick Start
1. **Uninstall** existing VirtualBox/VMWare
2. **Install** CloakBox (run as admin)
3. **Create VM** with 80GB+ storage (.VDI format, SATA)
4. **Install Windows 10** using Media Creation Tool ISO
5. **Run scripts** in this order:
   - `RUN ON PC.ps1` (on host)
   - `RUN IN VM.ps1` (inside VM)
   - `AntiOS.exe` (inside VM)
   - `GPU Spoofer.exe` (inside VM)
   - `VM CHECKER.ps1` (inside VM)
   - `Pearson OnVUE.ps1` (inside VM if using OnVUE)

## 🎥 Need Help?
- **Video Guide**: [YouTube Tutorial](https://www.youtube.com/watch?v=rk_TTvOCUtU)
- **Discord Support**: **kdmeena*

## ⚖️ Legal
For ethical testing and research purposes only. Users responsible for compliance with local laws.
