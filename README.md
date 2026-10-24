<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=22&pause=1200&color=00FFB3&center=true&vCenter=true&width=850&lines=PrestigeClient+Detection;YARA+%7C+Sigma+%7C+Suricata+%7C+IOCs;Validated+Against+Real+Samples;Keeping+The+Lobby+Clean" alt="Typing SVG" />
</p>

---

### `about`

```
$ ./prestige-detection --info
```

```
Signature :  PRESTIGE-CLIENT-2026
Authors   :  MEOW & KHATOXD
Target    :  Prestige Client / Prestige Injection (Minecraft cheat)
Type      :  Signed loader + VMProtect payload, manual-map into javaw.exe
Vectors   :  Disk · Memory · Process · Network
Severity  :  [ HIGH ]
```

---

## 📦 Contents

```
validate.ps1                  self-test harness - run this first
report.md                     full detection brief (start here)
behavioral.md                 runtime indicators + fileless vectors
iocs.json                     machine-readable IOCs

yara/prestige_disk.yar        rules for files on disk (3 rules, FP tested)
yara/prestige_memory.yar      rules for process RAM (4 rules)

sigma/prestige.yml            3 Sigma rules (process creation, proxy, file event)
network/prestige.rules        Suricata/Snort rules (DNS, SNI, HTTP)
```

## 🚀 Quick start

```powershell
powershell -ExecutionPolicy Bypass -File .\validate.ps1
```

Expected output: `RESULT: n passed, 0 failed / STATUS: READY FOR SUBMISSION`

con motore YARA reale:

```powershell
powershell -ExecutionPolicy Bypass -File .\validate.ps1 -YaraPath C:\tools\yara64.exe
```

**Fileless / manual-map mode:** quando il client è caricato senza file su disco, le disk rules restituiscono nulla **per design**. Scansiona la **memoria del processo** con `yara/prestige_memory.yar` — la regola `Prestige_Module_InMemory` è quella che scatta.

## 🎯 Which rule to use where

| Situation | Rule |
|---|---|
| Scanning downloads / files on disk | `yara/prestige_disk.yar` |
| Scanning process RAM, memory dumps | `yara/prestige_memory.yar` |
| Catching the loader after it was renamed | `Prestige_Launcher_OnDisk` |
| Catching a half-wiped payload | `Prestige_SelfDestruct_Residue` |
| Generic manual-map detection | `Prestige_ManualMap_PE_In_PrivMem` |
| SIEM / log correlation | `sigma/prestige.yml` |
| Blocking the infrastructure | `network/prestige.rules` |

## 🔗 Strongest anchors (survive a rebuild)

```
Prestige-Injection\Dependencies\cryptopp      (PDB path, module)
C:\Users\Admin\source\repos\Prestige-Injection (PDB path, module)
.vm_sec + .vlizer                              (VMProtect sections, module)
```

deboli / cambiano in minuti: error messages, hostname, product name, hashes.

## ⚠️ Known limitations

1. Hashes and hostnames change per build — high-confidence hit only.
2. FP tested su 694 binari System32 puliti, 0 falsi positivi — corpus più ampio consigliato.
3. Self-destruct è temporale — serve campionamento ad intervalli, non una singola scan.
4. Runtime detection va implementata dal motore che integra le regole.
5. Validazione sintattica YARA simulata — girare il motore reale prima della produzione.

read `report.md` section 11 prima di agire su un alert.

---

## 🛠️ Arsenal

[![YARA](https://img.shields.io/badge/YARA-FF6B35?style=for-the-badge&logo=virustotal&logoColor=white)](https://virustotal.github.io/yara/)
[![Sigma](https://img.shields.io/badge/Sigma-6A4C93?style=for-the-badge&logo=sigma&logoColor=white)](https://sigmahq.io/)
[![Suricata](https://img.shields.io/badge/Suricata-1B8
