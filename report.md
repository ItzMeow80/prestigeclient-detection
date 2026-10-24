# Detection Brief: Prestige Client / Prestige Injection

**Authors:** MEOW & KHATOXD
**Signature ID:** PRESTIGE-CLIENT-2026
**Threat type:** Minecraft cheat + manual-map injector
**Severity:** High
**Confidence:** High
**Collected:** 2026-10-21
**Validated:** 2026-10-21, tested directly against both real binaries
**Method:** static analysis + live traffic capture of the download (WinHTTP proxy)

---

## 1. In short

Prestige is a paid Minecraft cheat. The user downloads a small launcher
(`Prestige Launcher.exe`). That launcher does **not** contain the cheat itself.
Instead it connects to the seller's backend, downloads a large protected
payload, and loads it into memory using **manual mapping** instead of the normal
Windows loading path. The payload then finds the Minecraft process
(`javaw.exe`) and injects the cheat client into it.

Two properties matter for detection:

1. The cheat **never touches disk as a loaded module**, so normal module-based
   checks see nothing.
2. The cheat can **unload and wipe itself** from the game's memory on command.

The launcher is code-signed with a Sectigo certificate issued to
"Prestige Software Development". A signature here proves nothing except that
they bought a certificate.

---

## 2. Files and hashes

These identify **this specific build only**. Treat them as a high-confidence
hit, never as your only rule.

**Launcher** — `Prestige Launcher.exe`, 237848 bytes

    SHA256  D7508C0022D959E4566D2CC1742CC0B7752B6FD1E692ECAB7CEF7AC6B9D8EEC3
    MD5     A802560CC00C14F811F003991A717E8C

**Downloaded payload** — 4932864 bytes

    SHA256  A649B9304DD74EB38178AD99D193FC2458D4F96FC95E8C4590EFF630561C701F
    MD5     BDC3B52BFC6D0BCFE75065357357EAA4

---

## 3. What we actually verified

We extracted every ASCII and UTF-16 string from both binaries and ran the YARA
rules against them. Findings:

**Launcher** — rule `Prestige_Launcher`

    13 of 13 error messages found (ASCII)
    "Prestige Launcher" / "Prestige Launcher.exe" / "PrestigeLauncher"  -> UTF-16 only
    "Prestige Software Development" -> ASCII, also the certificate subject
    "api.prestigeclient.vip" / "/launcherDownload" -> UTF-16 only
    manifest: assemblyIdentity name="Prestige Launcher" version="1.2.3.0"
    sections: .text .rdata .data .pdata .fptable .rsrc .reloc  (NOT packed)
    rule fires on: 4 of ($e*)  -> matched, all 13 present

**Payload** — rule `Prestige_Client_Module`

    both PDB build paths found
    all 8 product strings found
    VMProtect sections .vm_sec and .vlizer both present
    all cleanup strings found:
      "wiping the last traces"
      "module-manager-clean"
      "module-shutdown"
      "waiting for Prestige to unload"
      "no Prestige memory remains"
    "api.prestigeclient.vip" NOT present here (it lives in the launcher)
    rule fires on: 1 of ($pdb*)  -> first condition already sufficient

**Important detail for integrators:** the download host and endpoint are stored
as **UTF-16**, not ASCII. A scanner doing an ASCII-only pass over the launcher
will not see them. Both YARA strings are declared `ascii wide` for exactly this
reason.

---

## 4. Network indicators

    Host      api.prestigeclient.vip
              (also prestigeclient.vip, www.prestigeclient.vip)
    Endpoint  POST /launcherDownload
    Port      443
    User-Agent  none

The request is sent through WinHTTP with **no user-agent header at all**. That
is unusual and is a useful tell. Plain `curl` and `requests` calls are blocked
by Cloudflare, which is why a WinHTTP wrapper was needed to observe the traffic
in the first place.

---

## 5. On-disk artifacts

    %APPDATA%\Prestige\changelogs_cache.json
    %USERPROFILE%\Downloads\Prestige Launcher.exe

---

## 6. How the loader works

Understanding this is what lets you write a **runtime** rule instead of
depending on strings.

1. Downloads the payload via WinHTTP `POST /launcherDownload`.
2. Validates the blob is a real x64 DLL (MZ magic, PE signature,
   `Machine == IMAGE_FILE_MACHINE_AMD64`, `IMAGE_FILE_DLL` flag). Rejects
   anything else with its own error message.
3. **Manual maps it:**
   - `VirtualAlloc` at the preferred ImageBase `0x180000000`
   - copies headers and sections
   - applies base relocations (`IMAGE_REL_BASED_DIR64`, `IMAGE_REL_BASED_HIGHLOW`)
   - resolves imports manually with `LoadLibraryA` / `GetProcAddress` and
     patches the IAT
   - sets per-section protection with `VirtualProtect`
   - registers the x64 exception table with `RtlAddFunctionTable` (without this
     `DllMain` would crash on the first SEH)
   - calls `DllMain(DLL_PROCESS_ATTACH)`
4. Locates `java.exe` / `javaw.exe` and maps the client into it.
5. On command, unloads and wipes its traces from the game's memory.

**The detection hook for step 3:** look for an image sitting in **private
executable memory** (`MEM_PRIVATE`, not `MEM_MAPPED` from a file), with readable
MZ and PE headers, whose base address does **not** appear in the process module
list / PEB. That is a manually mapped module. A normally loaded DLL is both
file-backed and listed in the PEB; this is neither.

JVM JIT regions are executable but have no MZ/PE header, so they do **not**
trigger this check. That keeps false positives low.

---

## 7. Fileless injection: vectors the MZ check will miss

The check above only fires if the image kept its PE header. These techniques
drop the header or work at a lower level, so each needs its own signal.

**Raw shellcode (no header)**
Private executable memory that is not a PE and not file-backed, entered through
a thread start address outside any known module. Flag executable-private pages
whose first bytes are not MZ but which back an active thread start.

**Classic remote thread chain**
`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` /
`CreateRemoteThreadEx` against a process you do not own, or
`NtMapViewOfSection` with a remote process handle.

**Process hollowing**
A process created suspended (`CREATE_SUSPENDED`) whose image on disk does not
match what is mapped, or whose primary thread resumes at a start address
outside the on-disk image. Watch `NtUnmapViewOfSection` /
`NtMapViewOfSection` on a suspended child.

**APC / early-bird**
`QueueUserAPC` or `NtQueueApcThread` aimed at a freshly created suspended
thread before it reaches its entry point.

**Thread hiding (less common, still worth logging)**
Thread start addresses inside memory regions with no owning module,
`SetWindowsHookEx` into a foreign process, or
`NtSetInformationThread(ThreadHideFromDebugger)`.

Any two of these in one session, together with a Prestige string, is a
confident hit.

---

## 8. Self-destruct behaviour

The payload can unload from the game and wipe what it left behind. Strings it
produces during cleanup:

    wiping the last traces
    no Prestige memory remains
    module-manager-clean
    module-shutdown
    waiting for Prestige to unload

This is the hardest part to detect, because it is an **event over time**, not
something a single file scan can catch. The practical approach is to sample
process memory on an interval and look for either:

- **signature count dropping from N > 0 to 0 while `javaw` is still alive**
  → the module unloaded, or
- **private regions filled with a flat pattern** (`0x00`, `0xCC`, ...)
  → the memory was wiped.

Admin privileges are required. `PROCESS_VM_READ` and PEB enumeration both fail
without them.

---

## 9. Packer

The payload is protected with **VMProtect**; both `.vm_sec` and `.vlizer`
sections are present. Two sections together are a strong indicator, but VMProtect
is also used by plenty of legitimate commercial software, so never fire on the
packer alone. Combine it with a product string or a PDB path.

The **launcher is not packed** — it uses ordinary `.text .rdata .data .pdata
.fptable .rsrc .reloc` sections. Run packer checks against the downloaded
module, not the loader.

---

## 10. Package contents

    iocs.json       hashes / network / paths / PE fields, machine readable
    prestige.yar    Prestige_Client_Module + Prestige_Launcher
    behavioral.md   runtime indicators + fileless vectors
    report.md       this document

---

## 11. Known limitations

Stated up front so there are no surprises later.

1. **Strings and hostnames are cheap to change.** Error messages, the domain and
   the product name can all be rewritten in about ten minutes. The anchors that
   actually hold across rebuilds are the two PDB paths and the VMProtect
   sections:

       Prestige-Injection\Dependencies\cryptopp
       C:\Users\Admin\source\repos\Prestige-Injection

2. **False positives not yet measured.** The YARA conditions combine several
   signals to keep FP low, and every string was verified against the two real
   samples. However the rules have **not** yet been run against a corpus of
   clean files. Please validate before production deployment.

3. **Self-destruct cannot be caught statically.** It is a timing-based
   behaviour and needs continuous monitoring.

4. **This is not a drop-in module.** It provides IOCs, static signatures and a
   behavioural specification. Converting that into live runtime detection is
   work on the integrating side.

---

**Made by MEOW & KHATOXD**
