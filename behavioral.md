# Prestige behavioral stuff

authors MEOW KHATOXD

these are the things that survive a rebuild and names strings host change but the
technique doesn't and this is what to look at at runtime not on disk

validated against the real samples on 2026-10-21
  launcher  sha256 D7508C0022D959E4566D2CC1742CC0B7752B6FD1E692ECAB7CEF7AC6B9D8EEC3
  module    sha256 A649B9304DD74EB38178AD99D193FC2458D4F96FC95E8C4590EFF630561C701F

## loading the payload

launcher uses WinHTTP and POST to /launcherDownload and port 443 and there's no
user-agent header at all (WINHTTP_NO_USER_AGENT_HEADER) and host and endpoint
are stored as UTF-16 so an ASCII-only string scan misses them

before it does anything it checks the blob it got is actually a x64 dll and
that means MZ and PE sig and machine == IMAGE_FILE_MACHINE_AMD64 and the
IMAGE_FILE_DLL flag and if not it bails out with its own error string like
"Download corrupted (bad MZ)." and there's 13 of those in total

imports are WINHTTP.dll and mscoree.dll and it's sectigo-signed with subject
"Prestige Software Development" and the signature means nothing here

## manual mapping (the interesting part)

VirtualAlloc at preferred ImageBase 0x180000000 and it falls back to whatever if that's taken
copies headers and sections and applies relocs (IMAGE_REL_BASED_DIR64 and IMAGE_REL_BASED_HIGHLOW)
resolves imports by hand with LoadLibraryA and GetProcAddress and patches the IAT
VirtualProtect per section depending on the R/W/X bits
registers the x64 exception table with RtlAddFunctionTable otherwise DllMain crashes on the first SEH
calls DllMain(DLL_PROCESS_ATTACH) on the entry point

what to hook at runtime is an image that's sitting in private executable memory
(MEM_PRIVATE not MEM_MAPPED from a file) with readable MZ + PE headers and
whose base address is not in the process module list or the PEB and that's a
manually mapped module and legit DLLs loaded with LoadLibrary show up in the
PEB and are file-backed while this one doesn't and isn't

JIT regions in the JVM are executable but have no MZ/PE header so they won't
trip this check which is good

## injecting into the game

the module goes looking for java.exe / javaw.exe and maps the client into it
and because it was manual-mapped nothing shows up in the target's PEB either

## fileless injection and other vectors to cover

the check above only fires on images that kept a MZ/PE header and these
variations drop the header or work at a lower level so they need their own
signals

raw shellcode with no header and that's private executable memory that is not a PE and
not file-backed entered via a thread start address outside any known module and you
flag exec-private pages whose first bytes are not MZ but that back an active thread start

classic create-remote-thread chain and that's VirtualAllocEx + WriteProcessMemory +
CreateRemoteThread or CreateRemoteThreadEx in a target you don't own or
NtMapViewOfSection with a remote process handle

process hollowing and that's a process created suspended (CREATE_SUSPENDED) whose image
on disk does not match the mapped image or whose primary thread is resumed
from a start address outside the on-disk image and watch for
NtUnmapViewOfSection / NtMapViewOfSection on a suspended child

APC and early-bird which is queueuserapc / NtQueueApcThread aimed at a freshly created
suspended thread before it reaches its entry point

thread hiding and that's less common but worth logging and it means thread start addresses in memory
regions with no owning module or SetWindowsHookEx into a foreign process or
NtSetInformationThread(ThreadHideFromDebugger)

any two of these in the same session plus a Prestige string is a confident hit

## self-destruct

it can unload itself from the game and wipe the traces and these are the
strings it leaves around while doing that

    wiping the last traces
    no Prestige memory remains
    module-manager-clean
    module-shutdown
    waiting for Prestige to unload

this one's a pain to detect because it's a thing that happens over time and not a
file you can scan once and what you can do is sample memory on an interval and
look for either of these

signatures going from N > 0 to 0 while javaw is still alive which means it unloaded
private regions filled with a flat pattern like 0x00 or 0xCC which means the memory got wiped

needs admin obviously since PROCESS_VM_READ and PEB enumeration both fail otherwise

## packer

VMProtect and sections .vm_sec and .vlizer both present and that's pretty strong but the
launcher itself is NOT packed (plain .text/.rdata/.data/.pdata/.fptable/.rsrc/
.reloc) so packer checks belong on the downloaded module and not on the loader

plenty of legit commercial software ships VMProtect too so don't fire on this
alone and combine it with something else
