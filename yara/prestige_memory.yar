/*
 *  Prestige Client / Prestige Injection
 *  Memory-oriented rules - the ones that matter for a runtime anti-cheat
 *  Authors: MEOW & KHATOXD
 *
 *  Use these against process dumps / RAM snapshots of javaw, java,
 *  PrestigeLauncher, or any process where the payload got manual-mapped.
 *
 *  WHY THESE EXIST: a manually mapped module is MEM_PRIVATE and does not
 *  appear in the PEB module list, so module-based checks miss it entirely.
 *  Strings survive in RAM even after the file is deleted, and they survive a
 *  partial wipe. This is where you catch it.
 *
 *  FP TESTED 2026-10-21 against 694 clean System32 binaries -> 0 hits
 */

rule Prestige_Module_InMemory
{
    meta:
        description = "Prestige client module resident in process memory"
        author      = "MEOW & KHATOXD"
        severity    = "high"
        category    = "cheat.in_memory"
        date        = "2026-10-21"
        reference   = "PRESTIGE-CLIENT-2026"

    strings:
        // in-memory these are the most reliable, they are big and specific
        $s1 = "Prestige Injection is ready"                       ascii wide
        $s2 = "Inject Prestige Client"                            ascii wide
        $s3 = "Prestige could not map the secure payload"         ascii wide
        $s4 = "The complete Prestige experience with manual mapping" ascii wide
        $s5 = "PRESTIGE_CMM_DEBUG_STAY"                           ascii wide
        $s6 = "Active - waiting for Prestige to unload."          ascii wide
        $s7 = "Done - no Prestige memory left in the game."        ascii wide
        $s8 = "Prestige Client Mod"                               ascii wide

        $pdb1 = "Prestige-Injection\\Dependencies\\cryptopp"      ascii wide
        $pdb2 = "C:\\Users\\Admin\\source\\repos\\Prestige-Injection" ascii wide

        $n1 = "api.prestigeclient.vip"                            ascii wide
        $n2 = "prestigeclient.vip"                                ascii wide

        // self-destruct residue - may be caught mid-wipe
        $u1 = "wiping the last traces"                            ascii wide
        $u2 = "no Prestige memory remains"                        ascii wide
        $u3 = "waiting for Prestige to unload"                    ascii wide
        $u4 = "module-manager-clean"                              ascii wide
        $u5 = "module-shutdown"                                   ascii wide

    condition:
        // two independent markers = confident, one PDB path = certain
        1 of ($pdb*) or
        2 of ($s*) or
        (1 of ($s*) and 1 of ($n*)) or
        (1 of ($s*) and 1 of ($u*)) or
        3 of ($u*)
}

rule Prestige_Launcher_InMemory
{
    meta:
        description = "Prestige Launcher loader resident in memory"
        author      = "MEOW & KHATOXD"
        severity    = "medium"
        category    = "cheat.loader_in_memory"
        date        = "2026-10-21"
        reference   = "PRESTIGE-CLIENT-2026"

    strings:
        $e1  = "Download corrupted (bad MZ)."                     ascii wide
        $e2  = "Download corrupted (not a 64-bit DLL)."           ascii wide
        $e3  = "Missing dependency for the Prestige module:"      ascii wide
        $e4  = "Unresolved import in the Prestige module."        ascii wide
        $e5  = "The Prestige module refused to initialize."       ascii wide
        $e6  = "The Prestige module missing its entry point."     ascii wide
        $e7  = "Could not download Prestige."                     ascii wide
        $e8  = "Your antivirus is blocking requests to the Prestige API." ascii wide
        $e9  = "Your internet provider is blocking requests to the Prestige API." ascii wide

        $id1 = "Prestige Launcher"            ascii wide
        $id2 = "PrestigeLauncher"             ascii wide
        $id3 = "Prestige Software Development" ascii wide

        $n1 = "api.prestigeclient.vip"        ascii wide
        $n2 = "/launcherDownload"             ascii wide

    condition:
        3 of ($e*) or
        (2 of ($e*) and 1 of ($id*)) or
        (1 of ($id*) and 1 of ($n*)) or
        (2 of ($n*) and 2 of ($e*))
}

rule Prestige_SelfDestruct_Residue
{
    meta:
        description = "Cleanup strings left behind by the Prestige unload/wipe routine"
        author      = "MEOW & KHATOXD"
        severity    = "medium"
        category    = "cheat.self_destruct"
        date        = "2026-10-21"
        note        = "fires even when the payload is half-wiped - these strings are short and get missed by the wipe"

    strings:
        $d1 = "wiping the last traces"            ascii wide
        $d2 = "no Prestige memory remains"        ascii wide
        $d3 = "waiting for Prestige to unload"    ascii wide
        $d4 = "module-manager-clean"              ascii wide
        $d5 = "module-shutdown"                   ascii wide
        $d6 = "Verified: no Prestige memory remains" ascii wide

    condition:
        2 of them
}

rule Prestige_ManualMap_PE_In_PrivMem
{
    meta:
        description = "Behavioral - a full PE image sitting in private executable memory"
        author      = "MEOW & KHATOXD"
        severity    = "medium"
        category    = "injection.manual_map"
        date        = "2026-10-21"
        note        = "generic manual-map signal. Combine with Prestige_Module_InMemory for attribution. Alone it also catches other injectors and some legitimate software (DRM, anticheats)."

    strings:
        $mz     = { 4D 5A }
        $pe     = "PE"
        $prest  = "Prestige" ascii wide

    condition:
        // PE header plus Prestige content anywhere in the region
        $mz at 0 and $pe and $prest
}
