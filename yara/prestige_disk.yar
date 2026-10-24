/*
 *  Prestige Client / Prestige Injection
 *  Disk-oriented rules (files on disk, downloads, installers)
 *  Authors: MEOW & KHATOXD
 *
 *  VALIDATED 2026-10-21 against the two real samples:
 *    launcher  D7508C0022D959E4566D2CC1742CC0B7752B6FD1E692ECAB7CEF7AC6B9D8EEC3
 *    module    A649B9304DD74EB38178AD99D193FC2458D4F96FC95E8C4590EFF630561C701F
 *  FP TESTED 2026-10-21 against 694 clean System32 binaries -> 0 false positives
 *
 *  NOTE: launcher stores host/endpoint as UTF-16. Keep `ascii wide`.
 */

rule Prestige_Launcher_OnDisk
{
    meta:
        description = "Prestige Launcher x64 loader - downloads and manual-maps the payload"
        author      = "MEOW & KHATOXD"
        severity    = "medium"
        category    = "cheat.loader"
        sha256      = "D7508C0022D959E4566D2CC1742CC0B7752B6FD1E692ECAB7CEF7AC6B9D8EEC3"
        md5         = "A802560CC00C14F811F003991A717E8C"
        size        = 237848
        signed      = "Sectigo / Prestige Software Development (signature is not a trust signal)"
        version     = "1.2.3.0"
        date        = "2026-10-21"
        reference   = "PRESTIGE-CLIENT-2026"

    strings:
        // loader-specific error messages, exact text - very specific
        $e1  = "Download corrupted (bad MZ)."                        ascii
        $e2  = "Download corrupted (not a 64-bit DLL)."              ascii
        $e3  = "Download corrupted (truncated)."                     ascii
        $e4  = "Download corrupted (bad PE offset)."                 ascii
        $e5  = "Download corrupted (bad PE signature)."              ascii
        $e6  = "Missing dependency for the Prestige module:"         ascii
        $e7  = "Unresolved import in the Prestige module."           ascii
        $e8  = "The Prestige module refused to initialize."          ascii
        $e9  = "The Prestige module missing its entry point."        ascii
        $e10 = "The Prestige module reported an initialization failure." ascii
        $e11 = "Could not download Prestige."                        ascii
        $e12 = "Your antivirus is blocking requests to the Prestige API." ascii
        $e13 = "Your internet provider is blocking requests to the Prestige API." ascii

        // identity - UTF-16 in this build (version resource + strings)
        $id1 = "Prestige Launcher"              ascii wide
        $id2 = "PrestigeLauncher"               ascii wide
        $id3 = "Prestige Software Development"  ascii wide
        $id4 = "Prestige Launcher.exe"          ascii wide
        $id5 = "Prestige Launcher\" version=\"1.2.3.0" ascii

        // version resource (VS_VERSION_INFO) - survives file rename
        $vr1 = "Copyright (C) 2026 Prestige Software Development. All rights reserved." ascii wide
        $vr2 = "CompanyName"    ascii wide
        $vr3 = "OriginalFilename" ascii wide

        // embedded manifest assemblyIdentity
        $mf1 = "name=\"Prestige Launcher\" version=\"1.2.3.0\" processorArchitecture=\"amd64\"" ascii

        // Authenticode: real DER bytes, verified in the sample.
        // $ct_cn   = OID commonName (2.5.4.3) + UTF8String + "Prestige Software Development"
        // $ct_ser  = certificate serial number 64B9692518A71E22975BCB85520F1F20
        // NOTE: "CN=..." display form does NOT exist in the file - it is ASN.1 encoded.
        $ct_cn  = { 03 55 04 03 0C 1D 50 72 65 73 74 69 67 65 20 53 6F 66 74 77 61 72 65 20 44 65 76 65 6C 6F 70 6D 65 6E 74 }
        $ct_ser = { 64 B9 69 25 18 A7 1E 22 97 5B CB 85 52 0F 1F 20 }

        // network - wchar_t config => UTF-16 only in the real sample
        $n1 = "api.prestigeclient.vip"  ascii wide
        $n2 = "/launcherDownload"       ascii wide

        // optional: catches loader drops that are renamed
        $u1 = "module-manager-clean"    ascii
        $u2 = "module-shutdown"         ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 400KB and
        (
            // error strings alone are enough (13 present in the real sample)
            4 of ($e*) or
            // identity + a couple of errors
            (3 of ($e*) and 1 of ($id*)) or
            // renamed loader: identity + endpoint
            (2 of ($id*) and 1 of ($n*)) or
            // manifest + endpoint + any error
            ($id5 and 1 of ($n*) and 1 of ($e*)) or
            // renamed loader that also left cleanup strings
            (2 of ($u*) and 1 of ($id*)) or
            // version resource copyright line is unique to this vendor
            ($vr1 and 1 of ($id*)) or
            // embedded manifest identity (independent of strings table)
            $mf1 or
            // signed subject + product name
            (1 of ($ct*) and 1 of ($id*))
        )
}

rule Prestige_Client_Module_OnDisk
{
    meta:
        description = "Prestige client module - VMProtect'd manual-map injector for Minecraft"
        author      = "MEOW & KHATOXD"
        severity    = "high"
        category    = "cheat.injector"
        sha256      = "A649B9304DD74EB38178AD99D193FC2458D4F96FC95E8C4590EFF630561C701F"
        md5         = "BDC3B52BFC6D0BCFE75065357357EAA4"
        size        = 4932864
        packer      = "VMProtect (.vm_sec + .vlizer)"
        imagebase   = "0x180000000"
        date        = "2026-10-21"
        reference   = "PRESTIGE-CLIENT-2026"

    strings:
        // PDB / build paths - strongest anchor, survived rebuilds so far
        $pdb1 = "Prestige-Injection\\Dependencies\\cryptopp"       ascii
        $pdb2 = "C:\\Users\\Admin\\source\\repos\\Prestige-Injection" ascii

        // proprietary product strings
        $s1 = "PRESTIGE_CMM_DEBUG_STAY"           ascii
        $s2 = "Active - waiting for Prestige to unload." ascii
        $s3 = "Done - no Prestige memory left in the game." ascii
        $s4 = "Prestige could not map the secure payload into this target." ascii
        $s5 = "Prestige Injection is ready"        ascii
        $s6 = "Inject Prestige Client"             ascii
        $s7 = "no Prestige memory remains"         ascii
        $s8 = "The complete Prestige experience with manual mapping" ascii

        // VMProtect
        $vm1 = ".vm_sec"   ascii
        $vm2 = ".vlizer"   ascii

        // backend
        $n1 = "api.prestigeclient.vip"   ascii wide
        $n2 = "prestigeclient.vip"       ascii wide

        // self-destruct / unload residue
        $u1 = "wiping the last traces"        ascii
        $u2 = "no Prestige memory remains"    ascii
        $u3 = "waiting for Prestige to unload" ascii
        $u4 = "module-manager-clean"          ascii
        $u5 = "module-shutdown"               ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // a single PDB path is a smoking gun
            1 of ($pdb*) or
            // two product strings
            2 of ($s*) or
            // product string + VMProtect section
            (1 of ($s*) and 1 of ($vm*)) or
            // backend + product string
            (1 of ($n*) and 1 of ($s*)) or
            // cleanup residue
            (2 of ($u*) and 1 of ($s*))
        )
}

rule Prestige_VMProtect_Section_Heuristic
{
    meta:
        description = "Heuristic - PE carrying BOTH VMProtect sections plus any Prestige marker"
        author      = "MEOW & KHATOXD"
        severity    = "medium"
        category    = "packer.vmprotect"
        date        = "2026-10-21"
        note        = "standalone VMProtect is NOT malicious - this needs a Prestige marker too"

    strings:
        $vm1 = ".vm_sec"  ascii
        $vm2 = ".vlizer"  ascii
        $m1  = "PRESTIGE_CMM_DEBUG_STAY"                        ascii
        $m2  = "Prestige Injection is ready"                    ascii
        $m3  = "Inject Prestige Client"                         ascii
        $m4  = "could not map the secure payload"               ascii
        $m5  = "Prestige-Injection\\Dependencies\\cryptopp"     ascii
        $m6  = "wiping the last traces"                         ascii

    condition:
        uint16(0) == 0x5A4D and
        1 of ($vm*) and 1 of ($m*)
}
