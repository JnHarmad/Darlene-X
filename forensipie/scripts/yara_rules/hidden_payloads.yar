rule Hidden_Executables_In_APK
{
    meta:
        description = "Detects hidden or embedded executables in APK files"
        author = "Harmad"
        reference = "Static Analysis Rule - ForensiPie"
        date = "2025-04-16"
        category = "static"

    strings:
        // Signatures for embedded Windows executables
        $mz = { 4D 5A }  // 'MZ' header for PE (Windows executable)

        // Signatures for ELF binaries (Linux/Android native)
        $elf = { 7F 45 4C 46 } // ELF header

        // Dalvik Executable
        $dex = { 64 65 78 0A 30 33 35 00 } // "dex\n035"

        // Suspicious file names
        $filename1 = ".exe"
        $filename2 = ".elf"
        $filename3 = ".dex"
        $filename4 = "payload"
        $filename5 = "dropper"

    condition:
        any of ($mz, $elf, $dex) or
        2 of ($filename*)
}
