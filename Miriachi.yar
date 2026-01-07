rule Mariachi_Malware_Detection
{
    meta:
        author = "Ibrahim Ayyad"
        description = "Detects mariachi.exe malware sample"
        date = "2026-01-06"

    strings:
        $s1 = "Mutex_2" ascii
        $s2 = ".fake-c2-evil.edu" ascii
        $s3 = "nc -nvlp 8" ascii
        $s4 = "IsUserAnAdm" ascii
        $s5 = "decoy" ascii nocase
        $s6 = "readLog" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($s*) and
        filesize < 50MB
}
