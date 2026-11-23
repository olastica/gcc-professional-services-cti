/*
   Payload ransomware - Windows PE variant
   Author: Olasunkanmi Ogidan
   Date: 2026-11-22
   Status: experimental - compiled and logic-tested on synthetic data only; NOT tested against the real sample
   Reference sample (SHA-256): 1ca67af90400ee6cbbd42175293274a0f5dc05315096cb2e214e4bfe12ffb71f
   Sources: Nopal Cyber advisory (28 May 2026), Derp.ca research, VirusTotal behaviour report
   Note: Linux/ESXi variant is covered by the public rule Babuk_Payload_Ransomware_ESXi (github.com/kirkderp/yara)
   MITRE ATT&CK: T1486, T1490, T1480
*/

rule Payload_Ransomware_Windows
{
    meta:
        description = "Detects Payload ransomware (Babuk-derived) Windows PE by mutex, log, note and recovery strings"
        author = "Olasunkanmi Ogidan"
        date = "2026-11-22"
        reference = "https://www.nopalcyber.com/threat-hunting-advisory/may-28th,-2026"
        hash = "1ca67af90400ee6cbbd42175293274a0f5dc05315096cb2e214e4bfe12ffb71f"
        tlp = "CLEAR"

    strings:
        $mutex  = "MakeAmericaGreatAgain" ascii wide
        $log    = "payload.log" ascii wide nocase
        $note1  = "RECOVER_payload.txt" ascii wide nocase
        $note2  = "RECOVERY-xx0001.txt" ascii wide nocase
        $label  = "g:payload" ascii wide
        $ini    = "recovery.ini" ascii wide nocase
        $arg    = "--background" ascii wide
        $vss    = "delete shadows /all /quiet" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($mutex and 2 of ($log, $note1, $note2, $label, $ini, $arg, $vss)) or
            5 of them
        )
}
