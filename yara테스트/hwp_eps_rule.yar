rule HWP_Malware_EPS
{
    meta:
        description = "Detects malicious EPS patterns in HWP files"

    strings:
        $eps1 = /<[0-9A-Fa-f]{500,}/
        $eps2 = "4 mod get xor put" nocase
        $eps3 = "exec" nocase
        $eps4 = "/concatstrings" nocase
        $eps5 = "dup dup 4 2 roll copy length" nocase
        $eps6 = "get xor" nocase
        $eps7 = "string dup" nocase
        $eps8 = "putinterval" nocase
        $eps9 = "repeat" nocase
        $eps10 = "aload" nocase
        $eps11 = "eaprocc" nocase
        $eps12 = "1{1} put" nocase
        $eps13 = "get closefile" nocase

    condition:
        any of ($eps1, $eps2, $eps3, $eps4, $eps5, $eps6,
                $eps7, $eps8, $eps9, $eps10, $eps11, $eps12, $eps13)
}
