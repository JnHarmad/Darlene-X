rule Android_Obfuscation_Base64Strings
{
    meta:
        description = "Detects long suspicious Base64-encoded strings"
        author = "Harmad"
        severity = "medium"
        category = "Obfuscation"

    strings:
        $base64 = /[A-Za-z0-9+\/]{40,}={0,2}/ wide ascii

    condition:
        $base64
}


rule Android_Obfuscation_ShortIdentifiers
{
    meta:
        description = "Detects suspicious short or meaningless class/method names"
        author = "CyberPie"
        severity = "low"
        category = "Obfuscation"

    strings:
        $short_class = /L[a-z]{1,2}\// wide ascii
        $method_a = "->a(" ascii
        $method_b = "->b(" ascii
        $method_c = "->c(" ascii

    condition:
        any of ($*)
}




