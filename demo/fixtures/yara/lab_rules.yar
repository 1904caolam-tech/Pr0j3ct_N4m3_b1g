rule Log4j_Exploit_Attempt : exploit cve
{
    meta:
        author = "P4B lab"
        description = "Log4j JNDI exploit string observed in a request"
        severity = "high"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        attack_technique = "T1190"
    strings:
        $jndi_ldap = "${jndi:ldap://" nocase
        $jndi_dns  = "${jndi:dns://" nocase
    condition:
        any of them
}

rule CobaltStrike_Beacon : malware c2
{
    meta:
        author = "P4B lab"
        description = "Cobalt Strike beacon marker present in file"
        severity = "critical"
        attack_technique = "T1071.001"
    strings:
        $a = "beacon.dll" nocase
        $b = "sleeve.dll" nocase
    condition:
        any of them
}
