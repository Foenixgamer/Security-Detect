rule SQS_Suspicious_Strings {
    meta:
        description = "Ejemplo de regla YARA para SQS (Capa 2)."
        author = "SQS"
    strings:
        $remote = "DownloadFile" ascii wide nocase
        $psexec = "PsExec" ascii wide nocase
        $mimikatz = "Mimikatz" ascii wide nocase
    condition:
        any of them
}