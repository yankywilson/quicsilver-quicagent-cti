/*
  Operation QUICSILVER / QUICAgent - YARA pack
  ANCHOR - Colonel Yanky Wilson - TLP:CLEAR - 2026-10-15
  Every string below was checked against the four QUICAgent builds, the ACMECS VHD and its parts
  (tests/yara_results.txt). Tags: NOVEL / CORROBORATED / PUBLISHED - see docs/09.
  The RC4 keys are never stored as one string: the code builds them on the stack with movabs immediates,
  so a plain-text rule on Seqrite's key misses - use QUICSILVER_QUICAgent_RC4_Key_Builder instead.
  "/poll" is NOT a QUICAgent endpoint: it only occurs inside Go's internal/poll package path.
*/

rule QUICSILVER_QUICAgent_RAT_CA_Pin
{
    meta:
        description = "QUICAgent `agent` lineage - embedded RAT CA certificate (O=RAT System, CN=RAT CA) used to pin the C2 TLS certificate"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "CORROBORATED (CA name published by Seqrite); December-build pin NOVEL"
        fidelity = "very high"
        hash1 = "2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63"
        hash2 = "cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059"
        hash3 = "c15aead19e0d6e8ed51de79a858d7ef6b5ede226c7db79e7008a23b3445c164d"
    strings:
        $pem_l1 = "MIIB6DCCAW+gAwIBAgIBATAKBggqhkjOPQQDAzAzMQswCQYDVQQGEwJVUzETMBEG" ascii
        $pem_l3 = "RQhDBeC71D58LobicSzXeOVjLCooAhtFeqqsIQkSwuOnhL1H" ascii
    condition:
        // no PE check on purpose: also fires on header.doc (first half of the split payload) and on memory
        all of them
}

rule QUICSILVER_QUICAgent_RAT_TeamServer_Pin
{
    meta:
        description = "QUICAgent `rat/agent` lineage (April 2026, HolidayNotice.pdf.exe) - embedded RAT-TeamServer certificate and Go module path"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "very high"
        hash1 = "c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02"
    strings:
        $pem_l1 = "MIIDJzCCAg+gAwIBAgIQPRQb+wFr869BnUEn4cay5jANBgkqhkiG9w0BAQsFADAZ" ascii
        $pem_l2 = "MRcwFQYDVQQDDA5SQVQtVGVhbVNlcnZlcjAeFw0yNTEyMDUwNTU3NTRaFw0yNjEy" ascii
        $mod    = "mod\trat/agent\t(devel)" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($pem*) or ($mod and 1 of ($pem*)))
}

rule QUICSILVER_QUICAgent_C2_Protocol
{
    meta:
        description = "QUICAgent (both lineages) - quic-go HTTP/3 client with the agent's C2 paths and idempotency header"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "high"
        note = "Survives a re-key of the pinned certificate and a new C2 host. Requires quic-go: for a non-QUIC rebuild, hunt with a copy that drops $quic"
        hash1 = "2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63"
        hash2 = "c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02"
        hash3 = "cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059"
    strings:
        $quic  = "github.com/quic-go/quic-go" ascii
        $idem  = "X-Idempotency-Key" ascii
        $hb    = "/heartbeat" ascii
        $res   = "/result" ascii
        // agent lineage (Dec 2025, Jun/Aug 2026)
        $a1    = "%s/upload?%s" ascii
        $a2    = "%s/upload/next?%s" ascii
        $a3    = "/download?task_id=" ascii
        $h1    = "X-Agent-Hostname" ascii
        $h2    = "X-Agent-ID" ascii
        // rat/agent lineage (Apr 2026)
        $r1    = "/upload/chunk/pull" ascii
        $r2    = "/register" ascii
        $t1    = "file_list_result" ascii
        $t2    = "file_download_result" ascii
        $t3    = "shell_result" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and $quic and $idem and $hb and $res
        and ((2 of ($a*) and all of ($h*)) or (all of ($r*) and 2 of ($t*)))
}

rule QUICSILVER_QUICAgent_RC4_Key_Builder
{
    meta:
        description = "QUICAgent - RC4 key assembled on the stack with movabs immediates (agent: 'MySecretEncryptionKey2025!@#$%', 30 B; rat/agent: '2024axcegbaxcegb', 16 B)"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "agent key CORROBORATED (published by Seqrite); rat/agent key and the stack-build pattern NOVEL"
        fidelity = "very high"
        note = "No PE check on purpose: also fires on the current header.doc (4a1a1b14...) and on process memory, not on the deleted 652 KB fragment. Survives a new C2, certificate or build ID; a new key breaks it"
        hash1 = "2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63"
        hash2 = "cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059"
        hash3 = "c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02"
    strings:
        // mov rdx, 'MySecret' ; mov [rsp+xx], rdx ; mov rdx, 'Encrypti'
        $agent = { 48 BA 4D 79 53 65 63 72 65 74 48 89 54 24 ?? 48 BA 45 6E 63 72 79 70 74 69 }
        // mov rdx, '2024axce' ; mov [rsp+xx], rdx ; mov rdx, 'gbaxcegb'
        $april = { 48 BA 32 30 32 34 61 78 63 65 48 89 54 24 ?? 48 BA 67 62 61 78 63 65 67 62 }
    condition:
        filesize < 50MB and any of them
}

rule QUICSILVER_QUICAgent_Worker_Resolver
{
    meta:
        description = "QUICAgent June/August builds - Cloudflare Workers dead-drop resolver URLs and Startup-folder persistence"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "CORROBORATED (URLs and SystemIn.lnk published by Seqrite; corrected /vere0zme82cad path NOVEL)"
        fidelity = "very high"
        hash1 = "cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059"
        hash2 = "c15aead19e0d6e8ed51de79a858d7ef6b5ede226c7db79e7008a23b3445c164d"
    strings:
        $w1  = "https://appupdate.0cmds20cj2cdf8.workers.dev/A3cmf0q9ASCion" ascii
        $w2  = "https://regupdate.eamakfu49dc28wa.workers.dev/vere0zme82cad" ascii
        $p1  = "SystemIn.lnk" ascii
        $p2  = "create_lnk_*.ps1" ascii
        $p3  = "$shell = New-Object -ComObject Shell.Application; $shell.ShellExecute('%s')" ascii
    condition:
        1 of ($w*) or all of ($p*)
}

rule QUICSILVER_QUICAgent_December_Installer
{
    meta:
        description = "QUICAgent December 2025 build - EDR-aware self-install to C:\\Users\\Public\\Downloads\\SystemPublicCache"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "very high"
        hash1 = "2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63"
    strings:
        $dir  = "SystemPublicCache" ascii
        $pub  = "C:\\Users\\Public\\Downloads" ascii
        $edr1 = "sentinelagent.exe" ascii
        $edr2 = "bdagent.exe" ascii
        $tl   = "tasklist" ascii
        $del  = "ping 127.0.0.1 -n 3 >nul & del /f /q" ascii
    condition:
        uint16(0) == 0x5A4D and $dir and $pub and 3 of ($edr1, $edr2, $tl, $del)
}

rule QUICSILVER_QUICAgent_April_Installer
{
    meta:
        description = "QUICAgent April 2026 build - checks SentinelOne / Trend Micro / Bitdefender processes, records its original path, deletes Downloads\\*.hta, embeds sample.pdf"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "high"
        hash1 = "c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02"
    strings:
        $e1 = "SentinelAgent.exe" ascii
        $e2 = "ptsessionagent.exe" ascii
        $e3 = "bdagent.exe" ascii
        $op = "original_path.txt" ascii
        $ws = "WScript.Shell" ascii
        $ps = "github.com/mitchellh/go-ps" ascii
        $hta = "*.hta" ascii
        $emb = "sample.pdf" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($e*) and $op and ($ws or $ps or ($hta and $emb))
}

rule QUICSILVER_QUICAgent_Builder_Paths
{
    meta:
        description = "QUICAgent builds compiled without -trimpath on the developer's machine (Windows user `qwe`, project folders `C:\\go agent` and `C:\\go agent 2`)"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "very high"
        hash1 = "2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63"
        hash2 = "c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02"
    strings:
        $mod  = "C:/Users/qwe/go/pkg/mod/" ascii
        $src1 = "C:/go agent/agent/main.go" ascii
        $src2 = "C:/go agent 2/agent/main.go" ascii
    condition:
        uint16(0) == 0x5A4D and $mod and 1 of ($src*)
}

rule QUICSILVER_LNK_FTP_Script_Loader
{
    meta:
        description = "QUICSILVER / GriefLure-style LNK that runs ftp.exe -s:<script> from a nest of `_` folders; flags the known builder host"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "CORROBORATED (technique published by Seqrite); LNK hash NOVEL"
        fidelity = "high"
        hash1 = "836fa2c799b0b7c2ab683055d880674a2cfe95dc6e47b0650f9f8e0dcb43f858"
    strings:
        $ftp   = "System32\\ftp.exe" ascii nocase
        $arg_w = "_/_/j/" wide
        $arg_s = "-s\"\":" wide
        $host  = "desktop-stv6gg" ascii
    condition:
        uint32(0) == 0x0000004C and filesize < 64KB and $ftp and ($arg_w or $arg_s or $host)
}

rule QUICSILVER_FTP_Script_Split_Payload
{
    meta:
        description = "ftp.exe command script that opens a decoy and rebuilds an EXE from two .doc halves with copy /b"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "CORROBORATED"
        fidelity = "very high"
        hash1 = "5328c3c3e8cf6bc498c3557cd57a0f98177da8f70dfe3accf9c0f73490f70fd1"
    strings:
        $bang  = "!start" ascii
        $copy  = "copy /Y /b" ascii nocase
        $plus  = /\.doc\s*\+\s*[^\r\n]{0,200}\.doc\s+"?[^\r\n]{0,200}\.exe/ ascii nocase
        $quit  = "quit" ascii
    condition:
        filesize < 4KB and $bang and $copy and $plus and $quit
}

rule QUICSILVER_VHD_Lure_Container
{
    meta:
        description = "QUICSILVER VHD lure - FAT volume holding header.doc / body.doc under a `_rels` folder and an ftp.exe LNK"
        author = "ANCHOR / Colonel Yanky Wilson"
        date = "2026-10-15"
        tlp = "CLEAR"
        tag = "NOVEL"
        fidelity = "high"
        hash1 = "0803521a7e9081f46f8f9f61d72371ecc1f49657f10202fffa9a33f581d8bb39"
    strings:
        $footer = "conectix" ascii
        $sfn_h  = "HEADER  DOC" ascii
        $sfn_b  = "BODY    DOC" ascii
        $sfn_r  = "_RELS      " ascii
        $ftp    = "System32\\ftp.exe" ascii nocase
    condition:
        filesize < 100MB and $footer at (filesize - 512) and $sfn_h and $sfn_b and ($sfn_r or $ftp)
}
