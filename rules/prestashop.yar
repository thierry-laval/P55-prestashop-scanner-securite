/*
   Règles YARA — Scanner de sécurité PrestaShop
   ============================================
   Règles de détection de webshells, backdoors PHP, skimmers et code obfusqué
   couramment rencontrés sur des installations PrestaShop compromises.

   Ces règles sont un COMPLÉMENT aux motifs regex internes du scanner. YARA
   apporte des conditions composées (combinaisons de chaînes, compteurs,
   contraintes de taille) impossibles à exprimer proprement en regex simple.

   Usage :
     yara rules/prestashop.yar /chemin/vers/prestashop/
     php scanner.php --yara=rules/prestashop.yar

   IMPORTANT : ces règles privilégient la détection des comportements
   réellement malveillants (exécution de code, exfiltration, obfuscation
   lourde) plutôt que des chaînes isolées, afin de limiter les faux positifs.
   Adaptez-les à votre contexte : testez toujours sur un échantillon avant
   de vous fier aux résultats en production.
*/

/* ---------------------------------------------------------------------------
   WEBSHELLS GÉNÉRIQUES — exécution de code depuis une entrée utilisateur
   --------------------------------------------------------------------------- */

rule PHP_Webshell_Exec_User_Input
{
    meta:
        description = "Exécution de code PHP à partir d'une entrée utilisateur (webshell générique)"
        author      = "PrestaShop Security Scanner"
        severity    = "critical"
    strings:
        $e1 = "eval(" nocase
        $e2 = "assert(" nocase
        $e3 = "system(" nocase
        $e4 = "passthru(" nocase
        $e5 = "shell_exec(" nocase
        $e6 = "popen(" nocase
        $g  = "$_GET" nocase
        $p  = "$_POST" nocase
        $r  = "$_REQUEST" nocase
        $c  = "$_COOKIE" nocase
    condition:
        filesize < 1MB and
        any of ($e*) and
        any of ($g, $p, $r, $c)
}

rule PHP_Webshell_Obfuscated_Eval
{
    meta:
        description = "Eval d'une chaîne décodée (base64/gzinflate) — obfuscation typique"
        severity    = "critical"
    strings:
        $dec1 = "base64_decode" nocase
        $dec2 = "gzinflate" nocase
        $dec3 = "gzuncompress" nocase
        $dec4 = "str_rot13" nocase
        $dec5 = "urldecode" nocase
        $exec = "eval(" nocase
    condition:
        filesize < 512KB and
        $exec and
        2 of ($dec*)
}

rule PHP_Halt_Compiler_Payload
{
    meta:
        description = "Payload caché après __halt_compiler() — technique d'évasion"
        severity    = "critical"
    strings:
        $halt = "__halt_compiler" nocase
        $pay1 = "eval(" nocase
        $pay2 = "base64_decode" nocase
        $pay3 = "<?php" nocase
    condition:
        $halt and any of ($pay*)
}

/* ---------------------------------------------------------------------------
   WEBSHELLS CONNUS — familles répandues (signatures de code)
   --------------------------------------------------------------------------- */

rule Webshell_WSO_Family
{
    meta:
        description = "Webshell de la famille WSO (FilesMan / WSO Shell)"
        severity    = "critical"
    strings:
        $s1 = "WSO" nocase
        $s2 = "FilesMan" nocase
        $s3 = "wso_version" nocase
        $s4 = "phpshell" nocase
        $s5 = "b374k" nocase
    condition:
        filesize < 2MB and 2 of ($s*)
}

rule Webshell_Generic_Panel_Keywords
{
    meta:
        description = "Panneau de contrôle webshell (upload, commande, gestion fichiers)"
        severity    = "critical"
    strings:
        $k1 = "Shell" nocase
        $k2 = "Upload" nocase
        $k3 = "Execute" nocase
        $k4 = "Command" nocase
        $f1 = "move_uploaded_file" nocase
        $f2 = "shell_exec" nocase
        $f3 = "proc_open" nocase
        $f4 = "pcntl_exec" nocase
    condition:
        filesize < 300KB and
        3 of ($k*) and
        2 of ($f*)
}

/* ---------------------------------------------------------------------------
   SKIMMERS DE CARTE BANCAIRE — exfiltration côté client
   --------------------------------------------------------------------------- */

rule JS_Card_Skimmer_Exfil
{
    meta:
        description = "Skimmer de carte : capture de champs de paiement + envoi réseau"
        severity    = "critical"
    strings:
        $cc1 = "cardnumber" nocase
        $cc2 = "card_number" nocase
        $cc3 = "cc_num" nocase
        $cc4 = "cvv" nocase
        $cc5 = "cvc" nocase
        $ex1 = "XMLHttpRequest" nocase
        $ex2 = "sendBeacon" nocase
        $ex3 = "fetch(" nocase
        $ex4 = "new Image()" nocase
    condition:
        filesize < 2MB and
        1 of ($cc*) and
        1 of ($ex*)
}

rule JS_Atob_Obfuscated_Blob
{
    meta:
        description = "Chaîne base64 volumineuse décodée par atob() — payload obfusqué"
        severity    = "warning"
    strings:
        $atob = "atob(" nocase
        $b64  = /[A-Za-z0-9+\/]{80,}={0,2}/
    condition:
        filesize < 2MB and $atob and $b64
}

/* ---------------------------------------------------------------------------
   BACKDOORS PHP — accès distant dissimulé
   --------------------------------------------------------------------------- */

rule PHP_Remote_Code_Fetch
{
    meta:
        description = "Récupération et exécution de code distant (file_get_contents/curl + eval)"
        severity    = "critical"
    strings:
        $fetch1 = "file_get_contents(" nocase
        $fetch2 = "curl_exec(" nocase
        $fetch3 = "fopen(" nocase
        $url    = "http" nocase
        $exec   = "eval(" nocase
    condition:
        filesize < 512KB and
        any of ($fetch*) and
        $url and
        $exec
}

rule PHP_Reverse_Shell_Pattern
{
    meta:
        description = "Motif de shell inversé (connexion socket sortante + exécution)"
        severity    = "critical"
    strings:
        $sock1 = "fsockopen(" nocase
        $sock2 = "stream_socket_client(" nocase
        $sock3 = "socket_connect(" nocase
        $exec1 = "exec(" nocase
        $exec2 = "shell_exec(" nocase
        $exec3 = "/bin/sh" nocase
        $exec4 = "/bin/bash" nocase
    condition:
        filesize < 256KB and
        any of ($sock*) and
        any of ($exec*)
}

/* ---------------------------------------------------------------------------
   MINERAIRE / CRYPTOJACKING
   --------------------------------------------------------------------------- */

rule Cryptominer_References
{
    meta:
        description = "Références à un mineur de cryptomonnaie"
        severity    = "critical"
    strings:
        $m1 = "coinhive" nocase
        $m2 = "cryptonight" nocase
        $m3 = "monero" nocase
        $m4 = "stratum+tcp" nocase
        $m5 = "xmrig" nocase
        $m6 = "miner.start" nocase
    condition:
        any of them
}

/* ---------------------------------------------------------------------------
   PERSISTANCE & REDIRECTIONS MALVEILLANTES
   --------------------------------------------------------------------------- */

rule PHP_Mailer_Spam_Backdoor
{
    meta:
        description = "Backdoor d'envoi de mail en masse (spam / phishing)"
        severity    = "warning"
    strings:
        $mail1 = "mail(" nocase
        $mail2 = "mb_send_mail(" nocase
        $bcc   = "Bcc:" nocase
        $loop  = "foreach" nocase
        $input = "$_POST" nocase
    condition:
        filesize < 512KB and
        any of ($mail*) and
        $loop and $input and
        ($bcc or 1 of ($mail*))
}

rule Htaccess_Malicious_Handler
{
    meta:
        description = ".htaccess forçant l'exécution PHP ou une redirection malveillante"
        severity    = "critical"
    strings:
        $h1 = "AddHandler" nocase
        $h2 = "SetHandler" nocase
        $h3 = "AddType" nocase
        $h4 = "auto_prepend_file" nocase
        $h5 = "ErrorDocument" nocase
        $php = "x-httpd-php" nocase
    condition:
        filesize < 64KB and
        any of ($h*) and
        ($php or $h4 or $h5)
}