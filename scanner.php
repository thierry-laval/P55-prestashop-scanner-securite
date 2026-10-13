<?php
/**
 * Scanner de Sécurité pour PrestaShop - Version 2.0.1
 * 
 * DESCRIPTION GÉNÉRALE :
 * Ce script effectue un audit complet de sécurité sur une installation PrestaShop.
 * Il détecte les fichiers malveillants, les failles de configuration, les permissions
 * dangereuses et les en-têtes HTTP manquants ou mal configurés.
 * 
 * FONCTIONNALITÉS PRINCIPALES :
 * - Scan récursif des répertoires critiques (classes, modules, themes, etc.)
 * - Pattern matching pour détecter les comportements malveillants connus (150+ patterns)
 * - Vérification des permissions de fichiers sensibles
 * - Audit des en-têtes HTTP de sécurité
 * - Audit de la configuration PHP (directives recommandées + extensions requises)
 * - Détection des versions vulnérables de PrestaShop
 * - Hachage MD5 des fichiers suspects pour traçabilité
 * - Export en CSV et JSON
 * - Interface web responsive avec résumé statistique
 *
 * @author Thierry Laval <https://thierrylaval.dev/>
 * @copyright 2007-2026 Thierry Laval
 * @license http://opensource.org/licenses/afl-3.0.php Academic Free License (AFL 3.0)
 * @version 2.0.1
 * @package PrestaShop_Scanner
 */

// ============================================================================
// CONFIGURATION INITIALE - Réglages généraux du script
// ============================================================================

ini_set('display_errors', 1);          // Affiche les erreurs PHP
set_time_limit(600);                   // Limite de temps : 10 minutes pour le scan
error_reporting(E_ALL);                // Signale toutes les erreurs
@date_default_timezone_set('Europe/Paris'); // Définit le fuseau horaire

// Active l'optimisation JIT (Just-In-Time) des regex PCRE pour améliorer les performances
if (defined('PCRE_JIT_SUPPORT')) {
    ini_set('pcre.jit', 1);
}

// --- Aide CLI (traitée immédiatement, AVANT tout scan) ---
// Sans ce bloc précoce, `php scanner.php --help` lancerait le scan complet
// (long) avant d'afficher l'aide. On court-circuite ici.
if (PHP_SAPI === 'cli' && isset($argv[1]) && in_array('--help', $argv, true)) {
    fwrite(STDOUT, <<<TXT
Scanner de sécurité PrestaShop — mode ligne de commande

Usage : php scanner.php [options]

Options :
  --path=<dossier>   Racine PrestaShop à analyser (défaut : auto-détection)
  --yara=<fichier>   Fichier de règles YARA (défaut : rules/prestashop.yar)
  --json             Sortie au format JSON
  --csv              Sortie au format CSV
  --quiet            N'affiche que le résumé (pas le détail des fichiers)
  --no-color         Désactive les couleurs ANSI
  --help             Affiche cette aide

Exemples :
  php scanner.php
  php scanner.php --path=/var/www/prestashop --quiet
  php scanner.php --json > rapport.json
  php scanner.php --csv  > rapport.csv
  php scanner.php --yara=/chemin/mes-regles.yar

TXT);
    exit(0);
}

// Taille maximale d'un fichier à scanner.
// Une valeur >0 (en octets) évite de charger en mémoire des fichiers
// énormes (archives, dumps, bundles JS) qui épuisent la mémoire PHP et
// font planter tout le scan. Mettre 0 pour désactiver toute limite.
// Recommandé : 5 Mo, largement suffisant pour du code PrestaShop.
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5 Mo par fichier


// ============================================================================
// DÉTECTION AUTOMATIQUE DE LA RACINE PRESTASHOP
// ============================================================================

$root_path = __DIR__;
$found = false;

// Mode CLI : l'option --path=<dossier> force la racine à analyser.
// On la traite ICI (avant la détection automatique) car le scan se base sur
// $root_path dès les lignes suivantes. En mode web, $argv n'existe pas.
if (PHP_SAPI === 'cli' && !empty($argv)) {
    foreach (array_slice($argv, 1) as $arg) {
        if (preg_match('/^--path=(.+)$/', $arg, $m)) {
            $cli_root = rtrim($m[1], '/');
            if (is_dir($cli_root)) {
                $root_path = $cli_root;
                $found = true;
            } else {
                fwrite(STDERR, "Erreur : le dossier --path indiqué est introuvable : {$cli_root}\n");
                exit(3);
            }
        }
    }
}

// Marqueurs fiables permettant d'identifier la racine d'une installation PrestaShop
$markers = [
    '/config/config.inc.php',           // PrestaShop 1.6, 1.7
    '/config/settings.inc.php',         // PrestaShop 1.6, 1.7
    '/config/defines.inc.php',          // PrestaShop 1.7+
    '/src/Core/Version.php',            // PrestaShop 8.x
    '/app/AppKernel.php',               // PrestaShop 1.7+
    '/composer.json'                    // Tous les projets modernes
];

// Recherche récursive vers le haut jusqu'à 5 niveaux pour trouver la racine.
// On saute cette étape si --path a déjà fixé la racine en mode CLI ($found = true),
// sinon la boucle écraserait le chemin fourni par l'utilisateur.
if (!$found) {
    for ($i = 0; $i < 5; $i++) {
        foreach ($markers as $marker) {
            if (file_exists($root_path . $marker)) {
                $found = true;
                break 2;
            }
        }
        $parent = dirname($root_path);
        if ($parent === $root_path) break; // Arrête si on atteint la racine système
        $root_path = $parent;
    }
}

// Fallback : utilise le répertoire courant si la racine n'est pas trouvée.
// ATTENTION : dans ce cas, on risque de scanner un dossier qui n'est PAS une
// installation PrestaShop (le dossier du script lui-même). On le signale
// clairement dans le rapport pour éviter un faux sentiment de sécurité.
$prestashop_root_detected = $found;
if (!$found) {
    $root_path = __DIR__;
}
$root_path = rtrim($root_path, '/');

// ============================================================================
// DÉTECTION DE LA VERSION PRESTASHOP ET INFOS SYSTÈME
// ============================================================================

$prestashop_version = detect_prestashop_version($root_path);
$php_version  = phpversion();
$memory_limit = ini_get('memory_limit');
$version      = '2.0.1';

// ============================================================================
// CONFIGURATION DU SCAN EXTERNE (Sucuri SiteCheck)
// ============================================================================

// Récupère le nom d'hôte du serveur
$host = isset($_SERVER['HTTP_HOST']) ? strtolower(trim($_SERVER['HTTP_HOST'])) : '';
$host = preg_replace('/:\d+$/', '', $host);     // Supprime le port
$host = preg_replace('/[^a-z0-9.\-]/', '', $host); // Garde seulement les caractères valides

// Préférence pour www.domaine.com plutôt que domaine.com pour Sucuri
$hostForSucuri = $host;
if ($host !== '' && stripos($host, 'www.') !== 0) {
    $parts = array_values(array_filter(explode('.', $host), 'strlen'));
    if (count($parts) <= 2) {
        $hostForSucuri = 'www.' . $host;
    }
}

// Détecte le protocole utilisé (HTTP ou HTTPS)
// Prend en compte les proxies inverses (X-Forwarded-Proto)
$scheme = 'https'; // Par défaut, préfère HTTPS pour la sécurité
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    $tmp = explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO']);
    $candidate = strtolower(trim($tmp[0]));
    if ($candidate === 'http' || $candidate === 'https') {
        $scheme = $candidate;
    }
} elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    $scheme = 'https';
} else {
    $scheme = 'http';
}

// Construit l'URL Sucuri SiteCheck pour le scan externe.
// FORMAT CORRECT : https://sitecheck.sucuri.net/results/<domaine>
// (sans schéma http/https dans le chemin, sinon Sucuri répond "Host not found").
// On utilise le host réel tel quel : le préfixe www. est un simple repli, car
// l'ajouter à tort (ou forcer https) casse la résolution du domaine.
$sucuriUrl = ($hostForSucuri !== '')
    ? ('https://sitecheck.sucuri.net/results/' . $hostForSucuri)
    : '';

// Second scan externe : urlscan.io (100% gratuit, sans compte ni clé API).
// urlscan.io analyse la page en direct dans un vrai navigateur et détecte
// requêtes sortantes suspectes, domaines malveillants, scripts injectés, etc.
// On utilise la page publique de recherche par domaine, pré-remplie avec l'hôte.
$urlscanUrl = ($host !== '')
    ? ('https://urlscan.io/domain/' . rawurlencode($host))
    : '';

// Audit externe des en-têtes HTTP : securityheaders.com (100% gratuit, sans compte).
// Compare les en-têtes de sécurité réellement renvoyés par le site avec les
// bonnes pratiques, et attribue une note (A+ à F). On pré-remplit la requête
// avec l'URL complète du site (schéma + hôte).
$securityHeadersUrl = ($host !== '')
    ? ('https://securityheaders.com/?q=' . rawurlencode($scheme . '://' . $host) . '&followRedirects=on')
    : '';

// ============================================================================
// CONFIGURATION DES RÉPERTOIRES À SCANNER
// ============================================================================
// Liste des répertoires critiques contenant du code qui sera analysé
// Inclut les modules populaires comme Appagebuilder et Leo* qui sont souvent ciblés

$directories = [
    // Répertoires principaux PrestaShop
    $root_path . '/classes/',           // Classes métier PrestaShop
    $root_path . '/composer/',          // Dépendances Composer
    $root_path . '/controllers/',       // Contrôleurs PrestaShop
    $root_path . '/override/',          // Overrides (souvent compromis)
    $root_path . '/config/',            // Configuration
    
    // Modules populaires (cibles fréquentes d'attaques)
    $root_path . '/modules/appagebuilder/',
    $root_path . '/modules/leoproductsearch/',
    $root_path . '/modules/leofeature/',
    $root_path . '/modules/leoblog/',
    
    // Répertoires standards
    $root_path . '/kerawen/',
    $root_path . '/themes/',             // Thèmes
    $root_path . '/app/',                // Application (PS 1.7+)
    $root_path . '/src/',                // Source (PS 8.x)
    $root_path . '/img/',                // Images (zone interdite pour PHP)

    $root_path . '/js/',                // JavaScript
    $root_path . '/vendor/smarty/smarty/libs/',  // Moteur de templating
    $root_path . '/pdf/',
    $root_path . '/mails/',             // Modèles d'e-mail
    $root_path . '/vendor/doctrine/cache/',      // Cache (dépendance ORM)
    $root_path . '/bin/',               // Scripts exécutables
    $root_path . '/upload/',            // Zone de téléchargement d'utilisateur
    $root_path . '/tools/',             // Scripts d'admin
    $root_path . '/download/',          // Fichiers à télécharger
];

// ============================================================================
// DÉTECTION AUTOMATIQUE DU DOSSIER D'ADMINISTRATION RENOMMÉ
// ============================================================================
// PrestaShop permet de renommer le dossier 'admin' pour des raisons de sécurité
// Ce code scanne les répertoires non-standards pour les découvrir

$root_dirs = scandir($root_path);
$excluded_dirs = [
    '.', '..', 'app', 'bin', 'cache', 'classes', 'config', 'controllers', 'docs',
    'download', 'img', 'install', 'js', 'localization', 'log', 'mails', 'modules',
    'override', 'pdf', 'src', 'themes', 'tools', 'translations', 'upload', 'var',
    'vendor', 'webservice', 'node_modules', '.git', '.github'
];
foreach ($root_dirs as $dir) {
    if (is_dir($root_path . '/' . $dir) && !in_array($dir, $excluded_dirs)) {
        $directories[] = $root_path . '/' . $dir . '/';
    }
}

// ============================================================================
// LISTE BLANCHE (Faux Positifs Connus)
// ============================================================================
// Fichiers à ignorer car ils déclenchent des faux positifs.
// On accepte à la fois des chemins complets et des fragments de chemins :
// - '/vendor/' pour ignorer toute la librairie vendor
// - '/js/tiny_mce/' si TinyMCE est toujours propre
// - '/tests.prestashop.' pour ignorer des dossiers de tests temporaires
// Ajoutez ici les fichiers ou dossiers qui sont légitimes dans votre
// environnement et que vous ne souhaitez pas voir remontés comme "infectés".

$whitelist = [
    // Exemple de fichier légitime contenant la chaîne card_number
    $root_path . '/src/Adapter/Order/QueryHandler/GetOrderForViewingHandler.php',
    // Cas fréquemment signalés par l'utilisateur
    '/vendor/',
    '/js/tiny_mce/',
    '/tests.prestashop.',

    // --- Bundles d'administration légitimes (PrestaShop 8/9, Symfony, API Platform) ---
    // Ces fichiers sont du code vendor minifié livré par l'admin. Ils contiennent
    // naturellement des fetch()/URL externes et génèrent des faux positifs critiques
    // (ex. bundles/apiplatform/graphql-playground/middleware.js).
    // IMPORTANT : on ne whiteliste PAS tout /admin/ (cible n°1 des attaquants),
    // uniquement les sous-dossiers de bundles front livrés par Symfony/API Platform.
    '/bundles/apiplatform/',
    '/bundles/fosjsrouting/',
    '/bundles/nelmioapidoc/',
    'graphql-playground',
    '/admin-dev/themes/',
];

// ============================================================================
// LISTE DES MOTIFS MALVEILLANTS À RECHERCHER (150+ patterns)
// ============================================================================
// Ces regex détectent les comportements suspects et les codes malveillants connus
// Chaque pattern couvre une catégorie de menaces spécifiques

$malicious_patterns = [
    // --- Codage / Décodage d'obfuscation ---
    'base64_decode' => '/base64_decode\([\'"][a-zA-Z0-9\/\+=]+[\'"]\)/i',

    // --- Configuration SSL/TLS suspecte ---
    'curl_setopt_ssl_verifypeer' => '/curl_setopt\(\s*\$ch\s*,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*false\s*\)/i',
    
    // --- Variables POST suspectes ---
    'advert_hash_post' => '/\$_POST\[[\'"]advert_hash[\'"]\]/i',
    
    // --- Hachage non sécurisé ---
    'md5_usage' => '/md5\([\'"][a-zA-Z0-9\/\+=]*[\'"]?\)/i',
    'gzuncompress' => '/gzuncompress\([\'"][a-zA-Z0-9\/\+=]*[\'"]?\)/i',
    'file_get_contents' => '/file_get_contents\([\'"][a-zA-Z0-9\/\+=]*[\'"]?\)/i',
    'file_get_contents_https' => '/file_get_contents\s*\(\s*[\'"]https[\'"]/i',
    'preg_replace_e' => '/preg_replace\(\s*["\'].*\/e["\']\s*,/i',
    'shell_exec' => '/shell_exec\((.*)\)/i',
    'passthru' => '/passthru\((.*)\)/i',
    'md5_request' => '/md5\s*\(\s*\$_REQUEST\s*(\[[\'"][a-zA-Z0-9_\-]+[\'"]\])?\s*\)/i',
    'malicious_exit' => '/if\s*\(\s*md5\s*\(\s*\$_REQUEST\s*\[\s*[\'"]product_img_one[\'"]\s*\]\s*\)\s*!=\s*[\'"][a-f0-9]{32}[\'"]\s*\)\s*\{\s*exit\s*;\s*\}/i',
    'gzdecode' => '/gzdecode\([\'"][a-zA-Z0-9\/\+=]*[\'"]?\)/i',
    'document_cookie' => '/document\.cookie\s*=\s*[\'"][^\'"]*[\'"]/i',
    'everything_is_life' => '/EverythingIsLife/i',
    'trust_is_important' => '/trustisimportant/i',
    'urldecode' => '/urldecode\s*\(\s*[\'"][a-zA-Z0-9_\-]*[\'"]?\s*\)/i',
    'btoa' => '/btoa\s*\(\s*[\'"][a-zA-Z0-9_\-]*[\'"]?\s*\)/i',
    'atob' => '/atob\s*\(\s*[\'"][a-zA-Z0-9_\-]*[\'"]?\s*\)/i',
    'at_includes' => '/@include\s*\(\s*[\'"][a-zA-Z0-9\/_\-\.]+[\'"]\s*\)/i',
    'tools_get_value' => '/Tools::getValue\([\'"][a-zA-Z0-9_\-]+[\'"]\s*,\s*\$_(GET|POST|REQUEST)/i',
    'db_execute_concat' => '/Db::getInstance\(\)->(execute|executeS)\s*\([\'"][^\'"]*\.\s*\$[a-zA-Z0-9_]+/',
    'unserialize' => '/unserialize\([\'"][a-zA-Z0-9\/\+=]*[\'"]?\)/i',
    'proc_open' => '/proc_open\((.*)\)/i',
    'xor_loop_obfuscation' => '/\bfor\s*\(\s*\$?[a-zA-Z0-9]+\s*=\s*[0-9]+\s*;\s*\$?[a-zA-Z0-9]+\s*<\s*[a-zA-Z0-9]+\s*;\s*\$?[a-zA-Z0-9]+\+\+\)\s*\{\s*\$?[a-zA-Z0-9]+\s*\^\s*[a-zA-Z0-9]+;/i',
    'create_function' => '/@create_function\((.*)\)/i',
    'adminer_files' => '/adminer(\-[0-9\.]*)?\.php$/i',
    'adminer_mentions' => '/adminer/i',
    'webshell_c99' => '/c99\.php$/i',
    'webshell_r57' => '/r57\.php$/i',
    'webshell_b374k' => '/b374k\.php$/i',
    'webshell_wso' => '/wso\.php$/i',
    'webshell_f' => '/f\.php$/i',
    'xsamxadoo_bot' => '/xsamxadoo_bot\.php$/i',
    'xsamxadoo_deface' => '/xsamxadoo_deface\.php$/i',
    'webshell_0x666' => '/0x666\.php$/i',
    'webshell_blm' => '/blm\.php$/i',
    'xsam_xadoo_html' => '/xsam_xadoo\.html$/i',
    'phpmyadmin' => '/phpmyadmin\.php$/i',
    'phpinfo' => '/phpinfo\.php$/i',
    'mysql_manager' => '/mysqlmanager\.php$/i',
    'multiple_md5_obfuscation' => '/md5\(md5\(md5\((.*)\)\)\)/i',
    'error_reporting_suppression' => '/error_reporting\(0\)/i',
    'base64_eval_chain' => '/base64_decode\s*\(\s*[\'"][a-zA-Z0-9\/\+=]+[\'"]\s*\)\s*;\s*\$[a-zA-Z0-9_]+\s*\(\s*\$[a-zA-Z0-9_]+\s*\)/i',
    'char_index_obfuscation' => '/\$\w+\[\d+\](?:\.\$\w+\[\d+\]){5,}.*\(\s*\$\w+\s*\)/',
    'indexed_function_call' => '/\$\w+\s*=\s*[\'"][^\'"]+[\'"]\s*;\s*\$\w+\s*=\s*(\$\w+\[\d+\]\.){5,}\s*\$\w+\[\d+\];/i',
    'md5_request_compare' => '/md5\s*\(\s*\$_REQUEST\s*\[\s*[\'"][a-zA-Z0-9_\-]+[\'"]\s*\]\s*\)\s*===?\s*[\'"][a-f0-9]{32}[\'"]/i',
    'obfuscated_eval_base64' => '/eval\s*\(\s*@?\$?\w+\s*\(\s*@?\$?\w+\s*\(\s*[\'"][a-zA-Z0-9\/=+]+[\'"]\s*\)\s*\)\s*\)\s*;/i',
    'js_credit_card_exfil' => '/\.value\.match\s*\(\s*\/[0-9]{13,16}\/\s*\)/i',
    'js_cryptominer' => '/new\s+(?:CoinHive|WebAssembly)/i',
    'rot13_obfuscation' => '/str_rot13\s*\(\s*[\'"][^\'"]+[\'"]\s*\)/i',
    'hex_encoded_strings' => '/[\'"]\\\x[0-9a-f]{2}(?:\\\x[0-9a-f]{2}){10,}[\'"]/i',
    'Softby' => '/softwarebyms|softbylinux/i',
    'Alfa' => '/trigger\.txt|\.alfa\b/i',
    'Alfa_shell_pattern' => '~ALFA\s*(?:SHELL|TEAM)|alfa\s*shell~i',
    'WebShellNew' => '/new\.php$\b/i',
    'Halt_compiler' => '/__halt_compiler\s*\(\s*\)\s*;/i',
    'Checkout' => '/checkout\.js\b/i',
    'Pci keys' => '~(?is)\b(card_number|expiry_date)\b.{0,120}\b(card|payment|checkout|stripe|payplug|cc|visa|mastercard)\b~',
    'Mal_url' => '~\bhttps?://assetsgogle\.icu(?:/[^\s"\'<>]*)?\b~i',
    'Pas_fork' => '~\b(?:pas[_-]fork|p\.\s*a\.\s*s(?:\s*-\s*fork)?)\b~i',
    'Pas_fork2' => '~^<\?=\s*#\s*[-\?\.\~\^A-Za-z0-9]{6,}~m',
    'Admin k2' => '/admin\.k2$/i',
    'Eval' => '/eval\s*\(\s*\$_SERVER\[[^\]]*\]/i',
    'WebSkimmer_Domain_IOC' => '/(frontstatics\.com|jquerycdn\.at|g-analytics\.com|jquery-js\.com)/i',
    'WebSkimmer_Custom_Func' => '/(sendCCData|collectCardData|skimmerInit)/i',
    'WebSkimmer_Form_Submit' => '/addEventListener\s*\(\s*[\'"]submit[\'"]\s*,[^)]+(card(number)?|cc_?num|cvv|cvc|exp(ir(y|ation))?|exp_?month|exp_?year)/is',
    // Détection d'exfiltration HTTP : on exige que l'appel réseau et l'URL externe
    // soient réellement liés (l'URL est un ARGUMENT proche de l'appel), et non une
    // simple coïncidence dans un bundle minifié. L'ancienne version laissait 200
    // caractères entre l'appel et l'URL, ce qui matchait du code JS légitime
    // (ex. graphql-playground/middleware.js d'API Platform) -> faux positifs massifs.
    'WebSkimmer_Exfil_HTTP' => '/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\([^;\n]{0,80}?[\'"]https?:\/\/[^\'"\s]+[\'"]/i',
    // Variante "new Image()" : l'affectation .src doit pointer vers une URL externe
    // (éventuellement via une concaténation, ex. .src="https://..."+data).
    'WebSkimmer_Exfil_Image' => '/\bnew\s+Image\s*\(\s*\)[^;\n]{0,60}?\.src\s*=\s*[\'"]https?:\/\/[^\'"\s]+/i',
    'WebSkimmer_Obfus_atob_wide' => '/atob\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}[\'"]\s*\)/i',
    'Eval_gzinflate_chain' => '~(?is)eval\s*\(\s*(gzinflate|gzuncompress)\s*\(\s*base64_decode\s*\(~',
    'Variable_function_exec' => '~(?is)\$\w+\s*=\s*[\'"][^\'"]+[\'"]\s*;\s*\$\w+\s*\(~',
    'Xor_decoder_pattern' => '~(?is)for\s*\(\s*\$\w+\s*=\s*0\s*;.*?strlen\s*\(.*?\).*?\)\s*\{[^}]{0,400}\^\s*\$\w+\s*\[~',
    'Dynamic_request_call' => '~\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\(~',
    'Wso_fingerprint' => '~WSO\s*(?:2\.|Shell|Web\s*Shell)~i',
    'Chr_obfuscation_chain' => '~chr\s*\(\s*\d{2,3}\s*\)(?:\s*\.\s*chr\s*\(\s*\d{2,3}\s*\)){5,}~i',
    'Hex_payload_large' => '~[\'"](?:\\\x[0-9a-fA-F]{2}){20,}[\'"]~',
    'High_entropy_string' => '~[\'"][A-Za-z0-9+\/=_\-]{500,}[\'"]~',
    'CodePen_Assets' => '~\bassets\.codepen\.io\b~i',
    'CodePen_URL' => '~https?://assets\.codepen\.io/[^\s"\']*~i',
    'Domain_XYZ' => '~https?://[a-z0-9.-]+\.xyz(?:[/?#"\']|\s|$)~i',
    'Domain_ICU' => '~https?://[a-z0-9.-]+\.icu(?:[/?#"\']|\s|$)~i',
    'eval_superglobals' => '/eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[\'"][^\'"]+[\'"]\]\s*\)/i',
    'assert_backdoor' => '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[\'"][^\'"]+[\'"]\]\s*\)/i',
    'include_superglobals' => '/\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[\'"][^\'"]+[\'"]\]\s*\)/i',
    'php_filter_usage' => '/php:\/\/filter\/resource=/i',
    'htaccess_suspicious_redirect' => '/RewriteRule\s+.*https?:\/\/[^\s]+/i',

    // --- .htaccess malveillants (souvent dans /img/ ou /upload/) ---
    'htaccess_malicious_handler'
        => '/(SetHandler|AddHandler|AddType)\s+application\/x-httpd-php/i',
    'htaccess_php_engine_on'
        => '/php_flag\s+engine\s+on/i',
    'htaccess_auto_prepend'
        => '/php_value\s+auto_prepend_file/i',

    'js_remote_loader_ioc' => '~(?:trasysit\.com\s*/\s*821921|aHR0cHM6Ly90cmFzeXNpdC5jb20vODIxOTIx|etcnadormx0sipblEvLCHOI)~i',
    // Variante stricte (>=40 chars base64) : signature classique de skimmer obfusqué.
    'WebSkimmer_Obfus_atob' => '/\batob\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}[\'"]\s*\)/i',
    'js_ga_lure_plus_obfuscation' => '~(?is)'
        . 'google-analytics\.com\/analytics\.js'
        . '(?=[\s\S]{0,8000}\bcreateElement\s*\(\s*[\'"]script[\'"]\s*\))'
        . '(?=[\s\S]{0,8000}\bappendChild\s*\()'
        . '(?=[\s\S]{0,8000}(?:\.\s*map\s*\(|\.\s*join\s*\(|\bfetch\s*\(|\bthen\s*\())~',
    'js_order_page_loader' => '~location\.href\.indexOf\(\s*[\'"](commande|order)[\'"]\s*\)\s*>\s*-?1[\s\S]{0,2000}d\.src\s*=\s*atob\s*\(~is',
    'iife_function_ji' => '~\(\s*function\s*\(\s*a\s*,\s*n\s*,\s*a_\s*,\s*l\s*,\s*y\s*,\s*t\s*,\s*i\s*,\s*c\s*,\s*s\s*\)\s*\{\s*function\s+ji\b~s',
    // Variante stricte base64_encode puis base64_decode dans le même fichier.
    // (L'ancienne clé dupliquée en début de tableau a été supprimée : en PHP,
    // une clé identique écrase silencieusement la précédente.)
    'base64_encode_decode_pair' => '~base64_encode\s*\([^)]+\).*?base64_decode~is',
      'path_traversal_pattern' => '~[\'\"][./\\\\]*\.\.[/\\\\][\'\"]~i', // motif très générique, ignoré plus loin
    'suspicious_eval_chain' => '~(?is)eval\s*\(\s*(?:stripslashes|htmlspecialchars_decode|urldecode)\s*\(~',
];

// ============================================================================
// SÉVÉRITÉ PAR MOTIF (faux positifs / bruit)
// ============================================================================
// Par défaut, un motif détecté est classé "critical". Mais certains motifs
// très génériques (md5(), file_get_contents(), atob()...) apparaissent dans du
// code légitime et noient le rapport. On les reclasse ici en warning/info pour
// que l'utilisateur se concentre d'abord sur les vraies menaces.
//
// Pour ajouter une règle : 'nom_du_pattern' => 'warning' | 'info'
$pattern_severity = [
    // Bruit élevé : usage courant en PrestaShop / libs JS -> information
    'md5_usage'                  => 'info',
    'file_get_contents'          => 'info',
    'atob'                       => 'info',
    'btoa'                       => 'info',
    'urldecode'                  => 'info',
    'document_cookie'            => 'info',
    'adminer_mentions'           => 'info',
    'Checkout'                   => 'info',
    'CodePen_Assets'             => 'info',
    'CodePen_URL'                => 'info',

    // Suspect mais souvent légitime -> avertissement
    'base64_decode'              => 'warning',
    'gzuncompress'               => 'warning',
    'gzdecode'                   => 'warning',
    'unserialize'                => 'warning',
    'file_get_contents_https'    => 'warning',
    'curl_setopt_ssl_verifypeer' => 'warning',
    'rot13_obfuscation'          => 'warning',
    'High_entropy_string'        => 'warning',
    'Domain_XYZ'                 => 'warning',
    'Domain_ICU'                 => 'warning',
    'htaccess_suspicious_redirect' => 'warning',
    'tools_get_value'            => 'warning',
    'db_execute_concat'          => 'warning',
    // Appels réseau sortants : très fréquents dans du JS légitime (analytics, CDN,
    // playgrounds d'API...). On les rétrograde pour ne pas noyer le rapport.
    'WebSkimmer_Exfil_HTTP'      => 'warning',
    'WebSkimmer_Exfil_Image'     => 'warning',
];

// Initialisation
$infected_files  = [];
$total_php_files = 0;
$file_hashes     = []; // Pour stocker les hashes MD5 des fichiers suspects

/**
 * FONCTION : scan_directory()
 * 
 * OBJECTIF :
 * Parcourt récursivement un répertoire et tous ses sous-répertoires pour scanner
 * les fichiers PHP, JavaScript, Templates et autres extensions sensibles.
 *
 * PARAMÈTRES :
 * @param string $dir                    Chemin du répertoire à scanner
 * @param array  $malicious_patterns     Tableau des patterns malveillants
 * @param array  &$infected_files       Tableau de résultats (modifié par référence)
 * @param int    &$total_php_files     Compteur de fichiers scannés (modifié par référence)
 * @param array  $whitelist             Fichiers à ignorer
 *
 * @return void
 */
function scan_directory($dir, $malicious_patterns, &$infected_files, &$total_php_files, $whitelist, &$file_hashes, $pattern_severity) {
    if (!is_dir($dir)) return;

    // Normalisation du chemin pour éviter les doubles slashs (//) qui cassent la whitelist
    $dir = rtrim($dir, '/');

    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;

        $file_path = $dir . '/' . $file;

        // Exclusion des dossiers de cache volumineux pour éviter les timeouts.
        // On exclut aussi les dossiers de développement/versioning qui ne font
        // PAS partie d'une installation PrestaShop en production : les scanner
        // n'apporte rien et peut faire exploser le temps d'exécution (.git peut
        // contenir des dizaines de milliers d'objets binaires).
        if (is_dir($file_path)) {
            $base = basename($file_path);
            if (strpos($file_path, '/var/cache') !== false
                || strpos($file_path, '/app/cache') !== false
                || in_array($base, ['.git', '.github', '.svn', 'node_modules', '.idea', '.vscode'], true)) {
                continue;
            }
        }

        if (is_dir($file_path)) {
            scan_directory($file_path, $malicious_patterns, $infected_files, $total_php_files, $whitelist, $file_hashes, $pattern_severity);
        } elseif (is_file($file_path) && in_array(pathinfo($file_path, PATHINFO_EXTENSION), ['php', 'tpl', 'html', 'xml', 'js', 'cache', 'htaccess'])) {
            $total_php_files++;
            scan_file($file_path, $malicious_patterns, $infected_files, $file_hashes, $whitelist, $pattern_severity);
        }
    }
}

/**
 * FONCTION : scan_file()
 *
 * OBJECTIF :
 * Analyse un fichier individuel en le comparant à tous les motifs malveillants.
 * Détecte les codes suspects, génère des hashes MD5 et reporte les violations.
 *
 * PARAMÈTRES :
 * @param string $file_path              Chemin complet du fichier à analyser
 * @param array  $malicious_patterns     Liste des patterns à rechercher
 * @param array  &$infected_files       Tableau des résultats (modifié par référence)
 * @param array  &$file_hashes          Tableau des hashes MD5 (modifié par référence)
 * @param array  $whitelist             Fichiers à exclure du scan
 *
 * @return void
 *
 * LOGIQUE :
 * 1. Vérifie si le fichier est dans la liste blanche (faux positifs)
 * 2. Vérifie la taille du fichier (évite les timeouts)
 * 3. Détecte les fichiers PHP dans les dossiers interdits (img/, upload/, download/)
 * 4. Compare le contenu avec tous les patterns malveillants
 * 5. Enregistre chaque match avec contexte et hash MD5
 */
function scan_file($file_path, $malicious_patterns, &$infected_files, &$file_hashes, $whitelist, $pattern_severity) {

    // Vérification de la liste blanche (fichiers connus sans danger).
    // Chaque élément de la whitelist peut être un chemin complet ou un fragment
    // (ex. '/vendor/' pour exclure tout le répertoire vendor). Cela permet de
    // filtrer facilement des bibliothèques entières ou des dossiers de tests
    // sans avoir à lister chaque fichier individuellement.
    foreach ($whitelist as $wh_item) {
        if ($wh_item !== '' && strpos($file_path, $wh_item) !== false) {
            return;
        }
    }

    // Vérification de la taille avant tout chargement en mémoire.
    // Si MAX_FILE_SIZE est 0, on ne fait aucune vérification et on scanne
    // quel que soit le poids du fichier. Autrefois une limite fixe était imposée
    // pour éviter les timeouts, mais l'utilisateur préfère désormais voir
    // tous les fichiers.
    if (MAX_FILE_SIZE > 0) {
        $size = @filesize($file_path);
        if ($size !== false && $size > MAX_FILE_SIZE) {
            $infected_files[] = [
                'file'       => $file_path,
                'line'       => null,
                'pattern'    => 'AVIS : Fichier non analysé car trop volumineux (> ' . round(MAX_FILE_SIZE / 1024 / 1024, 1) . ' Mo). À vérifier manuellement.',
                'context'    => ['Ce fichier dépasse la limite de taille configurée (MAX_FILE_SIZE) et n\'a pas été scanné automatiquement.'],
                'start_line' => 1,
                'mtime'      => @filemtime($file_path),
                'severity'   => 'info',
            ];
            return;
        }
    }

    // Garde mémoire dynamique.
    // Un fichier minifié d'une seule ligne énorme (bundle JS) combiné à
    // l'application de ~150 regex avec PREG_OFFSET_CAPTURE peut faire exploser
    // la mémoire disponible et interrompre TOUT le scan ("Allowed memory size
    // exhausted"). On estime ici le besoin mémoire et on renonce proprement
    // (fichier signalé "non analysé") plutôt que de planter le processus.
    $limit_raw = ini_get('memory_limit');
    if ($limit_raw !== false && $limit_raw !== '-1') {
        // Conversion de la valeur php.ini (ex. "128M") en octets.
        $unit = strtolower(substr($limit_raw, -1));
        $val  = (int) $limit_raw;
        $mem_limit_bytes = $val * (($unit === 'g') ? 1073741824 : (($unit === 'm') ? 1048576 : (($unit === 'k') ? 1024 : 1)));
        // Estimation de la consommation mémoire d'un fichier pendant le scan.
        // Le coût réel n'est pas seulement le contenu : chaque preg_match_all()
        // avec PREG_OFFSET_CAPTURE construit des tableaux de captures, et il y a
        // ~150 motifs. Sur un fichier minifié (peu de lignes mais très longues),
        // la consommation peut dépasser largement 10x la taille du fichier.
        // On retient un facteur prudent de 12x et une marge de sécurité de 60%.
        $estimated = ($size !== false ? $size : 0) * 12;
        $used      = memory_get_usage(true);
        if ($mem_limit_bytes > 0 && ($used + $estimated) > ($mem_limit_bytes * 0.60)) {
            $infected_files[] = [
                'file'       => $file_path,
                'line'       => null,
                'pattern'    => 'AVIS : Fichier non analysé (risque de saturation mémoire). À vérifier manuellement.',
                'context'    => ['Le fichier est trop lourd pour la mémoire PHP disponible (memory_limit = ' . $limit_raw . '). Il n\'a pas été scanné automatiquement pour éviter de faire échouer tout le scan.'],
                'start_line' => 1,
                'mtime'      => @filemtime($file_path),
                'severity'   => 'info',
            ];
            return;
        }
    }


    $content = file_get_contents($file_path);
    if ($content === false) return;

    // Calcul unique du hash MD5 par fichier (mis en cache pour éviter les appels
    // répétés à md5_file() pour chaque motif détecté dans le même fichier).
    if (!isset($file_hashes[$file_path])) {
        $file_hashes[$file_path] = md5_file($file_path);
    }
    $file_md5 = $file_hashes[$file_path];

    $lines      = explode("\n", $content);
    $line_count = count($lines);

    // Alerte sur les fichiers PHP dans des dossiers d'images/upload (Zone Interdite)
    $is_suspicious_dir = (
        strpos($file_path, '/img/') !== false || 
        strpos($file_path, '/upload/') !== false || 
        strpos($file_path, '/download/') !== false
    );
    // Exclusion des fichiers index.php légitimes (sécurité anti-listing de PrestaShop)
    // Exclusion de config.php (utilisé par Creative Elements)
    if ($is_suspicious_dir && pathinfo($file_path, PATHINFO_EXTENSION) === 'php' && !in_array(basename($file_path), ['index.php', 'config.php'])) { $infected_files[] = [
            'file'       => $file_path,
            'line'       => 0,
            'pattern'    => 'SUSPECT : Fichier PHP dans un dossier média (img/upload/download)',
            'context'    => ['Ce fichier PHP se trouve dans un emplacement anormal. À vérifier impérativement.'],
            'start_line' => 1,
            'mtime'      => @filemtime($file_path),
            'severity'   => 'critical',
            'md5'        => $file_md5,
        ];
        // On continue le scan pour voir s'il matche aussi des patterns connus
    }

    foreach ($malicious_patterns as $pattern_name => $pattern) {
        $_preg_ok = @preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);
        if (!$_preg_ok || empty($matches[0])) continue;

        // Comptage des occurrences et extraction du premier match uniquement.
        $total_occurrences = count($matches[0]);
        $first_match       = $matches[0][0];

        // Calcul du numéro de ligne SANS matérialiser un tableau de lignes :
        // substr_count() évite un explode() sur un gros fichier (bundle JS minifié),
        // qui dupliquait une grande portion du contenu en mémoire pour chaque motif
        // détecté et faisait échouer le scan ("Allowed memory size exhausted").
        $line_number = substr_count($content, "\n", 0, $first_match[1]);
        $context     = get_context($lines, $line_number, $line_count);

        // Libellé enrichi du pattern si plusieurs occurrences.
        // Exemples : "base64_decode" (1 fois) ou "base64_decode (×47)" (47 fois).
        $display_pattern = ($total_occurrences > 1)
            ? $pattern_name . ' (×' . $total_occurrences . ')'
            : $pattern_name;

        // Le motif "path_traversal_pattern" est extrêmement générique
        // et apparaît dans de nombreux fichiers PrestaShop (liens relatifs,
        // inclusions, etc.). Il ne s'agit pas d'une vulnérabilité en soi,
        // et il provoque des milliers de faux positifs qui noient le rapport.
        // Nous l'ignorons totalement pour ne montrer que les véritables
        // problèmes.
        if ($pattern_name === 'path_traversal_pattern') {
            continue;
        }

        // Pour les autres motifs, la sévérité dépend d'un mapping dédié :
        // les motifs très génériques (md5, atob, file_get_contents...) sont
        // rétrogradés en "info"/"warning" pour ne pas noyer le rapport. Tout
        // motif non listé reste "critical".
        $entry_severity = $pattern_severity[$pattern_name] ?? 'critical';

        $infected_files[] = [
            'file'       => $file_path,
            'line'       => $line_number + 1,
            'pattern'    => $display_pattern,
            'context'    => $context,
            'start_line' => max(0, $line_number - 5) + 1,
            'mtime'      => @filemtime($file_path),
            'severity'   => $entry_severity,
            'md5'        => $file_md5,
        ];
    }
}

/**
 * FONCTION : get_context()
 * 
 * OBJECTIF :
 * Extrait les lignes de code autour d'une détection pour afficher le contexte.
 * Cela permet à l'utilisateur de comprendre le code détecté (5 lignes avant, 15 après).
 *
 * PARAMÈTRES :
 * @param array $lines       Tableau des lignes du fichier
 * @param int   $line_number Numéro de la ligne détectée
 * @param int   $line_count  Nombre total de lignes
 *
 * @return array Lignes de contexte (max 21 lignes)
 */
function get_context($lines, $line_number, $line_count) {
    $start_line = max(0, $line_number - 5);   // 5 lignes avant la détection
    $end_line   = min($line_count - 1, $line_number + 15); // 15 lignes après
    return array_slice($lines, $start_line, $end_line - $start_line + 1);
}

/**
 * FONCTION : detect_prestashop_version()
 * 
 * OBJECTIF :
 * Détermine la version de PrestaShop installée sans exécuter de code PHP.
 * Supporte les versions 1.6, 1.7, et 8.x par recherche de fichiers de configuration.
 *
 * PARAMÈTRES :
 * @param string $root_path Chemin racine de l'installation PrestaShop
 *
 * @return string Numéro de version ou message d'erreur
 *
 * LOGIQUE :
 * 1. Cherche d'abord src/Core/Version.php (PrestaShop 8.x)
 * 2. Puis defines.inc.php (PrestaShop 1.7)
 * 3. Puis settings.inc.php (PrestaShop 1.6)
 * 4. Puis composer.json (versions modernes)
 * 5. Retourne un message d'erreur si aucune version non trouvée
 */
function detect_prestashop_version($root_path) {
    $settings_file   = $root_path . '/config/settings.inc.php';
    $defines_file    = $root_path . '/config/defines.inc.php';
    $version_file    = $root_path . '/src/Core/Version.php';
    $app_kernel_file = $root_path . '/app/AppKernel.php';
    $composer_file   = $root_path . '/composer.json';

    // PrestaShop 8.x — src/Core/Version.php (PRIORITÉ pour PS8)
    if (file_exists($version_file)) {
        $content = file_get_contents($version_file);
        if ($content !== false && preg_match("/const\s+VERSION\s*=\s*['\"]([^'\"]+)['\"]/i", $content, $m)) {
            return $m[1];
        }
    }

    // PrestaShop 1.7 / ancienne 8.x — defines.inc.php
    if (file_exists($defines_file)) {
        $content = file_get_contents($defines_file);
        if ($content !== false && preg_match("/define\s*\(\s*['\"]_PS_VERSION_['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/i", $content, $m)) {
            return $m[1];
        }
    }

    // PrestaShop 1.6 — settings.inc.php
    if (file_exists($settings_file)) {
        $raw = file_get_contents($settings_file);
        if ($raw !== false) {
            if (preg_match("/define\s*\(\s*['\"]_PS_VERSION_['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/i", $raw, $m)) {
                return $m[1];
            }
            if (preg_match("/\\\$_PS_VERSION_\s*=\s*['\"]([^'\"]+)['\"]/i", $raw, $m)) {
                return $m[1];
            }
        }
        
        // Fallback : include (méthode originale) si la lecture brute échoue
        if (!defined('_PS_VERSION_')) {
            @include($settings_file);
        }
        if (defined('_PS_VERSION_')) {
            return _PS_VERSION_;
        }
    }

    // AppKernel.php (1.7)
    if (file_exists($app_kernel_file)) {
        $content = file_get_contents($app_kernel_file);
        if ($content !== false && preg_match("/const\s+VERSION\s*=\s*['\"]([^'\"]+)['\"]/i", $content, $m)) {
            return $m[1];
        }
    }

    // composer.json
    if (file_exists($composer_file)) {
        $json = json_decode(file_get_contents($composer_file), true);
        if (is_array($json)) {
            if (isset($json['version'])) return $json['version'];
            if (isset($json['extra']['prestashop']['version'])) return $json['extra']['prestashop']['version'];
        }
    }

    return 'Fichiers de configuration introuvables (Racine testée : ' . $root_path . ')';
}

/**
 * FONCTION : scan_smarty_config_file()
 * 
 * OBJECTIF :
 * Vérifie la configuration du cache Smarty (moteur de templating)
 * Détecte les configurations dangereuses utilisant MySQL comme stockage de cache.
 *
 * PARAMÈTRES :
 * @param string $file_path        Chemin vers config/smarty.config.inc.php
 * @param array  &$infected_files  Tableau des résultats (modifié par référence)
 *
 * @return void
 *
 * ALERTE :
 * PS_SMARTY_CACHING_TYPE = 'mysql' peut causer des lenteurs et des failles de sécurité.
 */
function scan_smarty_config_file($file_path, &$infected_files) {
    if (!file_exists($file_path)) return;

    $file_content = file_get_contents($file_path);
    if (preg_match("/Configuration::get\('PS_SMARTY_CACHING_TYPE'\)\s*==\s*'mysql'/", $file_content)) {
        $infected_files[] = [
            'file'       => $file_path,
            'line'       => null,
            'pattern'    => "PS_SMARTY_CACHING_TYPE == 'mysql'",
            'context'    => ['Le fichier contient l\'option PS_SMARTY_CACHING_TYPE == "mysql", ce qui peut poser des problèmes.'],
            'start_line' => 1,
            'mtime'      => @filemtime($file_path),
            'severity'   => 'warning',
            'md5'        => md5_file($file_path),
        ];
    }
}

// Appel de la vérification du dossier /install
check_install_folder($infected_files, $root_path);

// Appel de la vérification des permissions sur les fichiers sensibles
check_sensitive_permissions($infected_files, $root_path);

// Appel de la vérification des headers HTTP de sécurité
$homepageUrl = $scheme . '://' . $host . '/';
$header_issues = [];
check_http_security_headers($homepageUrl, $header_issues);

/**
 * FONCTION : scan_phpunit_in_modules()
 * 
 * OBJECTIF :
 * Détecte la présence de PHPUnit (framework de test) dans le répertoire modules.
 * PHPUnit laissé accessible est un risque de sécurité car il expose des détails du code.
 *
 * PARAMÈTRES :
 * @param string $dir             Répertoire /modules à scanner récursivement
 * @param array  &$infected_files Tableau des résultats (modifié par référence)
 *
 * @return void
 *
 * RISQUE :
 * PHPUnit exposerait les tests du code, révélant sa structure et ses failles.
 * Doit être supprimé en production.
 */
function scan_phpunit_in_modules($dir, &$infected_files) {
    if (!is_dir($dir)) return;

    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;

        $file_path = $dir . '/' . $file;
        if (is_dir($file_path) && strtolower($file) === 'phpunit') {
            $infected_files[] = [
                'file'       => $file_path,
                'line'       => null,
                'pattern'    => 'Répertoire phpunit détecté',
                'context'    => ['Le répertoire "phpunit" est présent, ce qui peut représenter une faille de sécurité.'],
                'start_line' => 1,
                'mtime'      => @filemtime($file_path),
                'severity'   => 'warning',
                'md5'        => 'N/A',
            ];
        } elseif (is_file($file_path) && strtolower($file) === 'phpunit') {
            $infected_files[] = [
                'file'       => $file_path,
                'line'       => null,
                'pattern'    => 'Fichier phpunit détecté',
                'context'    => ['Le fichier "phpunit" est présent, ce qui peut représenter une faille de sécurité.'],
                'start_line' => 1,
                'mtime'      => @filemtime($file_path),
                'severity'   => 'warning',
                'md5'        => md5_file($file_path),
            ];
        }

        if (is_dir($file_path)) {
            scan_phpunit_in_modules($file_path, $infected_files);
        }
    }
}

/**
 * FONCTION : check_install_folder()
 * 
 * OBJECTIF :
 * Détecte la présence du dossier /install à la racine de PrestaShop.
 * C'est une FAILLE CRITIQUE - permet à un attaquant de réinstaller le site.
 *
 * PARAMÈTRES :
 * @param array  &$infected_files Tableau des résultats (modifié par référence)
 * @param string $root_path       Chemin racine de PrestaShop
 *
 * @return void
 *
 * ACTION REQUISE :
 * Le dossier /install DOIT être supprimé ou renommé immédiatement après l'installation.
 */
function check_install_folder(&$infected_files, $root_path) {
    $install_dir = $root_path . '/install';
    if (is_dir($install_dir)) {
        $infected_files[] = [
            'file'       => $install_dir,
            'line'       => null,
            'pattern'    => "DOSSIER D'INSTALLATION PRÉSENT",
            'context'    => [
                "Le dossier /install est toujours présent à la racine.",
                "Il doit être supprimé ou renommé immédiatement pour éviter une réinstallation malveillante."
            ],
            'start_line' => 1,
            'mtime'      => @filemtime($install_dir),
            'severity'   => 'critical',
            'md5'        => 'N/A',
        ];
    }
}

/**
 * FONCTION : check_sensitive_permissions()
 * 
 * OBJECTIF :
 * Vérifie les permissions d'accès aux fichiers sensibles (configuration, base de données).
 * Détecte les permissions "World Writable" (777) et "autres écriture" (002) dangereuses.
 *
 * PARAMÈTRES :
 * @param array  &$infected_files Tableau des résultats (modifié par référence)
 * @param string $root_path       Chemin racine de PrestaShop
 *
 * @return void
 *
 * VÉRIFICATIONS :
 * 1. Fichiers critiques accessibles en écriture par "others"
 * 2. Dossiers d'upload en 777 (lecteur, écriture, exécution pour tous)
 *
 * RECOMMANDATIONS :
 * - Fichiers config : 0644 (rw-r--r--)
 * - Dossiers : 0755 (rwxr-xr-x)
 * - Jamais 777 ou world-writable !
 */
function check_sensitive_permissions(&$infected_files, $root_path) {
    // 1. Fichiers/Dossiers critiques ne devant pas être World Writable
    $sensitive_paths = [
        $root_path . '/config/settings.inc.php',
        $root_path . '/app/config/parameters.php',
        $root_path . '/app/config/parameters.yml',
        $root_path . '/config/defines.inc.php',
        $root_path . '/.htaccess',
        $root_path . '/config/',
        $root_path . '/src/'
    ];

    foreach ($sensitive_paths as $path) {
        if (!file_exists($path)) continue;

        $perms = fileperms($path);
        // Vérifie si le fichier est accessible en écriture par "others" (World Writable - 0002)
        if (($perms & 0x0002) == 0x0002) {
            $octal = substr(sprintf('%o', $perms), -4);
            $type = is_dir($path) ? 'Dossier' : 'Fichier';
            $infected_files[] = [
                'file'       => $path,
                'line'       => null,
                'pattern'    => "PERMISSIONS CRITIQUES : $octal",
                'context'    => [
                    "$type sensible accessible en écriture publique (World Writable).",
                    "Permissions actuelles : $octal. Recommandé : 0644 (fichiers) ou 0755 (dossiers)."
                ],
                'start_line' => 1,
                'mtime'      => @filemtime($path),
                'severity'   => 'critical',
                'md5'        => is_file($path) ? md5_file($path) : 'N/A',
            ];
        }
    }

    // 2. Vérification spécifique pour /img/ et /upload/ (pas de 777)
    $upload_paths = [
        $root_path . '/img/',
        $root_path . '/upload/',
        $root_path . '/download/'
    ];

    foreach ($upload_paths as $path) {
        if (!file_exists($path)) continue;

        $perms = fileperms($path);
        
        // Détection robuste du 777 (rwxrwxrwx) via masque binaire
        if (($perms & 0777) === 0777) {
            $infected_files[] = [
                'file'       => $path,
                'line'       => null,
                'pattern'    => "PERMISSIONS DANGEREUSES : 777",
                'context'    => [
                    "Ce dossier est en 777 (lecture/écriture/exécution pour tous).",
                    "C'est un risque de sécurité majeur. Recommandé : 0755."
                ],
                'start_line' => 1,
                'mtime'      => @filemtime($path),
                'severity'   => 'critical',
                'md5'        => 'N/A',
            ];
        }
    }
}

/**
 * FONCTION : fix_detected_permissions()
 *
 * OBJECTIF :
 * Corrige automatiquement les permissions des fichiers/dossiers signalés par
 * le scan. Fichiers -> 0644 (rw-r--r--), dossiers -> 0755 (rwxr-xr-x).
 *
 * SÉCURITÉ :
 * La fonction ne travaille QUE sur les chemins déjà présents dans
 * $infected_files et dont le motif commence par "PERMISSIONS". Aucun chemin
 * arbitraire fourni par l'utilisateur n'est accepté : on ne peut donc pas
 * cibler un fichier hors des détections du scan.
 *
 * PARAMÈTRES :
 * @param array &$infected_files Tableau des détections du scan
 *
 * @return array Rapport : ['ok' => [...], 'fail' => [...]]
 */
function fix_detected_permissions(&$infected_files) {
    $report = ['ok' => [], 'fail' => []];

    foreach ($infected_files as $entry) {
        $pattern = $entry['pattern'] ?? '';
        if (strpos($pattern, 'PERMISSIONS') !== 0) continue;

        $path = $entry['file'] ?? '';
        if ($path === '' || !file_exists($path)) {
            $report['fail'][] = [$path, 'Chemin introuvable'];
            continue;
        }

        // Droits cibles : dossier 0755, fichier 0644
        $target = is_dir($path) ? 0755 : 0644;
        $old    = substr(sprintf('%o', fileperms($path)), -4);

        // @chmod : certains hébergeurs restreignent chmod ; on capture l'échec.
        if (@chmod($path, $target)) {
            clearstatcache(true, $path);
            $new = substr(sprintf('%o', fileperms($path)), -4);
            $report['ok'][] = [$path, $old, $new];
        } else {
            $report['fail'][] = [$path, "chmod $target refusé (droits insuffisants ou fichier verrouillé)"];
        }
    }

    return $report;
}

/**
 * FONCTION : check_http_security_headers()
 * 
 * OBJECTIF :
 * Effectue une requête HTTP vers la page d'accueil et vérifie la présence
 * des en-têtes de sécurité importants (HSTS, CSP, X-Frame-Options, etc.).
 *
 * PARAMÈTRES :
 * @param string $url            URL de la page d'accueil à vérifier
 * @param array  &$header_issues Tableau des en-têtes manquants/insuffisants
 *
 * @return void
 *
 * EN-TÊTES VÉRIFIÉS :
 * - X-Content-Type-Options : nosniff (évite MIME-type sniffing)
 * - X-Frame-Options : DENY ou SAMEORIGIN (évite clickjacking)
 * - Content-Security-Policy (CSP) : contrôle les ressources autorisées
 * - Strict-Transport-Security (HSTS) : forcer HTTPS (min 30 jours)
 * - Referrer-Policy : contrôle les informations de referrer
 * - Permissions-Policy : contrôle les fonctionnalités du navigateur
 * - X-XSS-Protection : protection XSS (navigateurs légers)
 */
function check_http_security_headers($url, &$header_issues) {
    if (empty($url) || !function_exists('curl_init')) return;

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    
    $response = curl_exec($ch);
    
    if ($response === false) {
        return;
    }

    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header_text = substr($response, 0, $header_size);

    $headers = [];
    foreach (explode("\r\n", $header_text) as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) == 2) {
            $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
        }
    }

    // Liste des headers à vérifier avec règles qualitatives
    $checks = [
        'x-content-type-options' => [
            'name' => 'X-Content-Type-Options',
            'check' => function($val) { return stripos($val, 'nosniff') !== false; },
            'msg' => 'Devrait être "nosniff".'
        ],
        'x-frame-options' => [
            'name' => 'X-Frame-Options',
            'check' => function($val) { return stripos($val, 'DENY') !== false || stripos($val, 'SAMEORIGIN') !== false; },
            'msg' => 'Devrait être DENY ou SAMEORIGIN.'
        ],
        'content-security-policy' => [
            'name' => 'Content-Security-Policy',
            'check' => function($val) { return !empty($val); },
            'msg' => 'Non défini.'
        ],
        'strict-transport-security' => [
            'name' => 'Strict-Transport-Security',
            'check' => function($val) { 
                if (preg_match('/max-age=(\d+)/', $val, $m)) {
                    return $m[1] >= 2592000; // 30 jours min
                }
                return false;
            },
            'msg' => 'Manquant ou max-age trop court (< 30 jours).'
        ],
        'referrer-policy' => [
            'name' => 'Referrer-Policy',
            'check' => function($val) { return !empty($val); },
            'msg' => 'Non défini.'
        ],
        'permissions-policy' => [
            'name' => 'Permissions-Policy',
            'check' => function($val) { return !empty($val); },
            'msg' => 'Non défini.'
        ],
        'x-xss-protection' => [
            'name' => 'X-XSS-Protection',
            'check' => function($val) { return stripos($val, '1; mode=block') !== false; },
            'msg' => 'Devrait être "1; mode=block".'
        ]
    ];

    foreach ($checks as $key => $rule) {
        if (!isset($headers[$key])) {
            $header_issues[] = [
                'header' => $rule['name'],
                'status' => 'Manquant',
                'details' => $rule['msg']
            ];
        } elseif (!$rule['check']($headers[$key])) {
            $header_issues[] = [
                'header' => $rule['name'],
                'status' => 'Insuffisant',
                'details' => 'Valeur actuelle : "' . htmlspecialchars($headers[$key]) . '". ' . $rule['msg']
            ];
        }
    }
}

/**
 * FONCTION : scan_root_htaccess()
 * 
 * OBJECTIF :
 * Analyse le fichier .htaccess principal à la racine pour détecter :
 * - Les redirects malveillants vers des domaines externes
 * - Les configurations PHP dangereuses (SetHandler, AddType)
 * - Les auto_prepend_file qui chargeraient du code malveillant
 *
 * PARAMÈTRES :
 * @param string $root_path       Chemin racine de PrestaShop
 * @param array  &$infected_files Tableau des résultats (modifié par référence)
 *
 * @return void
 *
 * MENACES DÉTECTÉES :
 * 1. RewriteRule -> URL externe : redirection malveillante
 * 2. SetHandler/AddHandler application/x-httpd-php : PHP en dossier non-code
 * 3. php_value auto_prepend_file : injection de code au démarrage
 */
function scan_root_htaccess($root_path, &$infected_files) {
    $htaccess_file = $root_path . '/.htaccess';
    if (!file_exists($htaccess_file)) return;

    $content = file_get_contents($htaccess_file);
    if ($content === false) return;

    // Patterns pour .htaccess malveillant
    $patterns = [
        'htaccess_redirect_malware' => '/RewriteRule\s+^.*$\s+https?:\/\/[^\s]+\s+[LR]/i',
        'htaccess_php_execution' => '/(SetHandler|AddHandler|AddType)\s+application\/x-httpd-php/i',
        'htaccess_php_value_prepend' => '/php_value\s+(?:auto_prepend_file|auto_append_file)/i',
    ];

    $lines = explode("\n", $content);
    $line_count = count($lines);

    foreach ($patterns as $pattern_name => $pattern) {
        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $line_number = count(explode("\n", substr($content, 0, $match[1]))) - 1;
                $start_line = max(0, $line_number - 2);
                $end_line = min($line_count - 1, $line_number + 5);
                $context = array_slice($lines, $start_line, $end_line - $start_line + 1);

                $infected_files[] = [
                    'file'       => $htaccess_file,
                    'line'       => $line_number + 1,
                    'pattern'    => "ALERTE .htaccess : $pattern_name",
                    'context'    => $context,
                    'start_line' => $start_line + 1,
                    'mtime'      => @filemtime($htaccess_file),
                    'severity'   => 'critical',
                    'md5'        => md5_file($htaccess_file),
                ];
            }
        }
    }
}

/**
 * FONCTION : check_prestashop_vulnerabilities()
 * 
 * OBJECTIF :
 * Détecte si la version de PrestaShop installée est connue pour avoir des failles.
 * Recommande une mise à jour si une version vulnérable est trouvée.
 *
 * PARAMÈTRES :
 * @param string $root_path        Chemin racine de PrestaShop
 * @param string $prestashop_version Numéro de version détecté
 * @param array  &$infected_files  Tableau des résultats (modifié par référence)
 *
 * @return void
 *
 * VERSIONS VULNÉRABLES CONNUES (2026) :
 * - 1.6.0 : Extrêmement ancienne, non supportée
 * - 1.7.0 : Mises à jour critiques manquantes
 * - 8.0.0-8.0.2 : Failles XSS et CSRF documentées
 *
 * NOTE : La base s'enrichit avec les mises à jour du script.
 */
function check_prestashop_vulnerabilities($root_path, $prestashop_version, &$infected_files) {
    if ($prestashop_version === 'Inconnue' || $prestashop_version === 'Fichiers de configuration introuvables (Racine testée : ' . $root_path . ')') {
        return;
    }

    // Base de versions vulérables connues (à jour jusqu'à 2026)
    $vulnerable_versions = [
        '1.6.0' => 'Très ancienne version, non supportée',
        '1.7.0' => 'Version 1.7.0, mises à jour critiques manquantes',
        '8.0.0' => '8.0.0-8.0.2 : failles XSS et CSRF connues',
    ];

    foreach ($vulnerable_versions as $vuln_version => $description) {
        if (stripos($prestashop_version, $vuln_version) === 0) {
            // Non critique car c'est juste alerter, mais l'utilisateur décide
            $infected_files[] = [
                'file'       => $root_path . '/config/',
                'line'       => null,
                'pattern'    => 'VERSION PRESTASHOP POTENTIELLEMENT VULNÉRABLE',
                'context'    => [
                    "PrestaShop $prestashop_version détecté.",
                    $description,
                    "Considérez une mise à jour pour des raisons de sécurité."
                ],
                'start_line' => 1,
                'mtime'      => time(),
                'severity'   => 'warning',
                'md5'        => 'N/A',
            ];
            break;
        }
    }
}

/**
 * FONCTION : get_statistics()
 * 
 * OBJECTIF :
 * Compte et retourne le nombre de détections par niveau de sévérité.
 * Utilisé pour afficher les cartes de résumé dans l'interface HTML.
 *
 * PARAMÈTRES :
 * @param array &$infected_files Tableau contenant toutes les détections
 *
 * @return array Tableau avec clés 'critical', 'warning', 'info' contenant les compteurs
 *
 * STRUCTURE DE RETOUR :
 * [
 *     'critical' => 5,  // Problèmes graves à corriger immédiatement
 *     'warning'  => 3,  // Avertissements à examiner
 *     'info'     => 2   // Informations pour connaissance
 * ]
 */
function get_statistics(&$infected_files) {
    $stats = [
        'critical' => 0,
        'warning' => 0,
        'info'    => 0,
    ];

    foreach ($infected_files as $file) {
        $severity = $file['severity'] ?? 'info';
        if (isset($stats[$severity])) {
            $stats[$severity]++;
        }
    }

    return $stats;
}

/**
 * Audite quelques directives PHP et extensions essentielles pour PrestaShop.
 *
 * Le retour est un tableau de chaînes décrivant les écarts ou manquements.
 * On vérifie à la fois des paramètres de sécurité (display_errors, allow_url_fopen,
 * etc.) et la présence d'extensions couramment requises (zip, gd, openssl, ...).
 *
 * @return array Liste d'avis/informations à afficher au-dessus du rapport.
 */
function audit_php_configuration() {
    $issues = [];

    $to_check = [
        'display_errors'     => ['should' => 'Off',  'msg' => 'Pour des raisons de sécurité, les erreurs PHP ne doivent pas être visibles sur un site en production.'],
        'allow_url_fopen'    => ['should' => 'Off',  'msg' => 'La désactivation empêche l\'ouverture de fichiers distants via URL, réduisant la surface d\'attaque.'],
        'session.use_strict_mode' => ['should' => '1','msg' => 'Evite l\'utilisation de sessions non initialisées.'],
        'session.use_only_cookies' => ['should' => '1','msg' => 'Empêche la propagation de l\'identifiant de session dans l\'URL.'],
        'session.cookie_httponly' => ['should' => '1','msg' => 'Renforce la sécurité des cookies de session.'],
    ];

    foreach ($to_check as $name => $info) {
        $current = strtolower(ini_get($name));
        if ($current === false) {
            $issues[] = "Impossible de lire la directive \"$name\".";
            continue;
        }
        if ($current !== strtolower($info['should'])) {
            $issues[] = "Directive $name=$current (recommandé: {$info['should']}). {$info['msg']}";
        }
    }

    // Extensions indispensables pour PrestaShop
    $required_ext = ['zip', 'gd', 'openssl', 'curl', 'pdo_mysql'];
    foreach ($required_ext as $ext) {
        if (!extension_loaded($ext)) {
            $issues[] = "Extension PHP manquante : '$ext' (nécessaire pour PrestaShop).";
        }
    }

    return $issues;
}

/**
 * FONCTION : check_recently_modified_files()
 *
 * OBJECTIF :
 * Repère les fichiers modifiés récemment dans les zones sensibles. Un fichier
 * PHP/JS modifié il y a quelques heures ou jours, sans qu'on s'y attende, est
 * souvent le meilleur indicateur d'une compromission ou d'une backdoor déposée.
 *
 * PARAMÈTRES :
 * @param string $root_path       Chemin racine de PrestaShop
 * @param array  &$infected_files Tableau des résultats (modifié par référence)
 * @param int    $days            Fenêtre de détection en jours (défaut : 7)
 *
 * @return void
 */
function check_recently_modified_files($root_path, &$infected_files, $days = 7) {
    $threshold = time() - ($days * 86400);
    // Zones où une modification récente est particulièrement suspecte
    $watched = ['/img/', '/upload/', '/download/', '/js/', '/classes/', '/override/', '/modules/'];
    $exts    = ['php', 'js', 'htaccess'];

    foreach ($watched as $sub) {
        $dir = $root_path . $sub;
        if (!is_dir($dir)) continue;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile()) continue;
            if (!in_array(strtolower($fileInfo->getExtension()), $exts, true)) continue;

            $mtime = $fileInfo->getMTime();
            if ($mtime >= $threshold) {
                $path = $fileInfo->getPathname();
                // Évite les doublons : un même fichier ne doit être signalé qu'une fois,
                // même s'il est atteint via plusieurs zones surveillées (ex. un module
                // dont un sous-dossier porte un nom proche).
                static $seen = [];
                $real = realpath($path) ?: $path;
                if (isset($seen[$real])) continue;
                $seen[$real] = true;

                $age_hours = round((time() - $mtime) / 3600, 1);
                $infected_files[] = [
                    'file'       => $path,
                    'line'       => null,
                    'pattern'    => 'FICHIER MODIFIÉ RÉCEMMENT (' . $age_hours . 'h)',
                    'context'    => [
                        "Ce fichier a été modifié il y a $age_hours heures (fenêtre de $days jours).",
                        "Une modification récente dans une zone sensible est un signal fort de compromission.",
                        "Vérifiez que cette modification est légitime (mise à jour, déploiement...)."
                    ],
                    'start_line' => 1,
                    'mtime'      => $mtime,
                    'severity'   => 'warning',
                    'md5'        => @md5_file($path) ?: 'N/A',
                ];
            }
        }
    }
}

foreach ($directories as $directory) {
    scan_directory($directory, $malicious_patterns, $infected_files, $total_php_files, $whitelist, $file_hashes, $pattern_severity);
}

// Scan des modules pour détecter PHPUnit (framework de test exposé en production)
scan_phpunit_in_modules($root_path . '/modules', $infected_files);

// Vérification de la configuration du cache Smarty (MySQL = lenteur / risque)
scan_smarty_config_file($root_path . '/config/smarty.config.inc.php', $infected_files);

// Scan du .htaccess principal à la racine
scan_root_htaccess($root_path, $infected_files);

// Détection des fichiers modifiés récemment (signal de compromission)
check_recently_modified_files($root_path, $infected_files, 7);

// Vérification des versions vulnérables de PrestaShop
check_prestashop_vulnerabilities($root_path, $prestashop_version, $infected_files);

// ============================================================================
// SCAN YARA (optionnel) - signatures composées
// ============================================================================
// Si le binaire `yara` est présent et qu'un fichier de règles est disponible,
// on lance un scan YARA en complément des motifs regex internes.
// Chemin des règles : --yara=<fichier> en CLI, sinon rules/prestashop.yar
// (à côté du script). Le scan est silencieusement ignoré si YARA est absent.
$yara_rules_path = __DIR__ . '/rules/prestashop.yar';
if (PHP_SAPI === 'cli' && !empty($argv)) {
    foreach ($argv as $arg) {
        if (preg_match('/^--yara=(.+)$/', $arg, $m)) {
            $yara_rules_path = $m[1];
        }
    }
}
$yara_report = scan_with_yara($root_path, $infected_files, $yara_rules_path);

// ============================================================================
// TRI DES RÉSULTATS - Ordre d'affichage
// ============================================================================
// Tri multi-critères :
// 1. Par sévérité décroissante (Critique=3 > Avertissement=2 > Info=1)
// 2. Par date de modification décroissante (plus récent en premier)
// Cela aide l'utilisateur à se concentrer sur les problèmes les plus graves

usort($infected_files, function ($a, $b) {
    // Score de sévérité : 3 = critique, 2 = warning, 1 = info
    $severity_score = ['critical' => 3, 'warning' => 2, 'info' => 1];
    $scoreA = $severity_score[$a['severity'] ?? 'info'] ?? 0;
    $scoreB = $severity_score[$b['severity'] ?? 'info'] ?? 0;

    // Comparaison par sévérité
    if ($scoreA !== $scoreB) {
        return $scoreB - $scoreA; // Plus grave en premier
    }

    // Si même sévérité, tri par date (plus récent en premier)
    $timeA = $a['mtime'] ?? 0;
    $timeB = $b['mtime'] ?? 0;
    return $timeB - $timeA;
});

// ============================================================================
// MODE LIGNE DE COMMANDE (CLI)
// ============================================================================
// Le script peut être exécuté depuis un terminal :
//   php scanner.php [options]
//
// Options :
//   --path=<dossier>   Racine PrestaShop à analyser (défaut : auto-détection)
//   --json             Sortie JSON (au lieu du rapport texte)
//   --csv              Sortie CSV (au lieu du rapport texte)
//   --quiet            N'affiche que le résumé final (pas le détail)
//   --no-color         Désactive les couleurs ANSI
//   --help             Affiche l'aide
//
// En mode CLI, aucune interface HTML n'est générée : on affiche un rapport
// texte, puis le script se termine. Le mode web reste totalement inchangé.
if (PHP_SAPI === 'cli') {
    // --- Analyse des arguments ---
    $cli_opts   = [];
    $cli_flags  = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (preg_match('/^--([a-zA-Z0-9_-]+)(?:=(.*))?$/', $arg, $m)) {
            if (isset($m[2])) {
                $cli_opts[$m[1]] = $m[2];
            } else {
                $cli_flags[$m[1]] = true;
            }
        }
    }

    // --help : affiche l'aide et quitte
    if (isset($cli_flags['help'])) {
        fwrite(STDOUT, <<<TXT
Scanner de sécurité PrestaShop v{$version} — mode ligne de commande

Usage : php scanner.php [options]

Options :
  --path=<dossier>   Racine PrestaShop à analyser (défaut : auto-détection)
  --json             Sortie au format JSON
  --csv              Sortie au format CSV
  --quiet            N'affiche que le résumé (pas le détail des fichiers)
  --no-color         Désactive les couleurs ANSI
  --help             Affiche cette aide

Exemples :
  php scanner.php
  php scanner.php --path=/var/www/prestashop --quiet
  php scanner.php --json > rapport.json
  php scanner.php --csv  > rapport.csv

TXT);
        exit(0);
    }

    $cli_json  = isset($cli_flags['json']);
    $cli_csv   = isset($cli_flags['csv']);
    $cli_quiet = isset($cli_flags['quiet']);
    $cli_color = !isset($cli_flags['no-color']) && (function_exists('posix_isatty') ? @posix_isatty(STDOUT) : true);

    // --- Sortie CSV ---
    if ($cli_csv) {
        fputcsv(STDOUT, ['Date Scan', 'Criticité', 'Fichier', 'Dernière Modif', 'Pattern', 'Hash MD5', 'Extrait de code'], ';', '"', '\\');
        $now = date('Y-m-d H:i:s');
        foreach ($infected_files as $e) {
            fputcsv(STDOUT, [
                $now,
                strtoupper($e['severity'] ?? 'INFO'),
                $e['file'],
                isset($e['mtime']) ? date('Y-m-d H:i:s', $e['mtime']) : 'N/A',
                $e['pattern'],
                $e['md5'] ?? 'N/A',
                implode("\n", $e['context'] ?? []),
            ], ';', '"', '\\');
        }
        exit(0);
    }

    // --- Sortie JSON ---
    if ($cli_json) {
        echo json_encode([
            'scan_date'            => date('Y-m-d H:i:s'),
            'root_path'            => $root_path,
            'prestashop_version'   => $prestashop_version,
            'php_version'          => $php_version,
            'total_files_scanned'  => $total_php_files,
            'total_issues'         => count($infected_files),
            'statistics'           => get_statistics($infected_files),
            'http_security_headers'=> $header_issues,
            'issues'               => $infected_files,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        exit(0);
    }

    // --- Sortie texte (rapport lisible) ---
    // Petites fonctions de mise en forme ANSI (désactivées si --no-color).
    $c = function ($code, $txt) use ($cli_color) {
        return $cli_color ? "\033[{$code}m{$txt}\033[0m" : $txt;
    };
    $stats = get_statistics($infected_files);
    $line  = str_repeat('=', 74);

    echo "\n" . $line . "\n";
    echo "  Scanner de sécurité PrestaShop v{$version}\n";
    echo $line . "\n";
    echo "  Racine analysée     : {$root_path}\n";
    echo "  Version PrestaShop  : {$prestashop_version}\n";
    echo "  Version PHP         : {$php_version}\n";
    echo "  Fichiers analysés   : {$total_php_files}\n";
    echo $line . "\n";
    printf("  %s %d   |   %s %d   |   %s %d\n",
        $c('1;31', 'CRITIQUES:'), $stats['critical'],
        $c('1;33', 'AVERTISSEMENTS:'), $stats['warning'],
        $c('1;36', 'INFOS:'), $stats['info']);
    echo $line . "\n\n";

    if (empty($infected_files)) {
        echo $c('1;32', "  ✅ Aucun fichier infecté détecté.") . "\n\n";
    } elseif ($cli_quiet) {
        echo "  (mode --quiet : détail masqué, utilisez --json pour l'export complet)\n\n";
    } else {
        foreach ($infected_files as $e) {
            $sev = $e['severity'] ?? 'info';
            $tag = $sev === 'critical' ? $c('1;31', '[CRITICAL]')
                 : ($sev === 'warning' ? $c('1;33', '[WARNING]') : $c('1;36', '[INFO]'));
            echo "  {$tag} {$e['pattern']}\n";
            echo "           Fichier : {$e['file']}";
            if (!empty($e['line'])) echo " (ligne {$e['line']})";
            echo "\n";
            if (!empty($e['mtime'])) echo "           Modifié : " . date('d/m/Y H:i', $e['mtime']) . "\n";
            if (!empty($e['md5']) && $e['md5'] !== 'N/A') echo "           MD5     : {$e['md5']}\n";
            echo "\n";
        }
    }

    // Résumé des en-têtes HTTP manquants
    if (!empty($header_issues)) {
        echo "  En-têtes HTTP de sécurité manquants/insuffisants : " . count($header_issues) . "\n";
        foreach ($header_issues as $h) {
            echo "    - {$h['header']} ({$h['status']})\n";
        }
        echo "\n";
    }

    // Résumé du scan YARA
    if (!empty($yara_report['available'])) {
        echo "  Scan YARA : " . $yara_report['matches'] . " détection(s)";
        if (!empty($yara_report['version'])) echo " (moteur " . $yara_report['version'] . ")";
        echo "\n\n";
    } elseif (!empty($yara_report['error'])) {
        echo "  Scan YARA : ignoré (" . $yara_report['error'] . ")\n\n";
    }

    // Code de sortie : 2 si problèmes critiques, 1 si avertissements, 0 sinon.
    // Permet l'intégration dans des scripts / CI (ex. cron, GitLab CI).
    if ($stats['critical'] > 0)      exit(2);
    if ($stats['warning'] > 0)       exit(1);
    exit(0);
}

// ============================================================================
// CORRECTION AUTOMATIQUE DES PERMISSIONS
// ============================================================================
// Si l'utilisateur clique sur le bouton "Corriger les permissions", on
// remet les droits propres (fichiers 0644, dossiers 0755) sur les chemins
// détectés par le scan. Le résultat est affiché dans le rapport ci-dessous.
// Sécurité : on ne touche QUE les chemins déjà listés par check_sensitive_permissions().
$permission_fix_report = null;
if (isset($_GET['fix_permissions'])) {
    $permission_fix_report = fix_detected_permissions($infected_files);
    // Après correction, on relance la détection pour rafraîchir l'affichage
    // (les entrées de permissions corrigées disparaissent du rapport).
    $infected_files = array_values(array_filter($infected_files, function ($e) {
        return strpos($e['pattern'] ?? '', 'PERMISSIONS') !== 0;
    }));
    check_sensitive_permissions($infected_files, $root_path);
}

// ============================================================================
// EXPORT DES RÉSULTATS - FORMAT CSV
// ============================================================================
// Permet à l'utilisateur de télécharger un rapport CSV pour post-traitement
// Excel, Google Sheets, scripts d'automatisation, etc.

if (isset($_GET['export_csv'])) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=scan_report.csv');
    $output = fopen('php://output', 'w');
    
    // En-têtes du CSV
    fputcsv($output, ['Date Scan', 'Criticité', 'Fichier', 'Dernière Modif', 'Pattern', 'Hash MD5', 'Extrait de code'], ';', '"', '\\');

    $current_date = date('Y-m-d H:i:s');
    foreach ($infected_files as $infected_file) {
        fputcsv($output, [
            $current_date,
            strtoupper($infected_file['severity'] ?? 'INFO'),
            $infected_file['file'],
            isset($infected_file['mtime']) ? date('Y-m-d H:i:s', $infected_file['mtime']) : 'N/A',
            $infected_file['pattern'],
            $infected_file['md5'] ?? 'N/A',
            implode("\n", $infected_file['context']),
        ], ';', '"', '\\');
    }

    // Ajout des problèmes d'en-têtes HTTP de sécurité dans le même CSV
    // (préfixe [HEADER] dans la colonne Fichier pour les distinguer).
    foreach ($header_issues as $issue) {
        fputcsv($output, [
            $current_date,
            'WARNING',
            '[HEADER] ' . $issue['header'],
            'N/A',
            'En-tête HTTP ' . $issue['status'],
            'N/A',
            $issue['details'],
        ], ';', '"', '\\');
    }

    fclose($output);
    exit();
}

// ============================================================================
// EXPORT DES RÉSULTATS - FORMAT JSON
// ============================================================================
// Format JSON structuré pour intégration dans d'autres systèmes
// Contient les métadonnées du scan et tous les détails des détections

if (isset($_GET['export_json'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename=scan_report.json');

    // Structure complète du rapport
    $report = [
        'scan_date' => date('Y-m-d H:i:s'),
        'prestashop_version' => $prestashop_version,
        'php_version' => $php_version,
        'total_files_scanned' => $total_php_files,
        'total_issues' => count($infected_files),
        'statistics' => get_statistics($infected_files),
        'http_security_headers' => $header_issues,
        'issues' => $infected_files
    ];
    
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit();
}

// ============================================================================
// REGROUPEMENT DES RÉSULTATS PAR FICHIER
// ============================================================================
// Le scan peut produire plusieurs entrées pour un même fichier (une par motif
// détecté). Pour un rapport lisible, on regroupe tout par fichier : l'utilisateur
// voit "ce fichier pose N problèmes" plutôt que N lignes quasi identiques.
// La sévérité du groupe est celle du motif le plus grave détecté.
function group_by_file($infected_files) {
    $severity_rank = ['critical' => 3, 'warning' => 2, 'info' => 1];
    $groups = [];
    foreach ($infected_files as $entry) {
        $file = $entry['file'] ?? 'inconnu';
        if (!isset($groups[$file])) {
            $groups[$file] = [
                'file'     => $file,
                'mtime'    => $entry['mtime'] ?? 0,
                'md5'      => $entry['md5'] ?? 'N/A',
                'severity' => 'info',
                'matches'  => [],
            ];
        }
        $groups[$file]['matches'][] = $entry;
        $rank = $severity_rank[$entry['severity'] ?? 'info'] ?? 0;
        if ($rank > ($severity_rank[$groups[$file]['severity']] ?? 0)) {
            $groups[$file]['severity'] = $entry['severity'];
        }
    }
    return array_values($groups);
}

/**
 * FONCTION : scan_with_yara()
 *
 * OBJECTIF :
 * Complète le scan interne (regex) par un scan YARA, si le binaire `yara` est
 * disponible sur le serveur. YARA apporte des conditions composées (combinaisons
 * de chaînes, compteurs, contraintes de taille) que des regex simples ne peuvent
 * pas exprimer proprement, ce qui améliore la détection de webshells, skimmers
 * et backdoors obfusqués.
 *
 * Le binaire est invoqué via proc_open() avec un tableau d'arguments (PAS via
 * shell), afin d'éviter toute injection de commande. Les chemins de règles et
 * de cibles sont passés tels quels, sans passer par le shell.
 *
 * PARAMÈTRES :
 * @param string $root_path        Racine PrestaShop à analyser
 * @param array  &$infected_files  Tableau de résultats (modifié par référence)
 * @param string $rules_path       Chemin du fichier de règles YARA
 *
 * @return array ['available' => bool, 'scanned' => int, 'matches' => int, 'error' => ?string]
 *
 * LOGIQUE :
 * 1. Vérifie que la fonction proc_open est disponible et que le binaire yara existe
 * 2. Lance `yara <rules> <root_path> -r` (scan récursif)
 * 3. Parse la sortie (une ligne par match : "NomDeRegle CheminFichier")
 * 4. Ajoute chaque match comme détection critique
 */
function scan_with_yara($root_path, &$infected_files, $rules_path) {
    $result = ['available' => false, 'scanned' => 0, 'matches' => 0, 'error' => null];

    // proc_open peut être désactivé (disable_functions) sur certains hébergements.
    if (!function_exists('proc_open') || !function_exists('proc_close')) {
        $result['error'] = 'proc_open indisponible';
        return $result;
    }

    // Vérifie la présence du binaire `yara` (et sa version) sans passer par le shell.
    $yara_bin = null;
    foreach (['yara'] as $candidate) {
        $probe = @proc_open(
            [$candidate, '--version'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (is_resource($probe)) {
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[1]); fclose($pipes[2]);
            $code = proc_close($probe);
            if ($code === 0 && trim($out) !== '') {
                $yara_bin = $candidate;
                $result['version'] = trim($out);
                break;
            }
        }
    }
    if ($yara_bin === null) {
        $result['error'] = 'binaire yara introuvable';
        return $result;
    }

    // Vérifie que le fichier de règles existe et est lisible.
    if (!is_file($rules_path) || !is_readable($rules_path)) {
        $result['error'] = 'règles YARA introuvables : ' . $rules_path;
        return $result;
    }
    if (!is_dir($root_path)) {
        $result['error'] = 'racine introuvable : ' . $root_path;
        return $result;
    }

    $result['available'] = true;

    // Construction de la commande sous forme de TABLEAU d'arguments :
    // aucune interpolation shell, donc aucun risque d'injection.
    //   yara -r -w <rules> <root_path>
    //   -r : récursif ; -w : masque les warnings de compilation.
    $cmd = [$yara_bin, '-r', '-w', $rules_path, $root_path];

    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $process = @proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($process)) {
        $result['error'] = 'échec du lancement de yara';
        return $result;
    }

    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit_code = proc_close($process);

    // yara renvoie 0 (aucun match), 1 (match(s) trouvé(s)) ou >1 (erreur).
    if ($exit_code > 1) {
        $result['error'] = 'yara a retourné un code ' . $exit_code . ($stderr ? ' : ' . trim($stderr) : '');
        return $result;
    }

    // Parsing de la sortie : chaque ligne = "NomDeRegle CheminDuFichier".
    //
    // IMPORTANT : on ignore les matches sur l'outillage du scanner lui-même.
    // Le fichier de règles YARA (.yar) et le script scanner.php contiennent
    // forcément les mots-clés des règles (eval, $_POST, noms de règles...) et
    // se détecteraient eux-mêmes, polluant le rapport de faux positifs. Ces
    // fichiers ne font pas partie de l'application PrestaShop analysée.
    $self_real  = realpath(__FILE__) ?: __FILE__;
    $rules_real = realpath($rules_path) ?: $rules_path;

    $lines = preg_split('/\R/', trim((string)$stdout));
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;

        // Le chemin peut contenir des espaces : on sépare sur le PREMIER espace.
        $sep = strpos($line, ' ');
        if ($sep === false) continue;
        $rule_name = substr($line, 0, $sep);
        $file_path = trim(substr($line, $sep + 1));
        if ($file_path === '') continue;

        // Exclusion de l'outillage du scanner (script + règles YARA).
        $file_real = realpath($file_path) ?: $file_path;
        if ($file_real === $self_real || $file_real === $rules_real) {
            continue;
        }
        // Exclusion de tout fichier de règles YARA (.yar / .yara).
        if (preg_match('/\.ya?ra?$/i', $file_path)) {
            continue;
        }

        $result['matches']++;
        $infected_files[] = [
            'file'       => $file_path,
            'line'       => null,
            'pattern'    => 'YARA : ' . $rule_name,
            'context'    => [
                'Règle YARA déclenchée : ' . $rule_name,
                'Détection basée sur une signature composée (YARA), complémentaire des motifs internes.',
                'Vérifiez ce fichier manuellement : il correspond à un profil malveillant connu.',
            ],
            'start_line' => 1,
            'mtime'      => @filemtime($file_path),
            'severity'   => 'critical',
            'md5'        => (is_file($file_path) ? @md5_file($file_path) : 'N/A') ?: 'N/A',
        ];
    }

    return $result;
}

?>

<!-- ========================================================================
    INTERFACE WEB HTML / BOOTSTRAP
    ========================================================================
    Affiche les résultats du scan de sécurité avec une interface web moderne.

    CONTENU :
    - Logo et informations du scan (version PS, PHP, etc.)
    - Résumé statistique (cards critiques, warnings, info)
    - Liste des fichiers détectés avec hiérarchie de sévérité
    - Boutons d'export (CSV, JSON)
    - Audit des en-têtes HTTP de sécurité
    - Lien vers Sucuri SiteCheck pour scan externe

    FRAMEWORK : Bootstrap 5.3.2 (CDN)
    RESPONSIVE : Adapté desktop et mobile
======================================================================== -->

<!DOCTYPE html>
<html lang="fr">
<head>
    <!-- En-têtes HTML pour l'interface web -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan de sécurité PrestaShop</title>
    
    <!-- Lien vers le framework Bootstrap 5.3.2 via CDN (contenu de distribution) -->
    <!-- Bootstrap offre des composants CSS/JS réactifs pour une interface web moderne -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>

<!-- =========================================================================
    CONTENEUR PRINCIPAL - Interface utilisateur du rapport de scan
    =========================================================================
    Affichage du logo, du titre, des informations du scan et du résumé.
    Framework : Bootstrap 5.3.2 pour le responsive design
    Classes : container (largeur max 1200px), mt-5 (marge supérieure)
====================================================================== -->
<div class="container mt-5">
    <!-- Logo PrestaShop en WebP encodé en base64 (images intégrées sans fichier externe) -->
    <div class="p-3 mb-3 text-center rounded">
    <center><img style="width:15%" src="data:image/webp;base64,UklGRiAQAABXRUJQVlA4WAoAAAAQAAAACAEARQAAQUxQSKkKAAABsID/v/K01f99k0ADJcg61maQursS6rJntbnTzF0r27ilnbu7wNzdtwq37s1cmPtWgTQ1pIEG+T1Pzv+cnJM01yUiJLmNJEkS/dTLzMhry6yseQH9v/AZMVdriArF33ScQiHLYY4TBSOMZMddYsBBhkG5ZSzCLXOzjIsEnyg4Q1d33u7iMi8VEcUqM0XHuZqN2htdB60hmgoAH0mkDDAfAcB1wsHHa0yvmF6IN2/eMjrGIOjQMIuYLpvOMt4TZgDADl0LwWYEl1sLAJUKrioA+EyzUXujUl2TheUKk1WWC6X8Xokz8h3TXaPmh3E2mQSdsF9Y5pJuumVCuL1wmPC9JseH3ENSxxNCNEPWs1GYpdmovdFfkmmyjlJNCBeSSVC7j1nCcG44hFvIWDdwW1zS47cNAMbLzgGASFb8RjPzInzYAlEp4oAQkSbKKq6xjIJmtwrPWYL1HNvfZ+4aSOOXQnYIV8seYk95jUYzTjefH4WFUkQSlSm4pbmGiXqMgpzrhBaf4Gnh95e5Ktnt6pu8SrZDOF2z0XyjH4QrpVs8sXzq8SiQNFl3s4yLzIKKVE/DMwFgayEZ690MoEn4U3Ks0JwlZbUCiHTWaEyg0qSgOKOBejHzzYJcbJdwHpFri/Cwbe4KAKioAdA6WLo/q9mDT3nkec2p05ja7D/Zi5ZZEI1hRZdKh9O6bmTuS/ay/hQAzJVS3hSe5Nawr7Uak2aJwshkop3s5dMsiGgZO4hn2kHhNjI3oBXAXuc4YVM7LiB8wyJcdQB2e/Uak+WHufI8kkwDIMwwCGKKIgBwYhHb1psANwLAu+SqB9AyhMsXEdFhwgQA+KtmYzLEPa0xcbxyDtbRlT1VtjhMgti8Imx8nf/V5pxfCccQVfIjJJ9KRfR9LF+z8YAVf6aqFEnzJDuKXGkYRES9w5BmS14C9AeAPW6iWcKHDkGKeIWInJsBNHXRbUwVk7n4s2dlmkmQNLfIzqQEuEN4mYiymgGgG5cVARBJI+oMAB9rNyZJa0SepiS7nMgwiIjIF+WingSwf1Y0V7HTPqnnLfZAJzpdmKfdmCQr3fJMT5TDdD2aSfpBCtY13DVWAgxuE7yKs/YqydXSbf0my9JuTPr5y6REndG201W/mgyCVJda/mQnnVlkSHFLLuZv+9kLXBGp9vqIaDuANbZ+Y+qdyBXxmfs9e56VGAQp2K/wF9lE+EHYFRTzMT8rVr7Nb3JPagEw16Ax9chXw6ayintMghRTwU7BE2FkK+LOF25iU8ZOIxYC2N/fpDFVEf0krDYIUnlceDwR7kB8raO4IS0AypcC+DLNpDF1vSL8YhCUBK4foTHXc+kbReduAHcaNaaucna6bhCUAN/Fv8rNHk9vyvOt8JVT9SXLGmnWqNjoQFMUZ3Q8ru/xRPldvZaX6KF4uSezZfpLB9VWQJWl36i7UZLpzIFG56K0dKXkOoWsiHCHVPEndw2j36i7UQp4TPjRMghKsPnkB4C2iaSYt4Sfbe52pm0wY9CouVEKWMBuhUKDoIS7Xai1Va5m+RPkm1x5dxg0Gqpm7xYUDhc2qzJUNisCD9fVM57BLOMrgyCFF4UX1abrPHEOrhde0Dgm3MelhaH600aN002+GCxeqTopeERGn3gZRUwfFshjdCamHWtUSGMZwwyCFLqKjK5q2RpreV0jxd9UqORgQV2kikEioiP/iUGj5kb078HJ9PBR6HD8iTP0pXs8TiKyLCsxXC4HWWntnJqyPR6byME3tj2eTCWnx5Oego6fzWd8BmctBCo1SLd60ezZBURkOxwJum8z08nO6ZCh6aLZs7sS+WIbu4m6zp59rFLB7NlFKegj8KkNtGd8++peMnic3QpMoQNl/mRX0gP8w+dLgXeVpgC3pqA1QFMk0hgFypgbVtxFRGTbtqX6mxxOpy1cD0xkVU4pxLJtUWVLqWQ5HRKH0yHXSP0i0iLbwd0JvMjf7pzLTpICfB3WOhG4nm1jpZqpbnenMiCcRUTuI687rQ8RDfD7D43p6/dnx0wru9Cv5i8rK2OnUQV+f4Z72oWswe/vRx0vnOZm3NPKTmE1/fx+/uc85BG7+GcpPh38hWgl/yDyF+AgIupzYZnfzV0bC/eTz51iJhBZ7T9B27lEM77ZUberelEhzQmFniCiH0J7cmlgVbiuNlRVILMWhWrra6tfsolKQ6FXtoT3VN8WEwotW7RtT/ibsST6w/W7qxd5iN4JhYj9udE0OhR6vCq0WHoFb0RLBjXhZ3xHHVvws0XWS9V7GkJbSpj134RrQ4vSrBQzUfr8awGN/BVoAZo2OXoDW4iKgVUOz0dgNVUFkheaWMe+R9gnhhF23TNABDS1AcBnuTRC6l/nonVAzDpgEk0C9qr+61YlMK4LcBf2px8J3EX0wj5gN/BngCZK2zQ9QqnofOAtegyo8I/bDJxsf4WWoTQfuIxKgXfG+R8FSrlhEdReMu2mKGq9IgSvXrIG+FzA9ktuqgZOo5fk/pliL3m7iQAW3XSOZDZQVoJoMeC/HSgW6+w4etgFwOc8UGxT60tFlwKrKAQ8EJi1DHidrgYup1Vo6EyLgddnBZ4AfuLmAEtsyvscOEMo72cXA21C9Fg77wngNaqV+5+Pq3poXpakM7DoLnye0YwLNqI+Q6zz81mnztuHth4x64baxb8Bk1PRE8DTBGBHQ0Mt8An1imBJVj3+SvQjsLehIQKAuwm4mNiB5jZhHBHVAB2JX+Y8BthEAMKs/9O41pJqfkdoCR6nb/BmHVaTWKe2vmEvgKniV4joBeCclMJvQvePwLnCZ8HgumXL7iFah9qzgFlE24Dvg8H1y5at5G4EzuYvZtcKE/gl9x4xG2OOBCqFIOu/V7CIVkmeVnoQ2IKL6CnUsU/gbgTCm4ObVyxbPiTm7phngPNSzPGdOhWeBvHs2wuc063bhJKSCUTnAj9iby7RUuDGbj5/SckM7gqgMs+RXwWcLlyanj4MaKSYUL4j7yngAWoETvR1m1JSMobWAv3Tu34muVppGgAMpDkAWgcQzQeCfX19Tyo5JSdmYydHp9+AYSnmvfLylwG8RvQ0sKpv3+eBcqL8JgDPEtF9bfikr/dm4DVuRCMaF4y9Hag/RPjtiJkbgFUC7hi7YD9aj6MVwBpv3/eA22gp8NLMJZBcr+SOAlF+LX07EU3ZD0z1Tm3FnsKJACrGlgP1mamFTVtzjZdoTFMriwhlSlcdZxDRoTU8Zn9/6S96tZmlNt9OAouKziCSElq/z6LRTTwh1J4ubmGNWuhj4BMiagWeYMdxaZ0yimmRNkslm7iaio4WkV0cZBF+ix/IGx0xVh8ec4pNN7PjR34FU+FiXq4BGi90CF9VAgj2scie/r0Q9FvUgbVUiODJwM1q84FHY4LAicIhtzcCaLzdKQIra9hmKeUQHxtvjsXOM/PHBgJjvWzxTJ+vgKU58gcGAkd43UTZ7CN9KyfWEfDlEDPTOzZQkEHCug6+wNh8BxGldxT9+S4iq8PAgC8/RwS38/my1bJ8vtyYfB8/g7c8BYFAoMBDIrCDd2BgYA6l9DgyMx2a7+TjdmQSceNjqUTMGqJMh06/4QuM1jqK3L+pcwu/HiAJ0t/xOWvt2iGytWsf+Huu8/jxObLx4wfTf+YMAQBWUDggUAUAADAbAJ0BKgkBRgA+kUSaSiW/v6Iklqzr8BIJQxPk+Ahr5h9y5t/YNca+Pga+YBzvPMB+tnrJegr0AP97/VfWW9VT0APLl9kb+64Ky+uNogZGsiGf+Pp7kdLmlZh/a+Lk3LqFajQFfnoeu49T6tArn8bvyzGYfdpcXAGidk0hnVH0FgQcHuiTOySTZJ2PYt+4f36EHeo02rhqStNsTkwUulX4ySXdTi/LJzoWRosEEAcM+8AzrQATJyNZ38HXm0UyZjHTaPu6idzIkkKASlJ2UMmSnpCbyMSSiv5jGMYxjGMYx04A/vhGv//1CspL9N35JjMUKkP69AAej+0xn/9RY5QFAewi0WIM/gLxZodrK9EzOXsiUzwpweZlJPa8iY2xCgjc1KcRlgv3jgQF6Gp0jR/BSFYjXP8H0V8v6bjyfMC+JwKiM25tnEByYSNX2B96ek3wOXYe+zzZYeWWsGovryhxiNueZ3QubkJlN+MrbvQxYR+1zUpxwH2uIVGEJ/Yv9wzq8VFxz+Bz5ETwH30sF4f/bIfJXfh7EmYJikBesh4bBvxbEjXbs/esZ+YA6o3LnpBXrJmnrbVvoyjWADrCRBSEQ4D2Aqu5/EDeYZMiZ/zthngRSa3emkVUkQQRAwITcsLwwe/Y7RQnBmLqpaYdm5p5ozkOR1grRL7mUAsHn8f24as0wVz0sHqvBLtdUwtQ18os0V0E8aA0TwlSOxtftjIzlWRB7pYTov8w84r2kgXTx58QngA603dD0t3mE7hSsVAqKv+FMAvoAxqL/GTLXBdDVd/kTpIf/7Rwt3OTz4bm1DJc/iqvNMOWbQyOmi6MI5Ci5yM0qOwyn1gLA7YiwOWj/GCIwR44j+1Oyauj3DtzoaqYh2gQ4/pR9l5uPnKYJ8BUBj7Edc68OBy/HS5xTd2JH8e4lLkcY7oPAq5PM8D9cSRiho0AscfH/HZOpeoSMijyDxLZkBa+ETMSoccgV3b7eYRQixHDBTu99mNwaxmIfPJ1M3wG9NzfKlbJPl9sIitNRLnKUn0VBzlzn2R9t4ATohCzIg0LrRRxP14jlJBp/X2vHdDBhAmZqqgOfzOwYQ450L2DeOCrElvLDQHHyGLoxtcMKz6xpRdcd/Vf5j7w+dpJNyb8u4TFAi13QVUeZjtYwWfiBmYEwc8jURHnlBWpX8gp6J9FkIEEzAvuPaqs7NCHy24QVDtt/v+GOzURkLzpKqcULo+XR4miPl6gLpJNfw9gYG+8ROoe8J+Zr4AF+il1dsMi5/tkeI7flN4XuFH5ENrTcJu9npqf9zqyMZ/7hiSJomOXc/0pvIWzjY+18+uPf7tOCj80zPzVRpw3w/SWCAPhRLcA9AtTK4cksdZpmh5fw1S+iyQ4qOFOiOTOtnsJH4i/rSTR2JkvQxlsHnYz4Fqm+FzrgO+weoxGuc7Rt4YWk3vLRP4EadrlLmRZURIvGFEY4P3nmW6mK6ceL2lb+snhSxHoqUw1YXlgHB4OkG+hLsXYm6m/JxOO/6d7XUAZakrN+/ZiVxYP5FSaGPvr3Vjnp0L6aNrmoPpHzf0xQVlHglOsLoR+4LWXYq58711FC5ba2qCtMcDpcWbSMZVrCqhH9JRnvkVcXuSzPX/yWliOn+mnp8hgkr1XAch/T29wRciYAG6nfSv1pkrXnmRar2GocOAEbaTg+6jIJe97v+aOv1eEqonj8iPM+woINUZuJ9//HGMOZAgcm8ThfjjM5SYpP6n83P5hJ/YnpAa7cTqHpEGSftLgdGBfv1HNf1pFygAAAAAAAAAAAAlV0rYgga4pFnjex7gAAAAAAAA="></center>
    </div>
    
    <!-- Lien vers le site personnalisé de l'auteur -->
    <center style="font-size:12px"><i><a href="https://thierrylaval.dev">Par thierrylaval.dev</a></i></center>
    <br>
    <div class="card border-secondary"><div class="card-body"><center><span style="font-size:17px">Ce script permet de réaliser un audit de sécurité rapide sur un site PrestaShop en analysant automatiquement les fichiers afin de détecter ceux qui présentent des signes suspects ou des modifications anormales. Il identifie notamment les fichiers récemment modifiés, les emplacements inhabituels ou les fragments de code potentiellement malveillants. Les résultats fournis incluent des informations contextuelles comme le chemin complet, la date de modification et des éléments techniques utiles pour faciliter l’analyse. Cela permet d’orienter efficacement les vérifications et d’accélérer la prise de décision avant toute action corrective.</span></center></div></div>
    <br>
    <!-- Informations supplémentaires -->
    <div class="mb-4">
        <ul>
            <li><strong>Version du script :</strong> <?php echo htmlspecialchars($version); ?></li>
            <li><strong>Version de PrestaShop :</strong> <?php echo htmlspecialchars($prestashop_version); ?></li>
            <li><strong>Version de PHP :</strong> <?php echo htmlspecialchars($php_version); ?></li>
            <li><strong>Limite de mémoire :</strong> <?php echo htmlspecialchars($memory_limit); ?></li>
            <li><strong>Racine analysée :</strong> <code><?php echo htmlspecialchars($root_path); ?></code></li>
        </ul>
    </div>
    <?php if (empty($prestashop_root_detected)): ?>
    <div class="alert alert-danger">
        <strong>⚠️ Racine PrestaShop non détectée :</strong> aucun fichier marqueur PrestaShop
        (<code>config/config.inc.php</code>, <code>src/Core/Version.php</code>, <code>app/AppKernel.php</code>, etc.)
        n'a été trouvé. Le scan a été effectué dans <code><?php echo htmlspecialchars($root_path); ?></code>.
        Les résultats peuvent être incomplets ou non pertinents : déplacez ce script à la racine de votre
        installation PrestaShop puis relancez-le.
    </div>
    <?php endif; ?>
    <!-- Audit de la configuration PHP : affichage détaillé des directives et extensions -->
    <?php
    $php_issues = audit_php_configuration();
    if (!empty($php_issues)) {
        echo '<div class="alert alert-warning">';
        echo '<strong>Observations sur la configuration PHP :</strong><ul>';
        foreach ($php_issues as $issue) {
            echo '<li>' . htmlspecialchars($issue) . '</li>';
        }
        echo '</ul></div>';
    } else {
        echo '<div class="alert alert-success">La configuration PHP semble conforme aux recommandations de PrestaShop.</div>';
    }
    ?>
    <hr>
    <div class="card">
        <div class="card-header bg-primary text-white">
            Résultat du scan
        </div>
        <div class="card-body">
            <?php if (!empty($infected_files)): ?>
                <!-- ALERTE si des fichiers infectés trouvés -->
                <div class="alert alert-danger" role="alert">
                    <strong>Attention !</strong> Des fichiers potentiellement infectés ou suspects ont été trouvés :
                </div>

<!-- =====================================================================
RÉSUMÉ STATISTIQUE - ONGLETS DE SÉVÉRITÉ
=====================================================================
    Les 3 catégories (critiques, avertissements, informations) sont présentées
    sous forme d'onglets cliquables. Chaque onglet affiche le compteur ET la
    liste des fichiers concernés (voir plus bas la zone de contenu des onglets).

    Couleurs :
    - bg-danger : critique (rouge)
    - bg-warning : avertissement (orange/jaune)
    - bg-info : information (bleu clair)
===================================================================== -->
                <?php
                $stats = get_statistics($infected_files);
                // Regroupement des fichiers par sévérité (la plus grave du fichier).
                $grouped_files = group_by_file($infected_files);
                $groups_by_severity = ['critical' => [], 'warning' => [], 'info' => []];
                foreach ($grouped_files as $g) {
                    $sev = $g['severity'] ?? 'info';
                    if (isset($groups_by_severity[$sev])) $groups_by_severity[$sev][] = $g;
                }
                // Métadonnées d'affichage des onglets.
                $tabs_meta = [
                    'critical' => ['label' => 'Issues Critiques', 'badge' => 'bg-danger',  'tab' => 'tab-critical'],
                    'warning'  => ['label' => 'Avertissements',  'badge' => 'bg-warning text-dark', 'tab' => 'tab-warning'],
                    'info'     => ['label' => 'Informations',    'badge' => 'bg-info text-dark',    'tab' => 'tab-info'],
                ];
                // Onglet actif par défaut : le plus grave qui contient des résultats.
                $active_tab = 'critical';
                if ($stats['critical'] === 0) {
                    $active_tab = $stats['warning'] > 0 ? 'warning' : ($stats['info'] > 0 ? 'info' : 'critical');
                }
                ?>
                <ul class="nav nav-pills nav-fill mb-3" id="severityTabs" role="tablist">
                    <?php foreach ($tabs_meta as $sev => $meta): ?>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link <?php echo $active_tab === $sev ? 'active' : ''; ?>"
                                id="<?php echo $meta['tab']; ?>-tab"
                                data-bs-toggle="tab"
                                data-bs-target="#<?php echo $meta['tab']; ?>"
                                type="button" role="tab"
                                aria-controls="<?php echo $meta['tab']; ?>"
                                aria-selected="<?php echo $active_tab === $sev ? 'true' : 'false'; ?>">
                            <span class="badge <?php echo $meta['badge']; ?>"><?php echo $stats[$sev]; ?></span>
                            <?php echo htmlspecialchars($meta['label']); ?>
                        </button>
                    </li>
                    <?php endforeach; ?>
                </ul>

<!-- =====================================================================
BOUTONS D'EXPORT DES RAPPORTS
=====================================================================
    Permet à l'utilisateur de télécharger les résultats complets du scan
    dans deux formats différents :
    - CSV (valeurs séparées par des points-virgules)
    - JSON (format structuré pour intégration API)
===================================================================== -->
                <div class="mb-3">
                    <a href="?export_csv=1" class="btn btn-warning">📥 Télécharger le rapport CSV</a>
                    <a href="?export_json=1" class="btn btn-info">📥 Télécharger le rapport JSON</a>
                    <?php
                    // Bouton de correction des permissions : affiché uniquement si
                    // le scan a détecté au moins un problème de permissions.
                    $has_perm_issues = false;
                    foreach ($infected_files as $e) {
                        if (strpos($e['pattern'] ?? '', 'PERMISSIONS') === 0) { $has_perm_issues = true; break; }
                    }
                    if ($has_perm_issues):
                    ?>
                    <a href="?fix_permissions=1" class="btn btn-danger"
                       onclick="return confirm('Corriger les permissions des fichiers/dossiers signalés ?\n\nFichiers -> 0644 (rw-r--r--)\nDossiers -> 0755 (rwxr-xr-x)\n\nCette action modifie les droits sur le serveur.');">
                        🛠️ Corriger les permissions détectées
                    </a>
                    <?php endif; ?>
                </div>

<!-- =====================================================================
LISTE DES FICHIERS DÉTECTÉS
=====================================================================
    Affiche chaque fichier infecté dans une liste Bootstrap avec :
    - Code couleur de sévérité (bordure gauche)
    - Badge sévérité (CRITICAL, WARNING, INFO)
    - Détails du fichier (chemin, modif, hash MD5, ligne, motif)
    - Bouton pour afficher le contenu en modal
===================================================================== -->
                <?php $grouped_files = group_by_file($infected_files); ?>
                <!-- Zone de contenu des onglets : un panneau par sévérité.
                     Chaque panneau liste uniquement les fichiers de sa sévérité. -->
                <div class="tab-content" id="severityTabsContent">
                <?php foreach ($tabs_meta as $sev => $meta):
                    $sev_groups = $groups_by_severity[$sev];
                ?>
                <div class="tab-pane fade <?php echo $active_tab === $sev ? 'show active' : ''; ?>"
                     id="<?php echo $meta['tab']; ?>" role="tabpanel"
                     aria-labelledby="<?php echo $meta['tab']; ?>-tab" tabindex="0">

                    <?php if (empty($sev_groups)): ?>
                        <div class="alert alert-light border mb-3">
                            Aucun résultat dans cette catégorie.
                        </div>
                    <?php else: ?>
                    <ul class="list-group mb-3">
                    <?php foreach ($sev_groups as $gindex => $group):
                        // ID unique par onglet + index (évite les collisions de modales).
                        $index = $sev . '-' . $gindex;
                        // Détermine la couleur de la sévérité du groupe
                        $severity = $group['severity'] ?? 'info';
                        $badge_class = 'bg-secondary';
                        $border_class = '';
                        if ($severity === 'critical') { $badge_class = 'bg-danger'; $border_class = 'border-danger'; }
                        elseif ($severity === 'warning') { $badge_class = 'bg-warning text-dark'; $border_class = 'border-warning'; }
                        elseif ($severity === 'info') { $badge_class = 'bg-info text-dark'; $border_class = 'border-info'; }
                        $nb_matches = count($group['matches']);
                    ?>
                        <li class="list-group-item <?php echo $border_class; ?>" style="border-left-width: 5px;">
                            <!-- Badge sévérité + compteur de motifs -->
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span class="badge <?php echo $badge_class; ?> rounded-pill">
                                    <?php echo strtoupper($severity); ?>
                                </span>
                                <span class="badge bg-dark rounded-pill"><?php echo $nb_matches; ?> motif<?php echo $nb_matches > 1 ? 's' : ''; ?></span>
                            </div>

                            <!-- Détails du fichier-->
                            <strong>Fichier :</strong> <?php echo htmlspecialchars($group['file']); ?><br>
                            <strong>Dernière modif :</strong> <?php echo !empty($group['mtime']) ? date('d/m/Y H:i:s', $group['mtime']) : 'N/A'; ?><br>
                            <strong>Hash MD5 :</strong> <code><?php echo htmlspecialchars($group['md5']); ?></code><br>

                            <!-- Liste des motifs détectés dans ce fichier (avec leur propre sévérité) -->
                            <div class="mt-2">
                                <strong>Motifs détectés :</strong>
                                <ul class="mb-0">
                                <?php foreach ($group['matches'] as $m):
                                    $msev = $m['severity'] ?? 'info';
                                    $mcolor = $msev === 'critical' ? 'text-danger' : ($msev === 'warning' ? 'text-warning' : 'text-muted');
                                ?>
                                    <li>
                                        <code><?php echo htmlspecialchars($m['pattern']); ?></code>
                                        <span class="<?php echo $mcolor; ?>" style="font-weight:bold;">[<?php echo strtoupper($msev); ?>]</span>
                                        <?php if (!empty($m['line'])): ?><span class="text-muted">ligne <?php echo (int)$m['line']; ?></span><?php endif; ?>
                                        <?php
                                        if (strpos($m['pattern'], 'htaccess') !== false) {
                                            $expl = '';
                                            if (strpos($m['pattern'], 'htaccess_redirect_malware') !== false) {
                                                $expl = 'Ce .htaccess contient une règle de redirection vers un domaine externe malveillant.';
                                            } elseif (strpos($m['pattern'], 'htaccess_php_execution') !== false) {
                                                $expl = 'Ce .htaccess force l\'exécution de fichiers PHP dans un dossier sensible (backdoor).';
                                            } elseif (strpos($m['pattern'], 'htaccess_php_value_prepend') !== false) {
                                                $expl = 'Ce .htaccess utilise php_value auto_prepend/append pour charger un script potentiellement malicieux.';
                                            }
                                            if ($expl) {
                                                echo '<div class="alert alert-warning mt-1 mb-1"><strong>Note :</strong> ' . htmlspecialchars($expl) . '</div>';
                                            }
                                        }
                                        ?>
                                    </li>
                                <?php endforeach; ?>
                                </ul>
                            </div>

                            <!-- Bouton pour afficher les détails en modal -->
                            <button type="button" class="btn btn-info mt-2" data-bs-toggle="modal" data-bs-target="#modal-<?php echo $index; ?>">
                                Informations
                            </button>

<!-- =====================================================================
MODAL de détails - Affichage du contexte du fichier
=====================================================================
    Affiche le contexte de chaque motif détecté dans le fichier,
    avec numérotation des lignes pour faciliter l'analyse manuelle.
===================================================================== -->
                            <div class="modal fade" id="modal-<?php echo $index; ?>" tabindex="-1" aria-labelledby="modalLabel-<?php echo $index; ?>" aria-hidden="true">
                                <div class="modal-dialog modal-xl">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="modalLabel-<?php echo $index; ?>">Détails du fichier : <?php echo htmlspecialchars($group['file']); ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <?php foreach ($group['matches'] as $m): ?>
                                                <h6 class="mt-2"><code><?php echo htmlspecialchars($m['pattern']); ?></code> — <?php echo strtoupper($m['severity'] ?? 'info'); ?></h6>
                                                <pre><code><?php
                                                    foreach (($m['context'] ?? []) as $context_line_number => $context_line) {
                                                        $display_line_number = ($m['start_line'] ?? 1) + $context_line_number;
                                                        echo str_pad($display_line_number, 4, ' ', STR_PAD_LEFT) . " | " . htmlspecialchars($context_line) . "\n";
                                                    }
                                                ?></code></pre>
                                            <?php endforeach; ?>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Fermer</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </li>
                    <?php endforeach; // foreach des groupes de cette sévérité ?>
                    </ul>
                    <?php endif; // fin cas vide ?>

                </div>
                <?php endforeach; // foreach des onglets (sévérités) ?>
                </div><!-- /.tab-content -->
            <?php else: ?>
                <!-- Cas où aucun fichier infecté n'a été trouvé -->
                <div class="alert alert-success" role="alert">
                    ✅ Aucun fichier infecté n'a été trouvé. Votre site semble sain !
                </div>

                <!-- Résumé statistique avec tous les compteurs à 0 -->
                <?php $stats = get_statistics($infected_files); ?>
                <div class="row mb-4">
                    <!-- Carte des issues critiques (0) -->
                    <div class="col-md-4">
                        <div class="card text-center bg-danger text-white">
                            <div class="card-body">
                                <h5 class="card-title">Issues Critiques</h5>
                                <p class="card-text" style="font-size: 2rem;"><strong><?php echo $stats['critical']; ?></strong></p>
                            </div>
                        </div>
                    </div>

                    <!-- Carte des avertissements (0) -->
                    <div class="col-md-4">
                        <div class="card text-center bg-warning text-dark">
                            <div class="card-body">
                                <h5 class="card-title">Avertissements</h5>
                                <p class="card-text" style="font-size: 2rem;"><strong><?php echo $stats['warning']; ?></strong></p>
                            </div>
                        </div>
                    </div>

                    <!-- Carte des informations (0) -->
                    <div class="col-md-4">
                        <div class="card text-center bg-info text-dark">
                            <div class="card-body">
                                <h5 class="card-title">Informations</h5>
                                <p class="card-text" style="font-size: 2rem;"><strong><?php echo $stats['info']; ?></strong></p>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
<!-- =====================================================================
    PIED DE CARTE - Résumé du nombre total de fichiers scannés
    =====================================================================
    Affiche le nombre total de fichiers PHP/TPL/HTML/XML/JS scannés
    pour donner une indication de la couverture du scan.
===================================================================== -->
        <div class="card-footer">
            <p class="mb-0">Nombre total de fichiers PHP/TPL/HTML/XML/JS scannés : <strong><?php echo $total_php_files; ?></strong></p>
        </div>
    </div>

<!-- =====================================================================
    RAPPORT DE CORRECTION DES PERMISSIONS
    =====================================================================
    Affiché après un clic sur "Corriger les permissions". Placé HORS de la
    carte de résultats pour rester visible même si tous les problèmes de
    permissions ont été résolus (la liste des fichiers peut alors être vide).
===================================================================== -->
    <?php if ($permission_fix_report !== null): ?>
    <div class="card mt-4 border-<?php echo empty($permission_fix_report['fail']) ? 'success' : 'warning'; ?>">
        <div class="card-header bg-<?php echo empty($permission_fix_report['fail']) ? 'success' : 'warning'; ?> text-<?php echo empty($permission_fix_report['fail']) ? 'white' : 'dark'; ?>">
            🛠️ Rapport de correction des permissions
        </div>
        <div class="card-body">
            <ul class="mb-0">
                <?php foreach ($permission_fix_report['ok'] as $ok): ?>
                <li>✅ <code><?php echo htmlspecialchars($ok[0]); ?></code> — <?php echo htmlspecialchars($ok[1]); ?> → <strong><?php echo htmlspecialchars($ok[2]); ?></strong></li>
                <?php endforeach; ?>
                <?php foreach ($permission_fix_report['fail'] as $fail): ?>
                <li>❌ <code><?php echo htmlspecialchars($fail[0]); ?></code> — <?php echo htmlspecialchars($fail[1]); ?></li>
                <?php endforeach; ?>
                <?php if (empty($permission_fix_report['ok']) && empty($permission_fix_report['fail'])): ?>
                <li>Aucun problème de permissions à corriger.</li>
                <?php endif; ?>
            </ul>
            <?php if (!empty($permission_fix_report['fail'])): ?>
            <p class="mt-2 mb-0"><strong>Note :</strong> un échec vient souvent d'un hébergement mutualisé qui restreint <code>chmod</code>. Contactez votre hébergeur pour ajuster les droits manuellement.</p>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

<!-- =====================================================================
    SECTION DÉTECTION DES MODULES PHPUNIT
    =====================================================================
    Affiche les répertoires ou fichiers PHPUnit détectés dans les modules.
    PHPUnit laissé accessible est un risque car il expose la structure du code.
===================================================================== -->
    <?php
    $phpunit_detected = array_filter($infected_files, function($file) {
        return strpos($file['pattern'] ?? '', 'phpunit') !== false;
    });
    if (!empty($phpunit_detected)):
    ?>
    <div class="card mt-4 border-warning">
        <div class="card-header bg-warning text-dark">
            🔧 Répertoires ou Fichiers PHPUnit Détectés
        </div>
        <div class="card-body">
            <p><strong>Avertissement :</strong> PHPUnit laissé accessible expose les tests et la structure du code.</p>
            <ul class="list-group">
                <?php foreach ($phpunit_detected as $item): ?>
                <li class="list-group-item list-group-item-warning">
                    <strong>📁 <?php echo htmlspecialchars($item['file']); ?></strong><br>
                    <small>Détails : <?php echo htmlspecialchars($item['pattern']); ?></small>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <?php endif; ?>

<!-- =====================================================================
    SECTION AUDIT DES EN-TÊTES HTTP DE SÉCURITÉ (DÉTAILLÉ)
    =====================================================================
    Affiche les résultats de la vérification des en-têtes de sécurité HTTP
    avec tableau de synthèse et recommandations de correction.
===================================================================== -->
    <?php 
    // Définir les recommandations pour chaque en-tête
    $header_recommendations = [
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-Content-Type-Options' => 'nosniff',
        'Content-Security-Policy' => "default-src 'self'",
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'X-XSS-Protection' => '1; mode=block',
    ];
    ?>
    <?php if (!empty($header_issues)): ?>
    <div class="card mt-4">
        <div class="card-header bg-danger text-white">
            🔒 Audit des Headers HTTP de Sécurité — <?php echo count($header_issues); ?>/<?php echo count($header_recommendations); ?> En-têtes manquants
        </div>
        <div class="card-body">
            <div class="alert alert-warning">
                <strong>Avertissement :</strong> Ces recommandations renforcent la sécurité, mais certaines modifications peuvent impacter des fonctionnalités ou des modules (sessions, PDF, backups, intégrations externes). Sauvegardez `php.ini`, testez en staging et appliquez les changements progressivement.
            </div>
            <table class="table table-sm table-striped">
                <thead class="table-light">
                    <tr>
                        <th style="width: 25%">En-tête</th>
                        <th style="width: 20%">Valeur actuelle</th>
                        <th style="width: 55%">Recommandation</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($header_issues as $issue): ?>
                    <tr>
                        <td><strong>❌ <?php echo htmlspecialchars($issue['header']); ?></strong></td>
                        <td>
                            <?php
                            // Le statut réel est "Manquant" ou "Insuffisant" : on l'affiche
                            // correctement au lieu d'un "Absent" figé pour tous les cas.
                            $is_missing = ($issue['status'] ?? '') === 'Manquant';
                            $badge_class = $is_missing ? 'bg-secondary' : 'bg-warning text-dark';
                            ?>
                            <span class="badge <?php echo $badge_class; ?>"><?php echo htmlspecialchars($issue['status']); ?></span>
                            <?php if (!empty($issue['details'])): ?>
                            <div style="font-size: 12px; margin-top: 4px; color: #666;"><?php echo htmlspecialchars($issue['details']); ?></div>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php echo htmlspecialchars($header_recommendations[$issue['header']] ?? '…'); ?>
                            <div style="font-family: monospace; background: #f5f5f5; padding: 8px; margin-top: 5px; border-radius: 3px; font-size: 12px;">
                                Header always set <?php echo htmlspecialchars($issue['header']); ?> "<?php echo htmlspecialchars($header_recommendations[$issue['header']] ?? '…'); ?>"
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <div class="alert alert-info mt-3" role="alert">
                <strong>💡 Correctif .htaccess :</strong> Ajouter ces directives (la plupart des hébergeurs ont déjà <code>mod_headers</code> activé) :
                <pre style="background: #f0f0f0; padding: 10px; border-radius: 3px; overflow-x: auto; margin-top: 8px;">
                    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
                    Header always set X-Frame-Options "SAMEORIGIN"
                    Header always set X-Content-Type-Options "nosniff"
                    Header always set Referrer-Policy "strict-origin-when-cross-origin"
                    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
                    Header always set X-XSS-Protection "1; mode=block"</pre>
            </div>
        </div>
    </div>
    <?php else: ?>
    <div class="card mt-4">
        <div class="card-header bg-success text-white">
            🔒 Audit des Headers HTTP de Sécurité — ✅ Tous les headers recommandés sont présents
        </div>
    </div>
    <?php endif; ?>

    <!-- =====================================================================
        COMPARAISON EXTERNE - securityheaders.com (100% gratuit, sans compte)
        =====================================================================
        Bouton vers securityheaders.com pour confronter l'audit local des
        en-têtes HTTP à une analyse externe indépendante (note de A+ à F).
        Affiché dès qu'un domaine est détecté, que des en-têtes manquent ou non.
    ===================================================================== -->
    <?php if (!empty($securityHeadersUrl)): ?>
    <div class="mt-3 mb-2">
        <a class="btn btn-outline-secondary"
           href="<?php echo htmlspecialchars($securityHeadersUrl, ENT_QUOTES, 'UTF-8'); ?>"
           target="_blank" rel="noopener noreferrer">
            🔬 Comparer avec securityheaders.com
        </a>
        <small class="text-muted ms-2" style="font-size:12px;">
            Analyse externe indépendante des en-têtes de sécurité (note A+ à F).
        </small>
    </div>
    <?php endif; ?>

    <!-- =====================================================================
        SECTION SCAN YARA - Signatures composées
        =====================================================================
        Affiche le statut du scan YARA (moteur de détection par signatures).
        Si le binaire `yara` est absent, on l'indique sans bloquer le rapport.
    ===================================================================== -->
    <div class="card mt-4">
        <div class="card-header <?php echo !empty($yara_report['available']) ? 'bg-secondary text-white' : 'bg-light'; ?>">
            🧬 Scan YARA (signatures de malwares)
        </div>
        <div class="card-body">
            <?php if (!empty($yara_report['available'])): ?>
                <p class="mb-1">
                    <strong>Moteur YARA actif</strong>
                    <?php if (!empty($yara_report['version'])): ?>
                        <span class="text-muted">(version <?php echo htmlspecialchars($yara_report['version']); ?>)</span>
                    <?php endif; ?>
                </p>
                <p class="mb-0">
                    Détections YARA : <strong><?php echo (int) $yara_report['matches']; ?></strong>.
                    <?php if ((int) $yara_report['matches'] > 0): ?>
                        Elles apparaissent dans la liste ci-dessus avec le préfixe <code>YARA :</code>.
                    <?php else: ?>
                        Aucune signature YARA déclenchée.
                    <?php endif; ?>
                </p>
            <?php else: ?>
                <p class="mb-1 text-muted">
                    Scan YARA non disponible : <?php echo htmlspecialchars($yara_report['error'] ?? 'inconnu'); ?>.
                </p>
                <p class="mb-0" style="font-size:13px;">
                    Pour l'activer, installez le moteur YARA sur le serveur (<code>yara</code>),
                    puis relancez le scan. Les règles par défaut se trouvent dans
                    <code>rules/prestashop.yar</code>.
                </p>
            <?php endif; ?>
        </div>
    </div>

<!-- =====================================================================
    SECTION AUDIT DE LA CONFIGURATION PHP (DÉTAILLÉ)
    =====================================================================
    Affiche un tableau détaillé des directives PHP et extensions critiques
    pour la sécurité dans un environnement PrestaShop.
===================================================================== -->
    <div class="card mt-4">
        <div class="card-header bg-info text-white">
            ⚙️ Audit de la Configuration PHP
        </div>
        <div class="card-body">
            <table class="table table-sm table-striped">
                <thead class="table-light">
                    <tr>
                        <th style="width: 30%">Directive</th>
                        <th style="width: 20%">Valeur actuelle</th>
                        <th style="width: 50%">Recommandation</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $php_directives = [
                        'allow_url_fopen' => [
                            'raison' => 'Permet la lecture de fichiers distants via fopen("http://..."). Un attaquant pourrait inclure du code malveillant distant.',
                            'details' => 'Doit être Off en production. Vérifiez si une extension PHP l\'utilise.'
                        ],
                        'allow_url_include' => [
                            'raison' => 'Permet d\'inclure des fichiers distants via include/require. TRÈS DANGEREUX.',
                            'details' => 'Doit TOUJOURS être Off. Exécution de code distant si activé.'
                        ],
                        'expose_php' => [
                            'raison' => 'Expose votre version PHP dans l\'en-tête X-Powered-By. Les attaquants l\'exploitent.',
                            'details' => 'Doit être Off pour masquer votre version.'
                        ],
                        'display_errors' => [
                            'raison' => 'Affiche les erreurs PHP à l\'écran = révèle chemins, structure DB, code interne.',
                            'details' => 'Doit être Off. Loggez plutôt dans un fichier avec error_reporting et log_errors.'
                        ],
                        'session.cookie_httponly' => [
                            'raison' => 'Interdit à JavaScript d\'accéder aux cookies de session (protection contre XSS).',
                            'details' => 'Doit être On pour empêcher le vol de session par scripts malveillants.'
                        ],
                        'session.cookie_secure' => [
                            'raison' => 'Force l\'envoi des cookies UNIQUEMENT via HTTPS (prévient l\'interception).',
                            'details' => 'Doit être On si votre site est en HTTPS (très recommandé).'
                        ],
                        'open_basedir' => [
                            'raison' => 'Limite l\'accès PHP à un répertoire spécifique (bac à sable).',
                            'details' => 'Exemple : "/var/www/prestashop:/tmp". Si non défini, PHP peut accéder à tout le filesystem.'
                        ],
                        'disable_functions' => [
                            'raison' => 'Désactive les fonctions d\'exécution système (exec, shell_exec, etc.).',
                            'details' => 'Empêche un attaquant d\'exécuter du code shell. Au minimum : exec, shell_exec.'
                        ],
                    ];
                    
                    foreach ($php_directives as $directive => $info) {
                        $current = ini_get($directive);
                        $raw_current = $current;
                        if ($current === false) { $current = '(non défini)'; }
                        
                        // Déterminer la valeur recommandée et le statut
                        $recommended = '';
                        if ($directive === 'allow_url_fopen' || $directive === 'allow_url_include' || 
                            $directive === 'expose_php' || $directive === 'display_errors') {
                            $recommended = 'Off';
                            $status = (strtolower($raw_current) === 'off' || $raw_current === '' || $raw_current === '0') ? '✅' : '❌';
                        } elseif ($directive === 'session.cookie_httponly' || $directive === 'session.cookie_secure') {
                            $recommended = 'On (1)';
                            $status = (strtolower($raw_current) === 'on' || $raw_current === '1') ? '✅' : '❌';
                        } elseif ($directive === 'open_basedir') {
                            $recommended = 'Configuré';
                            $status = (!empty($raw_current) && $raw_current !== false) ? '✅' : '❌';
                        } elseif ($directive === 'disable_functions') {
                            $recommended = 'Configuré';
                            $status = (!empty($raw_current) && $raw_current !== false) ? '✅' : '❌';
                        } else {
                            $status = '❓';
                        }
                    ?>
                    <tr>
                        <td><strong><?php echo htmlspecialchars($directive); ?></strong><br><span style="font-size: 12px; color: #666;">Recommandé : <code><?php echo htmlspecialchars($recommended); ?></code></span></td>
                        <td><code style="background: #f5f5f5; padding: 4px 6px;"><?php echo htmlspecialchars($current); ?></code><br><span style="font-size: 12px; margin-top: 4px; display: inline-block;"><?php echo $status; ?> <?php echo ($status === '✅') ? '<span style="color: green; font-weight: bold;">OK</span>' : (($status === '❌') ? '<span style="color: red; font-weight: bold;">À corriger</span>' : ''); ?></span></td>
                        <td>
                            <div style="margin-bottom: 8px;"><?php echo htmlspecialchars($info['raison']); ?></div>
                            <div style="background: #fffbea; padding: 8px; border-left: 3px solid #ff9900; border-radius: 3px; font-size: 13px;">
                                <strong>💡 Détails :</strong> <?php echo htmlspecialchars($info['details']); ?>
                            </div>
                        </td>
                    </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
    </div>

<!-- =====================================================================
    SECTION SCAN EXTERNE - Sucuri SiteCheck + urlscan.io
    =====================================================================
    Génère des liens vers des services de scan externe pour une seconde opinion
    sur la sécurité du site. Cette section n'apparaît que si un domaine valide
    est détecté (présent dans $_SERVER['HTTP_HOST']).

    Les deux services sont 100% gratuits et ne nécessitent ni compte ni clé API :
    - Sucuri SiteCheck : réputation du domaine, malwares connus
    - urlscan.io        : analyse live dans un navigateur, requêtes sortantes
===================================================================== -->
    <?php if (!empty($sucuriUrl) || !empty($urlscanUrl)): ?>
    <div class="card mt-4">
        <div class="card-header">
            🦠 Scans externes gratuits (seconde opinion)
        </div>
        <div class="card-body">
            <p class="text-muted" style="font-size:13px;">
                Ces services analysent votre site depuis l'extérieur. Aucun compte requis, 100% gratuit.
            </p>
            <?php if (!empty($sucuriUrl)): ?>
            <!-- Lien externe vers Sucuri (ouverture dans un nouvel onglet) -->
            <a class="btn btn-outline-primary" href="<?php echo htmlspecialchars($sucuriUrl, ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener noreferrer">
                🛡️ Ouvrir le rapport Sucuri
            </a>
            <?php endif; ?>
            <?php if (!empty($urlscanUrl)): ?>
            <!-- Lien externe vers urlscan.io (100% gratuit, sans compte) -->
            <a class="btn btn-outline-dark" href="<?php echo htmlspecialchars($urlscanUrl, ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener noreferrer">
                🔎 Analyser avec urlscan.io
            </a>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

</div>

</body>
</html>

<!-- =====================================================================
    CARTOUCHE EXPLICATIF FINAL - CONSEILS ET VÉRIFICATIONS
===================================================================== -->
<div class="container mt-4 mb-5">
    <div class="card border-secondary">
        <div class="card-header bg-light">
            ⚠️ Conseils de vérification après scan
        </div>
        <div class="card-body">
            <p>Rien ne garantit qu’un scan détecte 100% des menaces. Voici les vérifications complémentaires à effectuer et les bonnes pratiques en cas de suspicion :</p>
            <ul>
                <li><strong>Comparer l’intégrité :</strong> comparez les hash (MD5/SHA) des fichiers avec une copie propre de la même version de PrestaShop.</li>
                <li><strong>Fichiers récents :</strong> listez les fichiers modifiés récemment. <code>-mtime</code> raisonne en jours entiers (24h glissantes) et <strong>excluez les dossiers de cache/logs</strong> qui changent en permanence, sinon la liste est noyée de faux résultats :
                    <pre><code>find /chemin/vers/site -type f -mtime -30 -print \
  -not -path "*/var/cache/*" -not -path "*/var/logs/*" -not -path "*/img/tmp/*"</code></pre>
                </li>
                <li><strong>PHP dans uploads :</strong> vérifiez qu’aucun fichier PHP ne se trouve dans les répertoires d’upload publics.</li>
                <li><strong>Extensions trompeuses :</strong> cherchez les fichiers PHP déguisés — double extension (<code>.php.jpg</code>), variantes (<code>.php5</code>, <code>.php7</code>, <code>.phtml</code>, <code>.phar</code>) — fréquemment utilisées pour contourner les filtres :
                    <pre><code>find /chemin/vers/site -type f \( -name "*.php.*" -o -name "*.phtml" -o -name "*.phar" -o -name "*.php[0-9]" \)</code></pre>
                </li>
                <li><strong>Droits et permissions :</strong> détectez les fichiers world‑writable. <em>Syntaxe GNU/Linux</em> (serveur) :
                    <pre><code>find /chemin/vers/site -type f -perm /o+w -ls</code></pre>
                    <em>Sur macOS/BSD</em>, le préfixe est <code>+</code> et non <code>/</code> : <code>find ... -perm +o+w</code>.
                </li>
                <li><strong>.htaccess :</strong> recherchez les directives suspectes : <code>auto_prepend_file</code>, <code>auto_append_file</code>, <code>AddHandler</code>, <code>SetHandler</code>, <code>RewriteRule</code>, <code>&lt;FilesMatch&gt;</code>, <code>AddType</code> — mais aussi <strong><code>ErrorDocument</code></strong> (ex. <code>ErrorDocument 404 /malveillant.php</code>), vecteur de backdoor très courant et souvent oublié.</li>
                <li><strong>.user.ini :</strong> équivalent PHP-FPM du <code>.htaccess</code>, à vérifier au même titre (il peut redéfinir <code>auto_prepend_file</code>). Souvent oublié dans les audits.</li>
                <li><strong>Crons :</strong> vérifiez les tâches planifiées pour des exécutions inattendues (<code>crontab -l</code> et crontabs des comptes système), ainsi que les tâches ponctuelles avec <code>atq</code>.</li>
                <li><strong>Processus &amp; connexions :</strong> surveillez les processus PHP/serveur et connexions réseau inhabituelles (ex. <code>ps aux</code>, <code>ss -tup</code>).</li>
                <li><strong>Logs :</strong> analysez <code>error_log</code>, <code>access_log</code> et les logs d’application autour des dates suspectes.</li>
                <li><strong>Base de données :</strong> au‑delà des comptes admin inconnus, vérifiez surtout :
                    <ul>
                        <li><code>ps_configuration</code> : valeurs contenant du <strong>code JS/iframe injecté</strong> (les skimmers « stockés » en base sont invisibles dans les fichiers) ;</li>
                        <li><code>ps_employee</code> : comptes admin inconnus, comptes désactivés, dates de dernière modification de mot de passe (<code>last_passwd_gen</code>) ;</li>
                        <li><code>ps_module</code> / <code>ps_hook_module</code> : modules fantômes ou greffés sur des hooks inattendus.</li>
                    </ul>
                </li>
                <li><strong>Backups exposés :</strong> vérifiez qu’aucun fichier de sauvegarde (<code>*.sql</code>, <code>*.zip</code>, <code>*.tar.gz</code>, <code>*.bak</code>) n’est accessible en HTTP.</li>
                <li><strong>Modules exposés :</strong> supprimez PHPUnit, outils de dev ou autres consoles présentes en production.</li>
                <li><strong>Scan externe / antivirus :</strong> lancez un scan Sucuri/urlscan.io/antivirus/YARA pour une seconde opinion.</li>
            </ul>

            <h6>Procédure si compromission suspectée</h6>
            <ol>
                <li>Isoler la plateforme (mode maintenance / couper l’accès public).</li>
                <li>Prendre un snapshot + sauvegarde complète (fichiers + base).</li>
                <li><strong>Identifier et corriger l’origine</strong> (module vulnérable, compte compromis, faille d’injection). C’est l’étape prioritaire : sans elle, l’attaquant revient.</li>
                <li>Restaurer depuis un backup propre si possible ; sinon lancer une analyse forensique.</li>
                <li><strong>Changer tous les secrets APRÈS avoir corrigé la faille</strong> : mots de passe (FTP, SSH, DB, admin) <strong>et clés API</strong> (webservice PrestaShop). Les changer avant la correction est inutile : la faille encore active permettrait de les re‑compromettre.</li>
                <li>Vérifier que la remise en production est propre (re‑scanner, tester), puis surveiller les logs.</li>
            </ol>

            <hr>
            <h6>⚙️ Avertissement spécifique — Audit de la Configuration PHP</h6>
            <p>Les recommandations affichées dans la section <strong>Audit de la Configuration PHP</strong> renforcent la sécurité, mais certaines valeurs peuvent impacter des fonctionnalités légitimes (PDF, conversions, intégrations externes, sessions). Avant toute modification :</p>
            <ul>
                <li>Sauvegardez le <code>php.ini</code> et les configurations de pool PHP-FPM.</li>
                <li>Testez chaque changement dans un environnement de staging identique.</li>
                <li>Appliquez les modifications progressivement et surveillez les logs (PHP/Apache/Nginx).</li>
                <li>Pour <code>session.cookie_secure</code>, n’activez que si le site est en HTTPS.</li>
                <li>Pour <code>open_basedir</code>, notez qu’il est <strong>souvent déjà restreint par l’hébergeur</strong> (surtout en mutualisé) : inutile de le redéfinir vous‑même si c’est le cas.</li>
                <li>Pour <code>disable_functions</code>, veillez à inclure tous les chemins/fonctions nécessaires aux modules utilisés : désactiver <code>exec</code> peut casser des modules légitimes (génération PDF, traitement d’images).</li>
            </ul>
            <p><strong>En cas de doute :</strong> ne changez rien en production sans test ; contactez votre hébergeur ou un prestataire sécurité.</p>
        </div>
    </div>
</div>
