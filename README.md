# PrestaShop Security Scanner

Scanner de sécurité pour PrestaShop — audit automatique des fichiers, de la
configuration et des en-têtes HTTP.

**Version :** 2.0.1
**Auteur :** [Thierry Laval](https://thierrylaval.dev/)
**Licence :** Academic Free License (AFL 3.0)

---

## Présentation

Ce script effectue un audit de sécurité complet sur une installation
PrestaShop. Il analyse les fichiers afin de détecter ceux qui présentent des
signes suspects ou des modifications anormales, et vérifie plusieurs aspects de
la configuration du serveur.

### Fonctionnalités

- **Scan récursif** des répertoires critiques (`classes`, `modules`, `themes`,
  `override`, `img`, `upload`, etc.)
- **150+ motifs malveillants** (backdoors, web shells, skimmers de carte
  bancaire, code obfusqué, injections…)
- **Détection de PHP dans les dossiers média** (`img/`, `upload/`, `download/`)
- **Vérification des permissions** dangereuses (World Writable, 777)
  + correction automatique en un clic (fichiers `0644`, dossiers `0755`)
- **Audit des en-têtes HTTP de sécurité** (HSTS, CSP, X-Frame-Options…)
- **Audit de la configuration PHP** (directives sensibles + extensions requises)
- **Détection des versions vulnérables** de PrestaShop
- **Détection des fichiers modifiés récemment** (signal fort de compromission)
- **Détection de PHPUnit** exposé dans les modules
- **Analyse du `.htaccess`** racine (redirections, handlers PHP, prepend)
- **Export des résultats** en CSV et JSON
- **Scans externes gratuits** (Sucuri SiteCheck, urlscan.io, securityheaders.com)
- **Scan YARA** (signatures composées de malwares, optionnel)
- **Interface web responsive** (Bootstrap 5) **et** **mode ligne de commande**

---

## Installation

Aucune dépendance externe n'est requise. PHP 7.4+ (testé jusqu'à PHP 8.5).

1. Copiez `scanner.php` **à la racine** de votre installation PrestaShop.
2. Ouvrez-le dans votre navigateur : `https://votre-site.com/scanner.php`.

> ⚠️ **Sécurité :** supprimez le fichier `scanner.php` du serveur une fois
> l'audit terminé. Ne le laissez jamais accessible publiquement de façon
> permanente.

### Prérequis recommandés

- Extension PHP `curl` (pour l'audit des en-têtes HTTP)
- Extensions PrestaShop : `zip`, `gd`, `openssl`, `pdo_mysql`

---

## Utilisation — Interface web

Ouvrez simplement `scanner.php` dans un navigateur. Le rapport affiche :

- un résumé statistique (critiques / avertissements / infos) ;
- la liste des fichiers suspects, groupés par fichier, avec le contexte de code
  (numéro de ligne, extrait, hash MD5, date de modification) ;
- les boutons d'export **CSV** et **JSON** ;
- un bouton **« Corriger les permissions détectées »** (si applicable) ;
- l'audit des en-têtes HTTP et de la configuration PHP ;
- des liens vers les **scans externes gratuits** (Sucuri, urlscan.io).

---

## Utilisation — Ligne de commande (CLI)

Le script détecte automatiquement le mode CLI. Idéal pour un cron ou une CI.

```bash
php scanner.php [options]
```

### Options

| Option             | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `--path=<dossier>` | Racine PrestaShop à analyser (défaut : auto-détection) |
| `--yara=<fichier>` | Fichier de règles YARA (défaut : `rules/prestashop.yar`)|
| `--json`           | Sortie au format JSON                                  |
| `--csv`            | Sortie au format CSV                                         |
| `--quiet`          | N'affiche que le résumé (pas le détail des fichiers)         |
| `--no-color`       | Désactive les couleurs ANSI                                  |
| `--help`           | Affiche l'aide                                               |

### Exemples

```bash
# Rapport texte complet
php scanner.php --path=/var/www/prestashop

# Résumé seul (parfait pour un cron)
php scanner.php --path=/var/www/prestashop --quiet

# Exports
php scanner.php --path=/var/www/prestashop --json > rapport.json
php scanner.php --path=/var/www/prestashop --csv  > rapport.csv

# Scan YARA avec des règles personnalisées
php scanner.php --path=/var/www/prestashop --yara=/chemin/mes-regles.yar
```

### Codes de sortie (intégration CI / cron)

| Code | Signification                          |
|------|----------------------------------------|
| `0`  | Aucun problème détecté                 |
| `1`  | Avertissements présents                |
| `2`  | Problèmes **critiques** présents       |
| `3`  | Erreur d'argument (ex. `--path` invalide) |

---

## Scans externes gratuits

Le rapport propose des liens vers deux services **100 % gratuits**, sans compte
ni clé API, pour une seconde opinion :

- **[Sucuri SiteCheck](https://sitecheck.sucuri.net/)** — réputation du domaine,
  malwares connus, listes noires.
- **[urlscan.io](https://urlscan.io/)** — analyse de la page en direct dans un
  navigateur, requêtes sortantes, scripts injectés.

> Ces scans nécessitent que le site soit **accessible publiquement**. Un domaine
> local (`localhost`, `127.0.0.1`) ne peut pas être analysé par ces services.

---

## Scan YARA (optionnel)

En complément des motifs regex internes, le scanner peut invoquer
[YARA](https://virustotal.github.io/yara/) pour appliquer des **signatures
composées** (combinaisons de chaînes, compteurs, contraintes de taille)
impossibles à exprimer proprement en regex simple. Cela améliore la détection
des webshells, skimmers et backdoors obfusqués.

### Prérequis

Le binaire `yara` doit être installé sur le serveur et accessible dans le `PATH` :

```bash
# Debian / Ubuntu
sudo apt install yara

# macOS (Homebrew)
brew install yara
```

Si YARA est absent, le scan YARA est **automatiquement ignoré** (sans erreur ni
blocage) et le reste du scan fonctionne normalement.

### Règles par défaut

Le fichier `rules/prestashop.yar` fournit un jeu de règles couvrant :

- webshells génériques (exécution de code depuis une entrée utilisateur) ;
- obfuscation (`eval` + `base64_decode`/`gzinflate`/`str_rot13`) ;
- payloads cachés après `__halt_compiler()` ;
- familles connues (WSO, panneaux webshell) ;
- skimmers de carte bancaire (capture + exfiltration réseau) ;
- backdoors d'exécution de code distant et reverse shells ;
- mineurs de cryptomonnaie ;
- `.htaccess` malveillants.

### Utilisation

Le scan YARA est automatique si le binaire et les règles sont présents. Pour
utiliser vos propres règles :

```bash
php scanner.php --path=/var/www/prestashop --yara=/chemin/mes-regles.yar
```

Les détections YARA apparaissent dans le rapport avec le préfixe `YARA :`
(sévérité `critical`).

> Les fichiers de l'outillage du scanner (le script lui-même et les fichiers de
> règles `.yar`) sont automatiquement exclus du scan YARA pour éviter les faux
> positifs.

---

## Configuration

Les principaux réglages sont en tête de `scanner.php` :

- `MAX_FILE_SIZE` — taille maximale d'un fichier analysé (défaut : 5 Mo).
  Les fichiers plus gros sont signalés « non analysés » (à vérifier
  manuellement) plutôt que d'échouer.
- `$directories` — répertoires à scanner.
- `$whitelist` — fichiers/dossiers légitimes à ignorer (faux positifs connus).
- `$malicious_patterns` — motifs de détection (regex).
- `$pattern_severity` — reclassement de motifs bruités en `warning`/`info`.

---

## Avertissement

Rien ne garantit qu'un scan détecte 100 % des menaces. Ce script est un outil
d'aide à la décision : il **oriente** les vérifications, il ne les remplace pas.
En cas de doute sur une compromission, faites appel à un professionnel de la
sécurité. Consultez la section « Conseils de vérification » en bas du rapport
pour la marche à suivre.

---

## Licence

Academic Free License (AFL 3.0) — voir le fichier [LICENSE](LICENSE).