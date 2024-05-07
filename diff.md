diff --git a/BSI-TR-02102-2-2_2021_01_DE.txt b/BSI-TR-02102-2_2024_01_DE.txt
index f81ae0f..2d136ec 100644
\--- a/BSI-TR-02102-2-2_2021_01_DE.txt
\+++ b/BSI-TR-02102-2_2024_01_DE.txt
@@ -2,19 +2,17 @@ Technische Richtlinie TR-02102-2
Kryptographische Verfahren:
Empfehlungen und Schlüssellängen
Teil 2 – Verwendung von Transport Layer Security (TLS)
[\-Version 2021-01-]

Änderungshistorie
[\-Version-]

[\-Datum-]

[\-Beschreibung-]{+Tabelle 1: Änderungshistorie+}

{+Version+}
2019-01

{+Datum+}
22\.02.2019

{+Beschreibung+}
Anpassung der Verwendungszeiträume, Empfehlung von TLS 1.3,
Empfehlung von PSK-Cipher-Suiten aus RFC 8442, Empfehlung des CCMModus

@@ -30,97 +28,144 @@ Anpassung der Verwendungszeiträume, Abkündigung von HMAC-SHA-1

Anpassung der Verwendungszeiträume

{+2022-01+}

{+24.01.2022+}

{+2023-01+}

{+17.01.2023+}

{+2024-01+}

{+29.02.2024+}

{+Anpassung der Verwendungszeiträume, Empfehlung der elliptischen+}
{+Kurve secp521r1+}
{+Anhebung des Sicherheitsniveaus auf 120 Bit, Anpassung der+}
{+Verwendungszeiträume+}
{+Anpassung der Verwendungszeiträume, Abkündigung der Empfehlung+}
{+von DSA und von DHE-Cipher-Suiten ab 2029+}

Bundesamt für Sicherheit in der Informationstechnik
Postfach 20 03 63
53133 Bonn
{+Tel.: +49 22899 9582-0+}
E-Mail: TR02102@bsi.bund.de
Internet: https://www.bsi.bund.de
© Bundesamt für Sicherheit in der Informationstechnik [\-2021-]{+2024+}

[\-Inhaltsverzeichnis-]{+Inhalt+}

[\-Inhaltsverzeichnis-]
[\-Änderungshistorie............................................................................................................................................................................. 2-]{+Inhalt+}
1

[\-Einleitung............................................................................................................................................................................................... 5-]{+Einleitung ............................................................................................................................................................................................ 4+}

2

[\-Grundlagen............................................................................................................................................................................................ 6-]{+Grundlagen ......................................................................................................................................................................................... 5+}

3

[\-Empfehlungen..................................................................................................................................................................................... 7-]{+Empfehlungen................................................................................................................................................................................... 6+}
3\.1
[\-Allgemeine Hinweise................................................................................................................................................................... 7-]
3\.1.1

[\-Verwendungszeiträume...................................................................................................................................................... 7-]{+Verwendungszeiträume ................................................................................................................................................ 6+}

3\.1.2

[\-Sicherheitsniveau................................................................................................................................................................... 7-]
[\-3.1.3-]
[\-Schlüssellängen bei Verfahren mit elliptischen Kurven .......................................................................................7-]{+Sicherheitsniveau ............................................................................................................................................................. 6+}

3\.2

[\-SSL/TLS-Versionen....................................................................................................................................................................... 7-]{+SSL/TLS-Versionen .............................................................................................................................................................. 6+}

3\.3

Empfehlungen zu TLS [\-1.2........................................................................................................................................................ 7-]{+1.2 .................................................................................................................................................. 6+}

3\.3.1

[\-Cipher-Suiten........................................................................................................................................................................... 8-]{+Cipher-Suiten..................................................................................................................................................................... 6+}

3\.3.2

[\-Diffie-Hellman Gruppen.................................................................................................................................................... 11-]{+Diffie-Hellman-Gruppen .............................................................................................................................................. 9+}

3\.3.3

[\-Signaturverfahren............................................................................................................................................................... 12-]{+Signaturverfahren ............................................................................................................................................................ 9+}

3\.3.4

Weitere [\-Empfehlungen..................................................................................................................................................... 12-]{+Empfehlungen................................................................................................................................................ 10+}

3\.4

{+4+}

{+Allgemeine Hinweise ........................................................................................................................................................... 6+}

Empfehlungen zu TLS [\-1.3...................................................................................................................................................... 14-]{+1.3 ................................................................................................................................................ 12+}

3\.4.1

[\-Handshake Modi.................................................................................................................................................................. 14-]{+Handshake-Modi............................................................................................................................................................ 12+}

3\.4.2

[\-Diffie-Hellman Gruppen.................................................................................................................................................... 14-]{+Diffie-Hellman-Gruppen ............................................................................................................................................ 12+}

3\.4.3

[\-Signaturverfahren............................................................................................................................................................... 15-]{+Signaturverfahren .......................................................................................................................................................... 13+}

3\.4.4

[\-Cipher-Suiten......................................................................................................................................................................... 16-]{+Cipher-Suiten................................................................................................................................................................... 14+}

{+3.4.5+}

{+Weitere Empfehlungen................................................................................................................................................ 14+}

3\.5

Authentisierung der Kommunikationspartner [\-............................................................................................................... 16-]{+...................................................................................................... 14+}

3\.6

Domainparameter und [\-Schlüssellängen.......................................................................................................................... 17-]{+Schlüssellängen ................................................................................................................... 14+}

3\.6.1

[\-Schlüssellängen.................................................................................................................................................................... 17-]{+Schlüssellängen ............................................................................................................................................................... 14+}

3\.6.2

Verwendung von elliptischen [\-Kurven......................................................................................................................... 18-]
[\-4-]{+Kurven .................................................................................................................. 15+}

{+Schlüssel und Zufallszahlen....................................................................................................................................................... 16+}
4\.1

{+Schlüsselspeicherung......................................................................................................................................................... 16+}

4\.2

{+Umgang mit Ephemer-Schlüsseln ............................................................................................................................... 16+}

4\.3

[\-Schlüssel und Zufallszahlen........................................................................................................................................................ 19-]
[\-Schlüsselspeicherung............................................................................................................................................................... 19-]
[\-Umgang mit Ephemer-Schlüsseln...................................................................................................................................... 19-]
[\-Zufallszahlen................................................................................................................................................................................. 19-]
[\-Literaturverzeichnis....................................................................................................................................................................... 20-]

[\-Tabellenverzeichnis-]

[\-Tabelle 1: Empfohlene Cipher-Suiten für TLS 1.2 mit Perfect Forward Secrecy...............................................................9-]
[\-Tabelle 2: Empfohlene Cipher-Suiten für TLS 1.2 ohne Perfect Forward Secrecy...........................................................9-]
[\-Tabelle 3: Empfohlene Cipher-Suiten für TLS 1.2 mit Pre-Shared Key...............................................................................10-]
[\-Tabelle 4: Übergangsregelungen für TLS 1.2 und frühere TLS-Versionen.........................................................................11-]
[\-Tabelle 5: Empfohlene Diffie-Hellman Gruppen für TLS 1.2...................................................................................................11-]
[\-Tabelle 6: Empfohlene Signaturverfahren für TLS 1.2................................................................................................................. 12-]
[\-Tabelle 7: Empfohlene Hashfunktionen für Signaturverfahren in TLS 1.2.......................................................................12-]
[\-Tabelle 8: Empfohlene Pre-Shared Key Modi für TLS 1.3..........................................................................................................14-]
[\-Tabelle 9: Empfohlene Diffie-Hellman Gruppen für TLS 1.3...................................................................................................15-]
[\-Tabelle 10: Empfohlene Signaturverfahren für TLS 1.3 (Client-/Server-Signatur)........................................................15-]
[\-Tabelle 11: Empfohlene Signaturverfahren für TLS 1.3 (Zertifikatssignaturen)..............................................................16-]
[\-Tabelle 12: Empfohlene Cipher-Suiten für TLS 1.3.......................................................................................................................-]{+Zufallszahlen .........................................................................................................................................................................+} 16

[\-Tabelle 13: Empfohlene Mindest-Schlüssellängen für das TLS-Handshakeprotokoll.................................................17-]{+Literaturverzeichnis ............................................................................................................................................................................... 17+}

Bundesamt für Sicherheit in der Informationstechnik

3

[\-Einleitung 1-]{+1 Einleitung+}

1

@@ -146,9 +191,9 @@ Seitenkanäle identifizieren und entsprechende Gegenmaßnahmen umsetzen. Je nach
auch für Fault-Attacken.
Hinweis: Für Definitionen kryptographischer Begriffe in diesem Dokument siehe das Glossar in [TR-021021].

[\-Bundesamt für Sicherheit in der Informationstechnik-]{+4+}

[\-5-]{+Bundesamt für Sicherheit in der Informationstechnik+}

2 Grundlagen

@@ -175,11 +220,11 @@ Anforderung eines Passwortes). Bei besonders kritischen Operationen sollte dabei
Authentisierung durch Wissen und Besitz (Zwei-Faktor-Authentisierung) erfolgen, die sich unter
Ausnutzung kryptographischer Mechanismen auch auf die übertragenen Daten erstrecken sollte.

[\-6-]

Bundesamt für Sicherheit in der Informationstechnik

[\-Empfehlungen 3-]{+5+}

{+3 Empfehlungen+}

3

@@ -204,50 +249,37 @@ verlängert wird.
Sicherheitsniveau

Das Sicherheitsniveau für alle kryptographischen Verfahren in dieser Technischen Richtlinie richtet sich
nach dem in Abschnitt 1.1 in [TR-02102-1] angegebenen[\-Sicherheitsniveau. Es liegt zurzeit bei 100 Bit.-]
[\-Hinweis: Ab dem Jahr 2023 wird ein-] Sicherheitsniveau[\-von 120 Bit angestrebt. Als Übergangsregelung ist die-]
[\-Verwendung von RSA-basierten Signatur--] und [\-Verschlüsselungsverfahren mit einer Schlüssellänge ab 2000-]
[\-Bit für das gesamte Jahr 2023 aber weiter konform zu dieser Richtlinie. Siehe dazu auch Abschnitt 1.1 in [TR02102-1].-]

[\-3.1.3-]

[\-Schlüssellängen bei Verfahren mit elliptischen Kurven-]

[\-Für einen Einsatzzeitraum bis Ende 2022 ist das Sicherheitsniveau-]{+liegt+} bei [\-Verfahren, die auf elliptischen Kurven-]
[\-basieren, etwas größer (im Vergleich zu RSA) gewählt worden, um einen Sicherheitsspielraum für diese-]
[\-Verfahren zu erreichen (vgl. Abschnitt 3.6). Für eine Begründung und weitere Erläuterungen siehe-]
[\-Bemerkung 4, Kapitel 3 in [TR-02102-1].-]{+120 Bit.+}

3\.2

SSL/TLS-Versionen

Das SSL-Protokoll existiert in den Versionen 1.0, 2.0 und 3.0, wobei die Version 1.0 nicht veröffentlicht
wurde. TLS 1.0 ist eine direkte Weiterentwicklung von SSL 3.0 und wird in [\-[RFC2246]\-]{+[RFC 2246]\+} spezifiziert. Des
Weiteren gibt es die TLS-Versionen 1.1, 1.2 und 1.3, welche in [\-[RFC4346], [RFC5246]\-]{+[RFC 4346], [RFC 5246]\+} und [\-[RFC8446]\-]{+[RFC 8446]\+}
spezifiziert werden.
Empfehlungen für die Wahl der TLS-Version sind:
{+•+}

[\-•-]Grundsätzlich werden TLS 1.2 und TLS 1.3 empfohlen.[\-• TLS 1.0 und TLS 1.1 werden nicht empfohlen (siehe auch Abschnitt 3.3.1.4).-]
[\-• SSL v2 ([SSLv2]) und SSL v3 ([SSLv3]) werden nicht empfohlen (siehe auch [RFC6176] und [RFC7568]).-]

[\-3.3-]{+•+}

[\-Empfehlungen zu-]TLS [\-1.2-]{+1.0 und TLS 1.1 werden nicht empfohlen (siehe auch [RFC 8996]).+}

[\-In TLS 1.2 werden die kryptographischen Verfahren einer Verbindung durch eine Cipher-Suite festgelegt.-]
[\-Eine Cipher-Suite spezifiziert ein (authentisiertes) Schlüsseleinigungsverfahren für das HandshakeProtokoll, ein authentisiertes Verschlüsselungsverfahren für das Record-Protokoll und eine Hashfunktion-]{+•+}

[\-Bundesamt für Sicherheit in der Informationstechnik-]{+SSL v2 ([SSLv2]) und SSL v3 ([SSLv3]) werden nicht empfohlen (siehe auch [RFC 6176] und [RFC 7568]).+}

[\-7-]{+3.3+}

[\-3-]Empfehlungen {+zu TLS 1.2+}

{+In TLS 1.2 werden die kryptographischen Verfahren einer Verbindung durch eine Cipher-Suite festgelegt.+}
{+Eine Cipher-Suite spezifiziert ein (authentisiertes) Schlüsseleinigungsverfahren für das HandshakeProtokoll, ein authentisiertes Verschlüsselungsverfahren für das Record-Protokoll und eine Hashfunktion+}
für die Schlüsselableitung. Für die Schlüsseleinigung müssen je nach Cipher-Suite noch eine [\-Diffie-Hellman-]
[\-Gruppe-]{+DiffieHellman-Gruppe+} (in einem endlichen Körper oder über einer elliptischen Kurve) oder Signaturverfahren
festgelegt werden.
Eine vollständige Liste aller definierten Cipher-Suiten mit Verweisen auf die jeweiligen Spezifikationen ist
verfügbar unter [IANA].

@@ -257,10 +289,22 @@ Cipher-Suiten

In TLS 1.2 werden Cipher-Suiten in der Regel mit der Namenskonvention TLS_AKE_WITH_Enc_Hash
angegeben, wobei AKE ein (authentisiertes) Schlüsseleinigungsverfahren, Enc ein
Verschlüsselungsverfahren mit Betriebsmodus und Hash eine Hashfunktion bezeichnet. Die Funktion Hash
wird von einem HMAC (Keyed-Hash Message Authentication Code) genutzt, der für die PRF [\-(PseudoRandom-]{+(Pseudo-Random+}
Function) zur Schlüsselableitung verwendet wird.1 Falls Enc kein authentisiertes Verschlüsselungsverfahren

{+1+}

{+6+}

{+Bei Cipher-Suiten, die den Betriebsmodus CCM verwenden, ist keine Hashfunktion angegeben. Diese+}
{+Cipher-Suiten verwenden SHA-256 für die PRF.+}
{+Bundesamt für Sicherheit in der Informationstechnik+}

{+3 Empfehlungen+}

(Authenticated Encryption with Associated Data, kurz AEAD) ist, so wird der HMAC zusätzlich für die
Integritätssicherung im Record-Protokoll eingesetzt.
Grundsätzlich wird empfohlen, nur Cipher-Suiten einzusetzen, die die Anforderungen an die Algorithmen
und Schlüssellängen der [TR-02102-1] erfüllen.

@@ -268,215 +312,197 @@ und Schlüssellängen der [TR-02102-1] erfüllen.

(EC)DHE Cipher-Suiten

Die folgenden Cipher-Suiten mit Perfect Forward [\-Secrecy 2-]{+Secrecy2+} werden empfohlen:
[\-Cipher-Suite-]

[\-IANA-Nr.-]

[\-Referenziert Verwendung-]
[\-in-]
[\-bis-]{+Tabelle 2: Empfohlene Cipher-Suiten für TLS 1.2 mit Perfect Forward Secrecy+}

{+Cipher-Suite+}
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

{+IANA-Nr.+}
0xC0,0x23

[\-[RFC5289]\-]{+Referenz+}
{+[RFC 5289]\+}

[\-2027+-]{+Verwendung bis+}
{+2030++}

TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384

0xC0,0x24

[\-[RFC5289]\-]{+[RFC 5289]\+}

[\-2027+-]{+2030++}

TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

0xC0,0x2B

[\-[RFC5289]\-]{+[RFC 5289]\+}

[\-2027+-]{+2030++}

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

0xC0,0x2C

[\-[RFC5289]\-]{+[RFC 5289]\+}

[\-2027+-]{+2030++}

TLS_ECDHE_ECDSA_WITH_AES_128_CCM

0xC0,0xAC

[\-[RFC7251]\-]{+[RFC 7251]\+}

[\-2027+-]{+2030++}

TLS_ECDHE_ECDSA_WITH_AES_256_CCM

[\-0xC0,0xAD-]

[\-[RFC7251]\-]

[\-2027+-]

TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

{+0xC0,0xAD+}
0xC0,0x27

[\-[RFC5289]\-]{+[RFC 7251]\+}
{+[RFC 5289]\+}

[\-2027+-]{+2030++}
{+2030++}

TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384

[\-0xC0,0x28-]

[\-[RFC5289]\-]

[\-2027+-]

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

{+0xC0,0x28+}
0xC0,0x2F

[\-[RFC5289]\-]{+[RFC 5289]\+}
{+[RFC 5289]\+}

[\-2027+-]{+2030++}
{+2030++}

TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

[\-0xC0,0x30-]

[\-[RFC5289]\-]

[\-2027+-]

TLS_DHE_DSS_WITH_AES_128_CBC_SHA256

{+0xC0,0x30+}
0x00,0x40

[\-[RFC5246]\-]{+[RFC 5289]\+}
{+[RFC 5246]\+}

[\-2027+-]{+2030++}
{+2029+}

TLS_DHE_DSS_WITH_AES_256_CBC_SHA256

0x00,0x6A

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]{+2029+}

TLS_DHE_DSS_WITH_AES_128_GCM_SHA256

0x00,0xA2

[\-[RFC5288]\-]{+[RFC 5288]\+}

[\-2027+-]{+2029+}

TLS_DHE_DSS_WITH_AES_256_GCM_SHA384

0x00,0xA3

[\-[RFC5288]\-]

[\-2027+-]

[\-1 Bei Cipher-Suiten, die den Betriebsmodus CCM verwenden, ist keine Hashfunktion angegeben. Diese CipherSuiten verwenden SHA-256 für die PRF.-]
[\-2 Perfect Forward Secrecy (kurz PFS, auch Forward Secrecy) bedeutet, dass eine Verbindung auch bei Kenntnis-]
[\-der Langzeit-Schlüssel der Kommunikationspartner nicht nachträglich entschlüsselt werden kann. Bei der-]
[\-Verwendung von TLS zum Schutz personenbezogener oder anderer sensibler Daten wird Perfect Forward-]
[\-Secrecy grundsätzlich empfohlen.-]
[\-8-]

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-Empfehlungen 3-]

[\-Cipher-Suite-]{+[RFC 5288]\+}

[\-IANA-Nr.-]

[\-Referenziert Verwendung-]
[\-in-]
[\-bis-]{+2029+}

TLS_DHE_RSA_WITH_AES_128_CBC_SHA256

0x00,0x67

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]{+2029+}

TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

0x00,0x6B

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]{+2029+}

TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

0x00,0x9E

[\-[RFC5288]\-]{+[RFC 5288]\+}

[\-2027+-]{+2029+}

TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

[\-0x00,0x9F-]

[\-[RFC5288]\-]

[\-2027+-]

TLS_DHE_RSA_WITH_AES_128_CCM

{+0x00,0x9F+}
0xC0,0x9E

[\-[RFC6655]\-]{+[RFC 5288]\+}
{+[RFC 6655]\+}

[\-2027+-]{+2029+}
{+2029+}

TLS_DHE_RSA_WITH_AES_256_CCM

0xC0,0x9F

[\-[RFC6655]\-]{+[RFC 6655]\+}

[\-2027+-]{+2029+}

[\-Tabelle 1: Empfohlene-]{+Hinweis: Die Verwendung von+} Cipher-Suiten[\-für TLS 1.2-] mit [\-Perfect Forward Secrecy-]{+dem CBC-Modus wird nur in Verbindung mit der TLSErweiterung „Encrypt-then-MAC“ empfohlen, sobald geeigntete Implementierungen zur Verfügung stehen+}
{+(siehe Abschnitte 3.3.4.4 und 3.3.4.5).+}
{+Hinweis: Die Cipher-Suiten der Form TLS_DHE\_* werden voraussichtlich von der IETF abgekündigt+}
{+(siehe https://datatracker.ietf.org/doc/draft-ietf-tls-deprecate-obsolete-kex/). Daher werden diese CipherSuiten in dieser Technischen Richtlinie nur noch bis 2029 empfohlen.+}

3\.3.1.2

(EC)DH [\-Cipher Suiten-]{+Cipher-Suiten+}

Sofern die Verwendung der in Abschnitt 3.3.1.1 empfohlenen Cipher-Suiten mit Perfect Forward Secrecy
nicht möglich ist, können auch die folgenden Cipher-Suiten eingesetzt werden:

{+2+}

{+Perfect Forward Secrecy (kurz PFS, auch Forward Secrecy) bedeutet, dass eine Verbindung auch bei+}
{+Kenntnis der Langzeit-Schlüssel der Kommunikationspartner nicht nachträglich entschlüsselt werden+}
{+kann. Bei der Verwendung von TLS zum Schutz personenbezogener oder anderer sensibler Daten wird+}
{+Perfect Forward Secrecy grundsätzlich empfohlen.+}

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+7+}

{+3 Empfehlungen+}

{+Tabelle 3: Empfohlene Cipher-Suiten für TLS 1.2 ohne Perfect Forward Secrecy+}

Cipher-Suite

IANA-Nr.

[\-Referenziert-]{+Referenz+}

Verwendung[\-in-] bis

TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256

0xC0,0x25

[\-[RFC5289]\-]{+[RFC 5289]\+}

2026

@@ -484,7 +510,7 @@ TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384

0xC0,0x26

[\-[RFC5289]\-]{+[RFC 5289]\+}

2026

@@ -492,79 +518,63 @@ TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256

0xC0,0x2D

[\-[RFC5289]\-]{+[RFC 5289]\+}

2026

TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384

[\-0xC0,0x2E-]

[\-[RFC5289]\-]

[\-2026-]

TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256

{+0xC0,0x2E+}
0xC0,0x29

[\-[RFC5289]\-]{+[RFC 5289]\+}
{+[RFC 5289]\+}

2026

[\-TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384-]

[\-0xC0,0x2A-]

[\-[RFC5289]\-]

2026

{+TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384+}
TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256

{+0xC0,0x2A+}
0xC0,0x31

[\-[RFC5289]\-]{+[RFC 5289]\+}
{+[RFC 5289]\+}

2026

[\-TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384-]

[\-0xC0,0x32-]

[\-[RFC5289]\-]

2026

{+TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384+}
TLS_DH_DSS_WITH_AES_128_CBC_SHA256

{+0xC0,0x32+}
0x00,0x3E

[\-[RFC5246]\-]{+[RFC 5289]\+}
{+[RFC 5246]\+}

2026

[\-TLS_DH_DSS_WITH_AES_256_CBC_SHA256-]

[\-0x00,0x68-]

[\-[RFC5246]\-]

2026

{+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+}
TLS_DH_DSS_WITH_AES_128_GCM_SHA256

{+0x00,0x68+}
0x00,0xA4

[\-[RFC5288]\-]{+[RFC 5246]\+}
{+[RFC 5288]\+}

{+2026+}
2026

TLS_DH_DSS_WITH_AES_256_GCM_SHA384

0x00,0xA5

[\-[RFC5288]\-]{+[RFC 5288]\+}

2026

@@ -572,7 +582,7 @@ TLS_DH_RSA_WITH_AES_128_CBC_SHA256

0x00,0x3F

[\-[RFC5246]\-]{+[RFC 5246]\+}

2026

@@ -580,7 +590,7 @@ TLS_DH_RSA_WITH_AES_256_CBC_SHA256

0x00,0x69

[\-[RFC5246]\-]{+[RFC 5246]\+}

2026

@@ -588,7 +598,7 @@ TLS_DH_RSA_WITH_AES_128_GCM_SHA256

0x00,0xA0

[\-[RFC5288]\-]{+[RFC 5288]\+}

2026

@@ -596,11 +606,12 @@ TLS_DH_RSA_WITH_AES_256_GCM_SHA384

0x00,0xA1

[\-[RFC5288]\-]{+[RFC 5288]\+}

2026

[\-Tabelle 2: Empfohlene-]{+Hinweis: Die Verwendung von+} Cipher-Suiten [\-für TLS 1.2 ohne Perfect Forward Secrecy-]{+mit dem CBC-Modus wird nur in Verbindung mit der TLSErweiterung „Encrypt-then-MAC“ empfohlen, sobald geeigntete Implementierungen zur Verfügung stehen+}
{+(siehe Abschnitte 3.3.4.4 und 3.3.4.5).+}

3\.3.1.3

@@ -608,120 +619,109 @@ Schlüsseleinigung mit vorab ausgetauschten Daten

Sollen bei einer TLS-Verbindung zusätzliche vorab ausgetauschte Daten in die Schlüsseleinigung einfließen,
können Cipher-Suiten mit einem Pre-shared Key (kurz PSK) verwendet werden. Grundsätzlich werden

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-9-]

[\-3 Empfehlungen-]

hierbei solche Cipher-Suiten empfohlen, bei denen neben dem Pre-shared Key weitere ephemere Schlüssel
oder ausgetauschte Zufallszahlen in die Schlüsseleinigung eingehen.
Die Verwendung von Cipher-Suiten vom Typ TLS_PSK\_*, das heißt ohne zusätzliche ephemere Schlüssel
oder Zufallszahlen, wird nicht empfohlen, da bei diesen Cipher-Suiten die Sicherheit der Verbindung
ausschließlich auf der Entropie und der Vertraulichkeit des Pre-shared Keys beruht.
Die folgenden Cipher-Suiten mit PSK werden empfohlen:
[\-Cipher-Suite-]{+Tabelle 4: Empfohlene Cipher-Suiten für TLS 1.2 mit Pre-Shared Key+}

[\-IANA-Nr.-]

[\-Referenziert Verwendung-]
[\-in-]
[\-bis-]{+8+}

[\-TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256-]{+Cipher-Suite+}

[\-0xC0,0x37-]{+IANA-Nr.+}

[\-[RFC5489]\-]{+Referenz+}

[\-2027+-]{+Verwendung bis+}

{+TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256+}
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384

{+0xC0,0x37+}
0xC0,0x38

[\-[RFC5489]\-]{+[RFC 5489]\+}
{+[RFC 5489]\+}

[\-2027+-]{+2030++}
{+2030++}

TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256

[\-0xD0,0x01-]

[\-[RFC8442]\-]

[\-2027+-]

TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384

{+0xD0,0x01+}
0xD0,0x02

[\-[RFC8442]\-]{+[RFC 8442]\+}
{+[RFC 8442]\+}

[\-2027+-]{+2030++}
{+2030++}

TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256

[\-0xD0,0x05-]

[\-[RFC8442]\-]

[\-2027+-]

TLS_DHE_PSK_WITH_AES_128_CBC_SHA256

{+0xD0,0x05+}
0x00,0xB2

[\-[RFC5487]\-]{+[RFC 8442]\+}
{+[RFC 5487]\+}

[\-2027+-]{+2030++}
{+2029+}

TLS_DHE_PSK_WITH_AES_256_CBC_SHA384

[\-0x00,0xB3-]

[\-[RFC5487]\-]

[\-2027+-]

TLS_DHE_PSK_WITH_AES_128_GCM_SHA256

{+0x00,0xB3+}
0x00,0xAA

[\-[RFC5487]\-]{+[RFC 5487]\+}
{+[RFC 5487]\+}

[\-2027+-]{+2029+}
{+2029+}

TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
{+TLS_DHE_PSK_WITH_AES_128_CCM+}

0x00,0xAB
{+0xC0,0xA6+}

[\-[RFC5487]\-]{+[RFC 5487]\+}
{+[RFC 6655]\+}

[\-2027+-]{+2029+}
{+2029+}

[\-TLS_DHE_PSK_WITH_AES_128_CCM-]{+TLS_DHE_PSK_WITH_AES_256_CCM+}

[\-0xC0,0xA6-]{+0xC0,0xA7+}

[\-[RFC6655]\-]{+[RFC 6655]\+}

[\-2027+-]{+2029+}

[\-TLS_DHE_PSK_WITH_AES_256_CCM-]{+Bundesamt für Sicherheit in der Informationstechnik+}

[\-0xC0,0xA7-]{+3 Empfehlungen+}

[\-[RFC6655]\-]{+Cipher-Suite+}

{+IANA-Nr.+}

[\-2027+-]{+Referenz+}

{+Verwendung bis+}

TLS_RSA_PSK_WITH_AES_128_CBC_SHA256

0x00,0xB6

[\-[RFC5487]\-]{+[RFC 5487]\+}

2026

@@ -729,7 +729,7 @@ TLS_RSA_PSK_WITH_AES_256_CBC_SHA384

0x00,0xB7

[\-[RFC5487]\-]{+[RFC 5487]\+}

2026

@@ -737,7 +737,7 @@ TLS_RSA_PSK_WITH_AES_128_GCM_SHA256

0x00,0xAC

[\-[RFC5487]\-]{+[RFC 5487]\+}

2026

@@ -745,91 +745,37 @@ TLS_RSA_PSK_WITH_AES_256_GCM_SHA384

0x00,0xAD

[\-[RFC5487]\-]{+[RFC 5487]\+}

2026

[\-Tabelle 3: Empfohlene-]{+Hinweis: Die Verwendung von+} Cipher-Suiten[\-für TLS 1.2-] mit [\-Pre-Shared Key-]{+dem CBC-Modus wird nur in Verbindung mit der TLSErweiterung „Encrypt-then-MAC“ empfohlen, sobald geeignete Implementierungen zur Verfügung stehen+}
{+(siehe Abschnitte 3.3.4.4 und 3.3.4.5).+}
{+Hinweis: Die Cipher-Suiten der Form TLS_DHE\_* werden voraussichtlich von der IETF abgekündigt (siehe+}
{+https://datatracker.ietf.org/doc/draft-ietf-tls-deprecate-obsolete-kex/). Daher werden diese Cipher-Suiten+}
{+in dieser Technischen Richtlinie nur noch bis 2029 empfohlen.+}
Hinweis: Die Cipher-Suiten der Form TLS_RSA_PSK\_* aus Tabelle [\-3-]{+4+} bieten keine Perfect Forward Secrecy,
alle anderen Cipher-Suiten aus Tabelle [\-3-]{+4+} hingegen bieten Perfect Forward Secrecy.[\-3.3.1.4-]

[\-Übergangsregelungen-]

[\-SHA-1 ist keine kollisionsresistente Hashfunktion; die Erzeugung von SHA-1-Kollisionen ist zwar mit-]
[\-einigem Aufwand verbunden, aber praktisch machbar [SBK17, LP19]. Gegen die Verwendung in-]
[\-Konstruktionen, die keine Kollisionsresistenz benötigen (zum Beispiel als Grundlage für einen HMAC oder-]
[\-als Komponente eines Pseudozufallsgenerators) spricht aber nach gegenwärtigem Kenntnisstand-]
[\-sicherheitstechnisch nichts. Es wird empfohlen, auch in diesen Anwendungen als grundsätzliche-]
[\-Sicherungsmaßnahme eine Hashfunktion der SHA-2-Familie oder der SHA-3-Familie einzusetzen.-]
[\-Prinzipiell ist eine Verwendung von SHA-1 in der HMAC-Konstruktion oder in anderen kryptographischen-]
[\-Mechanismen mit vergleichbaren kryptographischen Anforderungen an die genutzte Hashfunktion (zum-]
[\-Beispiel im Rahmen eines Pseudozufallsgenerators oder als Teil der Mask Generation Function in RSAOAEP) bis 2019 konform zu der vorliegenden Technischen Richtlinie.-]
[\-Daher kann, abweichend zu den Empfehlungen in diesem Kapitel und in Teil 1 dieser Technischen-]
[\-Richtlinie [TR-02102-1], in bestehenden TLS-Anwendungen als Hashfunktion für die Integritätssicherung-]
[\-mittels HMAC übergangsweise noch SHA-1 eingesetzt werden (das heißt Cipher-Suiten der Form *\_SHA).-]
[\-10-]

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-Empfehlungen 3-]

[\-Unabhängig von dem in Tabelle 4 angegebenen maximalen Verwendungszeitraum wird eine-]
[\-schnellstmögliche Migration zu SHA-256 bzw. SHA-384 und TLS 1.2 empfohlen.-]
[\-Hinweis: Da TLS 1.1 die Hashfunktion SHA-1 als Komponente für die Signaturerstellung verwendet (und-]
[\-keine Unterstützung der SHA-2-Familie bietet), wird der Einsatz von TLS 1.1 nicht mehr empfohlen.-]
[\-Der Verschlüsselungsalgorithmus RC4 in TLS weist erhebliche Sicherheitsschwächen auf. Seine-]
[\-Verwendung wird daher nicht empfohlen (siehe auch [RFC7465]).-]
[\-Abweichung-]

[\-Verwendung-]
[\-maximal bis-]

[\-Empfehlung-]

[\-SHA-1 zur HMAC-Berechnung und als Komponente-]
[\-der PRF in TLS-]

[\-2019-]

[\-Migration zu SHA-256/-384-]

[\-SHA-1 als Komponente für die Signaturerstellung in-]
[\-TLS-]

[\-2015-]

[\-Migration zu SHA-256/-384/-512-]

[\-Tabelle 4: Übergangsregelungen für TLS 1.2 und frühere TLS-Versionen-]

[\-Anmerkung: In der vorliegenden Technischen Richtlinie wurde der Einsatz von SHA-1 bis 2015 als-]
[\-Komponente für die Signaturerstellung ausschließlich im Rahmen von TLS empfohlen (vgl. Tabelle 4), damit-]
[\-TLS 1.0 noch übergangsweise bis Ende 2015 eingesetzt werden konnte. Da SHA-1 für den Handshake bei TLS-]
[\-1.0 erforderlich ist und eine SHA-1-Kollision sicherlich nicht in Echtzeit (also während des Handshakes)-]
[\-berechnet werden konnte, war der Einsatz von SHA-1 in diesem einzigen Spezialfall noch etwas länger-]
[\-möglich.-]
[\-Grundsätzlich wird jedoch die Verwendung von SHA-1 (z.B. für die Erstellung von Signaturen) in der TR02102-1 seit 2013 nicht mehr empfohlen.-]

3\.3.2

[\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+}

Bei Verwendung von TLS_DHE\_* oder TLS_ECDHE\_* Cipher-Suiten kann der Client dem Server mittels
der „supported_groups“ Erweiterung (ehemals auch „elliptic_curves“ Erweiterung genannt) signalisieren,
welche [\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+} er verwenden möchte (siehe [\-[RFC7919]\-]{+[RFC 7919]\+} für DHE und [\-[RFC8422]\-]{+[RFC 8422]\+} für
ECDHE).
Die Verwendung der „supported_groups“ Erweiterung für TLS_ECDHE\_* Cipher-Suiten wird empfohlen.
Die Verwendung der „supported_groups“ Erweiterung für TLS_DHE\_* Cipher-Suiten wird empfohlen,
sobald geeignete Implementierungen zur Verfügung stehen.
Die folgenden [\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+} werden empfohlen:
[\-Diffie-Hellman Gruppe-]{+Tabelle 5: Empfohlene Diffie-Hellman-Gruppen für TLS 1.2+}

{+Diffie-Hellman-Gruppe+}

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

@@ -837,72 +783,57 @@ secp256r1

23

[\-[RFC8422]\-]{+[RFC 8422]\+}

[\-2027+-]{+2030++}

secp384r1
{+secp521r1+}

24
{+25+}

[\-[RFC8422]\-]{+[RFC 8422]\+}
{+[RFC 8422]\+}

[\-2027+-]{+2030++}
{+2030++}

brainpoolP256r1

[\-26-]

[\-[RFC7027]\-]

[\-2027+-]

brainpoolP384r1

{+26+}
27

[\-[RFC7027]\-]{+[RFC 7027]\+}
{+[RFC 7027]\+}

[\-2027+-]{+2030++}
{+2030++}

brainpoolP512r1

28

[\-[RFC7027]\-]

[\-2027+-]

[\-ffdhe2048-]{+[RFC 7027]\+}

[\-256-]

[\-[RFC7919]\-]

[\-2022-]{+2030++}

ffdhe3072

257

[\-[RFC7919]\-]{+[RFC 7919]\+}

[\-2027+-]{+2029+}

ffdhe4096

258

[\-[RFC7919]\-]

[\-2027+-]

[\-Tabelle 5: Empfohlene Diffie-Hellman Gruppen für TLS 1.2-]
[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-11-]{+[RFC 7919]\+}

[\-3 Empfehlungen-]{+2029+}

Grundsätzlich ist Abschnitt 3.6 bei der Wahl von Domainparametern und Schlüssellängen zu beachten.

@@ -911,15 +842,26 @@ Grundsätzlich ist Abschnitt 3.6 bei der Wahl von Domainparametern und Schlüsse
Signaturverfahren

In TLS 1.2 kann der Client dem Server mittels der „signature_algorithms“ Erweiterung (siehe [RFC5246])
signalisieren, welche Signaturverfahren er für die Schlüsseleinigung und für Zertifikate akzeptiert. [\-Der-]
[\-Algorithmus muss dabei-]{+Bei+}
{+beidseitiger Authentisierung signalisiert der Server dem Client die von ihm akzeptierten Signaturverfahren+}
{+mit der CertificateRequest-Nachricht. Die Algorithmen müssen in beiden Fällen+} als Kombination aus
Signaturverfahren und Hashfunktion angegeben werden.
Die Verwendung der „signature_algorithms“ Erweiterung wird empfohlen.
Die folgenden Signaturverfahren werden empfohlen:

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+9+}

{+3 Empfehlungen+}

{+Tabelle 6: Empfohlene Signaturverfahren für TLS 1.2+}

Signaturverfahren

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

@@ -927,66 +869,62 @@ rsa

1

[\-[RFC5246]\-]{+[RFC 5246]\+}

2025

[\-dsa-]

2

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]{+2029+}

ecdsa

3

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]{+2030++}

[\-Tabelle 6: Empfohlene Signaturverfahren für TLS 1.2-]{+dsa+}

Für Domainparameter und Schlüssellängen ist Abschnitt 3.6 zu beachten.
Hinweis: Die Nutzung des Signaturverfahrens rsa (IANA-Nr. 1) [\-ist auf Grund-]{+wird aufgrund+} der Verwendung des PKCS
\#1 v1.5 Paddingverfahrens nur noch bis 2025 empfohlen (siehe auch Abschnitt [\-1.4-]{+1.5+} in [TR-02102-1]). {+Für die+}
{+Nutzung von RSA-Signaturen mit PSS-Padding in TLS 1.2 gemäß [RFC 8446], Abschnitt 1.3 und 4.2.3, gelten+}
{+die Empfehlungen aus Tabelle 10 und Tabelle 11.+}
{+Hinweis: Die Nutzung des Signaturverfahrens dsa (IANA-Nr. 2) wird aufgrund der geringen Verbreitung+}
{+und der Abkündigung in [FIPS 186-5] nur noch bis 2029 empfohlen (siehe auch Bemerkung 5.7 in [TR02102-1]).+}
Die folgenden Hashfunktionen werden (in Kombination mit einem Signaturverfahren aus Tabelle 6)
empfohlen:
{+Tabelle 7: Empfohlene Hashfunktionen für Signaturverfahren in TLS 1.2+}

Hashfunktion
{+sha256+}
{+sha384+}
{+sha512+}

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

[\-sha256-]

4

[\-[RFC5246]\-]

[\-2027+-]

[\-sha384-]

5

[\-[RFC5246]\-]{+[RFC 5246]\+}
{+[RFC 5246]\+}

[\-2027+-]

[\-sha512-]{+2030++}
{+2030++}

6

[\-[RFC5246]\-]{+[RFC 5246]\+}

[\-2027+-]

[\-Tabelle 7: Empfohlene Hashfunktionen für Signaturverfahren in TLS 1.2-]{+2030++}

3\.3.4

@@ -996,14 +934,14 @@ Weitere Empfehlungen

Session Renegotiation

Es wird empfohlen Session Renegotiation nur auf Basis von [\-[RFC5746]\-]{+[RFC 5746]\+} zu verwenden. Durch den Client
initiierte Renegotiation sollte vom Server abgelehnt werden.

3\.3.4.2

Verkürzung der HMAC-Ausgabe

Die in [\-[RFC6066]\-]{+[RFC 6066]\+} definierte Extension „truncated_hmac“ zur Verkürzung der Ausgabe des HMAC auf 80 Bit
sollte nicht verwendet werden.

3\.3.4.3
@@ -1013,12 +951,6 @@ TLS-Kompression und der CRIME-Angriff
TLS bietet die Möglichkeit, die übertragenen Daten vor der Verschlüsselung zu komprimieren. Dies führt zu
der Möglichkeit eines Seitenkanalangriffes auf die Verschlüsselung, und zwar mit Hilfe der Länge der
verschlüsselten Daten (siehe [CRIME]).
[\-12-]

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-Empfehlungen 3-]

Um dies zu verhindern, muss sichergestellt werden, dass alle Daten eines Datenpakets von dem korrekten
und legitimen Verbindungspartner stammen und keine Plaintext-Injection durch einen Angreifer möglich
ist. Kann dies nicht sichergestellt werden, so wird empfohlen die TLS-Datenkompression nicht zu
@@ -1026,116 +958,125 @@ verwenden.

3\.3.4.4

Der [\-Lucky 13 Angriff-]{+Lucky-13-Angriff+}

Lucky 13 ist ein Seitenkanalangriff (Timing) gegen Cipher-Suiten mit {+dem+} CBC-Modus, bei dem der
Angreifer sehr geringe Zeitdifferenzen bei der Verarbeitung des Paddings auf Seiten des Servers ausnutzt.
Für diesen Angriff muss der Angreifer sehr genaue Zeitmessungen im Netzwerk machen können. Er schickt
manipulierte Chiffrate an den Server und misst die Zeit, die der Server benötigt, um das Padding dieser

{+10+}

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+3 Empfehlungen+}

Chiffrate zu prüfen bzw. einen Fehler zu melden. Durch Netzwerk-Jitter können hier aber sehr leicht Fehler
bei der Zeitmessung entstehen, so dass ein Angriff grundsätzlich als schwierig realisierbar erscheint, denn
der Angreifer muss im Netzwerk „sehr nahe“ am Server sein, um genau genug messen zu können.
Der Angriff kann abgewehrt werden, wenn
{+•+}

{+Authenticated Encryption, wie zum Beispiel AES-GCM oder AES-CCM, oder+}

{+•+}

{+Encrypt-then-MAC (siehe auch nächster Abschnitt)+}

[\-• Authenticated Encryption, wie zum Beispiel AES-GCM oder AES-CCM, oder-]
[\-• Encrypt-then-MAC (siehe auch nächster Abschnitt)-]
eingesetzt wird.

3\.3.4.5

Die [\-Encrypt-then-MAC Erweiterung-]{+Encrypt-then-MAC-Erweiterung+}

Gemäß TLS-Spezifikation (siehe [\-[RFC5246])-]{+[RFC 5246])+} werden die zu übertragenen Daten zunächst mit einem
Message Authentication Code (MAC) gesichert und dann mit einem Padding versehen; danach werden die
Daten und das Padding verschlüsselt. Diese Reihenfolge („MAC-then-Encrypt“) war in der Vergangenheit
häufig der Grund für Angriffe auf die Verschlüsselung, da das Padding nicht durch den MAC geschützt ist.
Bei den sogenannten Padding-Oracle-Angriffen werden die verschlüsselten TLS-Pakete durch einen Manin-the-Middle-Angreifer manipuliert, um die Prüfung des Paddings als Seitenkanal zu missbrauchen. Dies
kann beispielsweise dazu führen, dass der Angreifer ein HTTPS-Sitzungs-Cookie entschlüsseln kann und
somit die Sitzung des Opfers übernehmen kann.
In [\-[RFC7366]\-]{+[RFC 7366]\+} wird die TLS-Erweiterung „Encrypt-then-MAC“ spezifiziert. Hierbei werden die zu
übertragenen Daten zuerst mit einem Padding versehen, dann verschlüsselt und danach mit einem MAC
gesichert. Damit sind Manipulationen des Paddings ausgeschlossen, da es auch durch den MAC gesichert ist.
Der Einsatz der TLS-Erweiterung „Encrypt-then-MAC“ gemäß [\-[RFC7366]\-]{+[RFC 7366]\+} wird empfohlen, sobald
geeignete Implementierungen zur Verfügung stehen.

3\.3.4.6

Die [\-Heartbeat Erweiterung-]{+Heartbeat-Erweiterung+}

Die Heartbeat-Erweiterung wird in [\-[RFC6520]\-]{+[RFC 6520]\+} spezifiziert; sie ermöglicht es, eine TLS-Verbindung über
einen längeren Zeitraum aufrecht zu halten, ohne eine Renegotiation der Verbindung durchführen zu
müssen. Durch den sogenannten Heartbleed-Bug ist es einem Angreifer möglich, bestimmte
Speicherbereiche des Servers auszulesen, die möglicherweise geheimes Schlüsselmaterial enthalten. Dies
kann zu einer vollständigen Kompromittierung des Servers führen, falls der private Schlüssel des Servers
bekannt wird.
[\-Empfehlung:-]Es wird[\-dringend-] empfohlen, die Heartbeat-Erweiterung nicht zu verwenden.[\-Sollte es-]
[\-trotzdem erforderlich sein, so sollte sichergestellt sein, dass die verwendete TLS-Implementierung nicht-]
[\-anfällig für den Heartbleed-Bug ist.-]

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-13-]

[\-3 Empfehlungen-]

3\.3.4.7

Die [\-Extended Master Secret Erweiterung-]{+Extended-Master-Secret-Erweiterung+}

Um Angriffe, wie zum Beispiel den [\-Triple Handshake-Angriff-]{+Triple-Handshake-Angriff+} (siehe [BDF14]) abzuwehren, ist es sehr
sinnvoll, weitere Verbindungsparameter in den TLS-Handshake einfließen zu lassen, damit
unterschiedliche TLS-Verbindungen auch unterschiedliche Master Secrets (aus welchem die symmetrischen
Schlüssel abgeleitet werden) benutzen.
In [\-[RFC7627]\-]{+[RFC 7627]\+} wird die TLS-Erweiterung Extended Master Secret spezifiziert, die bei der Berechnung des
„erweiterten“ Master Secrets einen Hashwert über alle Nachrichten des TLS-Handshakes mit in dieses
einfließen lässt.
Der Einsatz der TLS-Erweiterung Extended Master Secret gemäß [\-[RFC7627]\-]{+[RFC 7627]\+} wird empfohlen, sobald
geeignete Implementierungen zur Verfügung stehen.

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+11+}

{+3 Empfehlungen+}

3\.4

Empfehlungen zu TLS 1.3

In TLS 1.3 werden die kryptographischen Verfahren einer Verbindung durch einen [\-Handshake Modus,-]{+Handshake-Modus,+} eine
[\-Diffie-Hellman Gruppe-]{+Diffie-Hellman-Gruppe+} (bei (EC)DHE), ein Signaturverfahren (bei zertifikatsbasierter Authentisierung) und
eine Cipher-Suite festgelegt. Im Gegensatz zu früheren TLS-Versionen spezifiziert eine Cipher-Suite hierbei
nur ein authentisiertes Verschlüsselungsverfahren für das Record-Protokoll sowie eine Hashfunktion für
die Schlüsselableitung.

3\.4.1

[\-Handshake Modi-]{+Handshake-Modi+}

Neben der standardmäßigen [\-Diffie-Hellman Schlüsseleinigung-]{+Diffie-Hellman-Schlüsseleinigung+} über endlichen Körpern (DHE) oder
elliptischen Kurven (ECDHE) gibt es in TLS 1.3 weitere [\-Handshake Modi,-]{+Handshake-Modi,+} die Pre-shared Keys (PSK)
verwenden. Unter Pre-shared Keys versteht man hierbei Schlüsselmaterial, das entweder vorab verteilt
wurde oder das in einer vergangenen Session über den Session-Ticket-Mechanismus ausgetauscht wurde.
Die folgenden PSK-Modi werden empfohlen:
{+Tabelle 8: Empfohlene Pre-Shared-Key-Modi für TLS 1.3+}

PSK-Modus
{+psk_ke+}

{+psk_dhe_ke+}

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

[\-psk_ke-]

0

[\-[RFC8446]\-]{+[RFC 8446]\+}

2026

[\-psk_dhe_ke-]

1

[\-[RFC8446]\-]

[\-2027+-]{+[RFC 8446]\+}

[\-Tabelle 8: Empfohlene Pre-Shared Key Modi für TLS 1.3-]{+2030++}

Hinweis: Der PSK-Modus psk_ke bietet keine Perfect Forward Secrecy. Dieser Modus sollte daher nur in
speziellen Anwendungsfällen nach Hinzuziehen eines Experten eingesetzt werden.
@@ -1146,97 +1087,83 @@ empfohlen.

3\.4.2

[\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+}

In TLS 1.3 können die Kommunikationspartner mittels der „supported_groups“ Erweiterung signalisieren,
welche [\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+} für (EC)DHE verwendet werden sollen.
Die folgenden [\-Diffie-Hellman Gruppen-]{+Diffie-Hellman-Gruppen+} werden empfohlen:
[\-14-]

[\-Bundesamt-]{+Tabelle 9: Empfohlene Diffie-Hellman-Gruppen+} für [\-Sicherheit in der Informationstechnik-]

[\-Empfehlungen 3-]

[\-Diffie-Hellman Gruppe-]

[\-IANA-Nr.-]

[\-Referenziert in-]

[\-Verwendung bis-]{+TLS 1.3+}

{+Diffie-Hellman-Gruppe+}
secp256r1

{+IANA-Nr.+}
23

[\-[RFC8422]\-]{+Referenz+}
{+[RFC 8422]\+}

[\-2027+-]{+Verwendung bis+}
{+2030++}

secp384r1
{+secp521r1+}

24
{+25+}

[\-[RFC8422]\-]{+[RFC 8422]\+}
{+[RFC 8422]\+}

[\-2027+-]{+2030++}
{+2030++}

brainpoolP256r1tls13

[\-31-]

[\-[RFC8734]\-]

[\-2027+-]

brainpoolP384r1tls13

{+31+}
32

[\-[RFC8734]\-]{+[RFC 8734]\+}
{+[RFC 8734]\+}

[\-2027+-]{+2030++}
{+2030++}

brainpoolP512r1tls13

33

[\-[RFC8734]\-]

[\-2027+-]{+[RFC 8734]\+}

[\-ffdhe2048-]

[\-256-]

[\-[RFC7919]\-]

[\-2022-]{+2030++}

ffdhe3072

257

[\-[RFC7919]\-]{+[RFC 7919]\+}

[\-2027+-]{+2030++}

ffdhe4096

258

[\-[RFC7919]\-]

[\-2027+-]{+[RFC 7919]\+}

[\-Tabelle 9: Empfohlene Diffie-Hellman Gruppen für TLS 1.3-]{+2030++}

Hinweis: Die Brainpool-Kurven werden grundsätzlich empfohlen.
Hinweis: In [\-[RFC8446]\-]{+[RFC 8446]\+} wurden die IANA-Nummern einiger EC-Gruppen, die laut [\-[RFC8446]\-]{+[RFC 8446]\+} entweder
veraltet sind oder wenig genutzt wurden, als „obsolete_RESERVED“ gekennzeichnet. Dazu zählen auch die
IANA-Nummern 26, 27, 28, die für die Brainpool-Kurven zur Nutzung in TLS 1.2 und früheren TLSVersionen registriert sind. Aus diesem Grund wurden für die Nutzung der Brainpool-Kurven in TLS 1.3 die
IANA-Nummern 31, 32, 33 reserviert (siehe [\-[RFC8734]).-]{+[RFC 8734]).+}
{+12+}

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+3 Empfehlungen+}

3\.4.3

@@ -1244,15 +1171,17 @@ Signaturverfahren

In TLS 1.3 können die Kommunikationspartner mittels der Erweiterungen „signature_algorithms“ und
„signature_algorithms_cert“ signalisieren, welche Signaturverfahren zur zertifikatsbasierten
Authentisierung [\-verwenden-]{+verwendet+} werden sollen. Die „signature_algorithms“ Erweiterung bezieht sich dabei auf
Signaturen, die der Client oder Server für eine CertificateVerify-Nachricht erstellt, und die
„signature_algorithms_cert“ Erweiterung auf Zertifikatssignaturen.
Die folgenden Signaturverfahren werden für die „signature_algorithms“ Erweiterung empfohlen:
{+Tabelle 10: Empfohlene Signaturverfahren für TLS 1.3 (Client-/Server-Signatur)+}

Signaturverfahren

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

@@ -1260,105 +1189,94 @@ rsa_pss_rsae_sha256

0x0804

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

rsa_pss_rsae_sha384

[\-0x0805-]

[\-[RFC8446]\-]

[\-2027+-]

rsa_pss_rsae_sha512

{+0x0805+}
0x0806

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

rsa_pss_pss_sha256

0x0809

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

rsa_pss_pss_sha384

0x080A

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

rsa_pss_pss_sha512

0x080B

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

ecdsa_secp256r1_sha256

0x0403

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

ecdsa_secp384r1_sha384
{+ecdsa_secp521r1_sha512+}

0x0503
{+0x0603+}

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

ecdsa_brainpoolP256r1tls13_sha256

[\-0x081A-]

[\-[RFC8734]\-]

[\-2027+-]

ecdsa_brainpoolP384r1tls13_sha384

{+0x081A+}
0x081B

[\-[RFC8734]\-]{+[RFC 8734]\+}
{+[RFC 8734]\+}

[\-2027+-]{+2030++}
{+2030++}

ecdsa_brainpoolP512r1tls13_sha512

0x081C

[\-[RFC8734]\-]

[\-2027+-]{+[RFC 8734]\+}

[\-Tabelle 10: Empfohlene Signaturverfahren für TLS 1.3 (Client-/Server-Signatur)-]{+2030++}

Die folgenden Algorithmen werden für die „signature_algorithms_cert“ Erweiterung empfohlen:
[\-Bundesamt-]{+Tabelle 11: Empfohlene Signaturverfahren+} für [\-Sicherheit in der Informationstechnik-]

[\-15-]

[\-3 Empfehlungen-]{+TLS 1.3 (Zertifikatssignaturen)+}

Signaturverfahren

IANA-Nr.

[\-Referenziert in-]{+Referenz+}

Verwendung bis

@@ -1366,7 +1284,7 @@ rsa_pkcs1_sha256

0x0401

[\-[RFC8446]\-]{+[RFC 8446]\+}

2025

@@ -1374,7 +1292,7 @@ rsa_pkcs1_sha384

0x0501

[\-[RFC8446]\-]{+[RFC 8446]\+}

2025

@@ -1382,147 +1300,146 @@ rsa_pkcs1_sha512

0x0601

[\-[RFC8446]\-]{+[RFC 8446]\+}

2025

rsa_pss_rsae_sha256

[\-0x0804-]

[\-[RFC8446]\-]

[\-2027+-]

rsa_pss_rsae_sha384

{+0x0804+}
0x0805

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

rsa_pss_rsae_sha512

0x0806

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

rsa_pss_pss_sha256

0x0809

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

rsa_pss_pss_sha384

[\-0x080A-]

[\-[RFC8446]\-]

[\-2027+-]

rsa_pss_pss_sha512

{+0x080A+}
0x080B

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

ecdsa_secp256r1_sha256
{+ecdsa_secp384r1_sha384+}

0x0403
{+0x0503+}

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

[\-ecdsa_secp384r1_sha384-]{+ecdsa_secp521r1_sha512+}

[\-0x0503-]{+0x0603+}

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]{+2030++}

ecdsa_brainpoolP256r1tls13_sha256

0x081A

[\-[RFC8734]\-]{+[RFC 8734]\+}

[\-2027+-]{+2030++}

ecdsa_brainpoolP384r1tls13_sha384

[\-0x081B-]

[\-[RFC8734]\-]

[\-2027+-]

ecdsa_brainpoolP512r1tls13_sha512

{+0x081B+}
0x081C

[\-[RFC8734]\-]{+[RFC 8734]\+}
{+[RFC 8734]\+}

[\-2027+-]

[\-Tabelle 11: Empfohlene Signaturverfahren für TLS 1.3 (Zertifikatssignaturen)-]{+2030++}
{+2030++}

Für Schlüssellängen bei RSA-Signaturen ist Abschnitt 3.6 zu beachten.
Hinweis: Die Nutzung der Signaturverfahren rsa_pkcs1\_* (IANA-Nr. 0x0401, 0x0501 und 0x0601) ist auf
Grund der Verwendung des PKCS #1 v1.5 Paddingverfahrens nur noch bis 2025 empfohlen (siehe auch
Abschnitt [\-1.4-]{+1.5+} in [TR-02102-1]).

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+13+}

{+3 Empfehlungen+}

3\.4.4

Cipher-Suiten

In TLS 1.3 werden Cipher-Suiten mit der Namenskonvention TLS_AEAD_Hash angegeben, wobei AEAD ein
authentisiertes Verschlüsselungsverfahren (authenticated encryption with associated data, kurz AEAD) für
das Record-Protokoll und Hash eine Hashfunktion für die Nutzung mit HMAC (Keyed-Hash Message
Authentication Code) und HKDF (HMAC-based Extract-and-Expand Key Derivation Function) im HandshakeProtokoll bezeichnet.
Die folgenden Cipher-Suiten werden empfohlen:
{+Tabelle 12: Empfohlene Cipher-Suiten für TLS 1.3+}

Cipher-Suite
{+TLS_AES_128_GCM_SHA256+}
{+TLS_AES_256_GCM_SHA384+}
{+TLS_AES_128_CCM_SHA256+}

{+3.4.5+}
{+3.4.5.1+}

IANA-Nr.

[\-Referenziert Verwendung-]
[\-in-]
[\-bis-]{+Referenz+}

[\-TLS_AES_128_GCM_SHA256-]{+Verwendung bis+}

0x13,0x01

[\-[RFC8446]\-]{+[RFC 8446]\+}

[\-2027+-]

[\-TLS_AES_256_GCM_SHA384-]{+2030++}

0x13,0x02

[\-[RFC8446]\-]

[\-2027+-]

[\-TLS_AES_128_CCM_SHA256-]

0x13,0x04

[\-[RFC8446]\-]{+[RFC 8446]\+}
{+[RFC 8446]\+}

[\-2027+-]{+2030++}
{+2030++}

[\-Tabelle 12: Empfohlene Cipher-Suiten für TLS 1.3-]{+Weitere Empfehlungen+}
{+Die Heartbeat-Erweiterung+}

{+Es wird empfohlen, die in [RFC 6520] spezifizierte Heartbeat-Erweiterung nicht zu verwenden (vgl.+}
{+Abschnitt 3.3.4.6).+}

3\.5

@@ -1530,20 +1447,22 @@ Authentisierung der Kommunikationspartner

Das TLS-Protokoll bietet die folgenden drei Möglichkeiten zur Authentisierung der
Kommunikationspartner:
{+•+}

[\-16-]{+Authentisierung beider Kommunikationspartner+}

[\-Bundesamt für Sicherheit in der Informationstechnik-]{+•+}

[\-Empfehlungen 3-]{+Nur serverseitige Authentisierung+}

{+•+}

{+Keine Authentisierung+}

[\-• Authentisierung beider Kommunikationspartner-]
[\-• Nur serverseitige Authentisierung-]
[\-• Keine Authentisierung-]
Die Notwendigkeit einer Authentisierung ist abhängig von der jeweiligen Anwendung. Bei der Verwendung
von TLS im Web ist im Allgemeinen zumindest eine Authentisierung des Servers notwendig. Bei der
Verwendung in geschlossenen Systemen (VPN o. ä.) ist zumeist eine beidseitige Authentisierung notwendig.
Die Technische Richtlinie [TR-02103] [\-enhält-]{+enthält+} Empfehlungen zu X.509-Zertifikaten und
Zertifizierungspfadvalidierung.
Für die Authentisierung innerhalb von Projekten des Bundes sind die Vorgaben der Technischen Richtlinie
[TR-03116-4] in der jeweils aktuellen Fassung zu beachten.
@@ -1553,10 +1472,18 @@ Für die Authentisierung innerhalb von Projekten des Bundes sind die Vorgaben de
Domainparameter und Schlüssellängen

Die Domainparameter und Schlüssellängen für
{+•+}

{+statische Schlüsselpaare der Kommunikationspartner,+}

{+•+}

{+ephemere Schlüsselpaare bei der Verwendung von Cipher-Suiten mit Perfect Forward Secrecy, und+}

{+•+}

{+Schlüsselpaare für die Signatur von Zertifikaten+}

[\-• statische Schlüsselpaare der Kommunikationspartner,-]
[\-• ephemere Schlüsselpaare bei der Verwendung von Cipher-Suiten mit Perfect Forward Secrecy, und-]
[\-• Schlüsselpaare für die Signatur von Zertifikaten-]
müssen den Empfehlungen in Teil 1 dieser Technischen Richtlinie (siehe [TR-02102-1]) entsprechen.

3\.6.1
@@ -1564,82 +1491,69 @@ müssen den Empfehlungen in Teil 1 dieser Technischen Richtlinie (siehe [TR-0210
Schlüssellängen

Es wird empfohlen, mindestens die folgenden Schlüssellängen zu verwenden:

{+14+}

{+Bundesamt für Sicherheit in der Informationstechnik+}

{+3 Empfehlungen+}

{+Tabelle 13: Empfohlene Mindestschlüssellängen für das TLS-Handshakeprotokoll+}

Algorithmus

Minimale
Schlüssellänge

Verwendung spätestens
ab

Verwendung bis

Signaturschlüssel für Zertifikate und Schlüsseleinigung
ECDSA
[\-DSS-]
[\-RSA-]

250 Bit

[\-2027+-]

[\-2000 Bit-]{+2030++}

[\-2022-]{+DSS+}

3000 Bit

2023

[\-2000 Bit-]{+2029+}

{+RSA+}

3000 Bit

[\-2027+-]
2023

[\-2024-]

[\-2027+-]{+2030++}

Statische und ephemere Diffie-Hellman-Schlüssel
ECDH
[\-DH-]

250 Bit

[\-2027+-]

[\-2000 Bit-]

[\-2022-]{+DH+}

3000 Bit

{+2030++}
2023

[\-2027+-]

[\-Tabelle 13: Empfohlene Mindest-Schlüssellängen für das TLS-Handshakeprotokoll-]{+2030++}

Hinweis: Ist ein Schlüsselpaar statisch, so wird es mehrfach für neue Verbindungen wiederverwendet. Im
Gegensatz dazu bedeutet ephemer, dass für jede neue Verbindung auch ein neues Schlüsselpaar erzeugt und
verwendet wird. Ephemere Schlüssel müssen nach Verbindungsende unbedingt sicher gelöscht werden,
siehe dazu auch Abschnitt 4.2. Soll eine Verbindung die Eigenschaft Perfect Forward Secrecy erfüllen, müssen
ausschließlich ephemere Schlüsselpaare verwendet werden.

[\-Bundesamt für Sicherheit in der Informationstechnik-]

[\-17-]

[\-3 Empfehlungen-]

[\-Wichtiger Hinweis: Es ist sinnvoll, für RSA, DH und DSS eine Schlüssellänge von 3000 Bit zu nutzen, um ein-]
[\-gleichartiges Sicherheitsniveau für alle asymmetrischen Verfahren zu erreichen. Eine Schlüssellänge von-]
[\-mindestens 3000 Bit ist damit ab dem Jahr 2023 für kryptographische Implementierungen verbindlich,-]
[\-wenn sie zur vorliegenden Technischen Richtlinie konform sein sollen. Jede Schlüssellänge von mindestens-]
[\-2000 Bit bleibt aber für Systeme mit einer Lebensdauer bis zum Jahr 2022 konform zur vorliegenden-]
[\-Technischen Richtlinie. Als Übergangsregelung ist außerdem die Nutzung von RSA-Schlüsseln mit einer-]
[\-Länge ab 2000 Bit bis Ende 2023 ebenfalls noch konform. Es handelt sich dabei um die empfohlene MindestSchlüssellänge für RSA, DH und DSS. Weitere Informationen finden sich in den Bemerkungen 4 und 5 in-]
[\-Kapitel 3 in [TR-02102-1].-]
Bemerkung: Die Empfehlungen in dieser Technischen Richtlinie sind geeignet, um das in Abschnitt 3.1.2
genannte Sicherheitsniveau von [\-zurzeit 100-]{+120+} Bit zu erreichen.
Der Vorhersagezeitraum für die vorliegenden Empfehlungen beträgt 7 Jahre. Geeignete Empfehlungen für
deutlich größere Zeiträume, wie sie in anderen öffentlich verfügbaren Dokumenten zu finden sind, sind
naturgemäß sehr schwierig, da zukünftige kryptographische Entwicklungen über längere Zeiträume nicht
@@ -1655,17 +1569,20 @@ Bei der Verwendung von elliptischen Kurven werden stets kryptographisch starke K
Körpern der Form Fp (p prim) empfohlen. Zusätzlich wird empfohlen, nur named curves (siehe Abschnitt
„Supported Groups Registry“ in [IANA]) einzusetzen, um Angriffe über nicht verifizierte schwache
Domainparameter zu verhindern. Die folgenden named curves werden empfohlen:
{+•+}

[\-•-]brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 (siehe [\-[RFC5639]\-]{+[RFC 5639]\+} und [\-[RFC7027])-]
[\-Sollten diese Kurven nicht verfügbar sein, so können auch die folgenden Kurven eingesetzt werden:-]{+[RFC 7027])+}

{+Sollten diese Kurven nicht verfügbar sein, so können auch die folgenden Kurven eingesetzt werden:+}
•[\-secp256r1, secp384r1-]

[\-18-]{+secp256r1, secp384r1, secp521r1+}

Bundesamt für Sicherheit in der Informationstechnik

[\-Schlüssel-]{+15+}

{+4 Schlüssel+} und Zufallszahlen[\-4-]

4

@@ -1679,7 +1596,7 @@ Private kryptographische Schlüssel, insbesondere statische Schlüssel und Signa
gespeichert und verarbeitet werden. Dies bedeutet u. a. den Schutz vor Kopieren, missbräuchlicher Nutzung
und Manipulation der Schlüssel. Eine sichere Schlüsselspeicherung kann zum Beispiel durch die
Verwendung zertifizierter Hardware (Chipkarte, HSM) gewährleistet werden.
Ebenso müssen die öffentlichen Schlüssel von als vertrauenswürdig [\-erkannten-]{+anerkannten+} Stellen (Vertrauensanker)
manipulationssicher gespeichert werden.

4\.2
@@ -1698,116 +1615,74 @@ Zufallszahlen
Für die Erzeugung von Zufallszahlen, zum Beispiel für kryptographische Schlüssel oder die
Signaturerzeugung, müssen geeignete Zufallszahlengeneratoren eingesetzt werden.
Empfohlen wird ein Zufallszahlengenerator aus einer der Klassen DRG.3, DRG.4, PTG.3 oder NTG.1 gemäß
[\-[AIS20/31],-]{+[AIS 20/31],+} vgl. auch Kapitel [\-9-]{+8+} in Teil 1 dieser Technischen Richtlinie [TR-02102-1].

[\-Bundesamt für Sicherheit in der Informationstechnik-]{+16+}

[\-19-]{+Bundesamt für Sicherheit in der Informationstechnik+}

Literaturverzeichnis

Literaturverzeichnis
[\-ID-]
[\-AIS20/31-]
[\-BDF14-]{+[AIS 20/31] BSI: AIS 20/31 – A proposal for: Functionality classes for random number generators, 2011+}
{+[BDF14] K. Bhargavan, A. Delignat-Lavaud, C. Fournet, A. Pironti, P.-Y. Strub: Triple Handshake and Cookie+}
{+Cutters: Breaking and Fixing Authentication over TLS, IEEE Symposium on Security and Privacy, 2014+}
{+[CRIME] J. Rizzo, Th. Duong: The+} CRIME [\-IANA-]
[\-LP19-]
[\-RFC2246-]
[\-RFC4346-]
[\-RFC5246-]
[\-RFC5289-]
[\-RFC5487-]
[\-RFC5489-]
[\-RFC5639-]
[\-RFC5746-]
[\-RFC6066-]
[\-RFC6176-]
[\-RFC6655-]
[\-RFC7027-]
[\-RFC7251-]
[\-RFC7465-]
[\-RFC7568-]
[\-RFC7627-]
[\-RFC7919-]
[\-RFC8422-]
[\-RFC8442-]
[\-RFC8446-]
[\-RFC8734-]
[\-SBK17-]

[\-20-]{+attack, Ekoparty Security Conference, 2012+}
{+[FIPS 186-5] National Institute of Standards and Technology: Federal Information Processing Standards+}
{+FIPS PUB 186-5, Digital Signature Standard (DSS), 2023+}
{+[IANA] IANA: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml+}
{+[RFC 2246] T. Dierks, C. Allen: RFC 2246, The TLS Protocol Version 1.0, 1999+}
{+[RFC 4346] T. Dierks, E. Rescorla: RFC 4346, The Transport Layer Security (TLS) Protocol Version 1.1, 2006+}
{+[RFC 5246] T. Dierks, E. Rescorla: RFC 5246, The Transport Layer Security (TLS) Protocol Version 1.2, 2008+}
{+[RFC 5289] E. Rescorla: RFC 5289, TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois+}
{+Counter Mode (GCM), 2008+}
{+[RFC 5487] M. Badra: RFC 5487, Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois+}
{+Counter Mode, 2009+}
{+[RFC 5489] M. Badra, I. Hajjeh: RFC 5289, ECDHE_PSK Cipher Suites for Transport Layer Security (TLS), 2009+}
{+[RFC 5639] M. Lochter, J. Merkle: RFC 5639, Elliptic Curve Cryptography (ECC) Brainpool Standard Curves+}
{+and Curve Generation, 2010+}
{+[RFC 5746] E. Rescorla, M. Ray, S. Dispensa, N. Oskov: RFC 5746, Transport Layer Security (TLS)+}
{+Renegotiation Indication Extension, 2010+}
{+[RFC 6066] D. Eastlake 3rd: RFC 6066, Transport Layer Security (TLS) Extensions: Extension Definitions, 2011+}
{+[RFC 6176] S. Turner, T. Polk: RFC 6176, Prohibiting Secure Sockets Layer (SSL) Version 2.0, 2011+}
{+[RFC 6655] D. McGrew, D. Bailey: RFC 6655, AES-CCM Cipher Suites for Transport Layer Security (TLS), 2012+}
{+[RFC 7027] M. Lochter, J. Merkle: RFC 7027, Elliptic Curve Cryptography (ECC) Brainpool Curves for+}
{+Transport Layer Security (TLS), 2013+}
{+[RFC 7251] D. McGrew, D. Bailey, M. Campagna, R. Dugal: RFC 7251, AES-CCM Elliptic Curve Cryptography+}
{+(ECC) Cipher Suites for TLS, 2014+}
{+[RFC 7465] A. Popov: RFC 7465, Prohibiting RC4 Cipher Suites, 2015+}
{+[RFC 7568] R. Barnes, M. Thomson, A. Pironti, A. Langley: RFC 7568, Deprecating Secure Sockets Layer+}
{+Version 3.0, 2015+}
{+[RFC 7627] K. Bhargavan, A. Delignat-Lavaud, A. Pironti, A. Langley, M. Ray: RFC 7627, Transport Layer+}
{+Security (TLS) Session Hash and Extended Master Secret Extension, 2015+}
{+[RFC 7919] D. Gillmor: RFC 7919, Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for+}
{+Transport Layer Security (TLS), 2016+}
{+[RFC 8422] Y. Nir, J. Josefsson, M. Pegourie-Gonnard: RFC 8422, Elliptic Curve Cryptography (ECC) Cipher+}
{+Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier, 2018+}
{+[RFC 8442] J. Mattsson, D. Migault: RFC 8442, ECDHE_PSK with AES-GCM and AES-CCM Cipher Suites for+}
{+TLS 1.2 and DTLS 1.2, 2018+}
{+[RFC 8446] E. Rescorla: RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3, 2018+}

{+17+}

[\-Referenz-]
[\-BSI: AIS 20/31 – A proposal for: Functionality classes for random number generators,-]
[\-September 2011-]
[\-K. Bhargavan, A. Delignat-Lavaud, C. Fournet, A. Pironti, P.-Y. Strub: Triple Handshake and-]
[\-Cookie Cutters: Breaking and Fixing Authentication over TLS, IEEE Symposium on Security-]
[\-and Privacy, 2014-]
[\-J. Rizzo, Th. Duong: The CRIME attack,-]
[\-https://www.ekoparty.org/archive/2012/CRIME_ekoparty2012.pdf, September 2012-]
[\-IANA: http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml-]
[\-G. Leurent, T. Peyrin: From Collisions to Chosen-Prefix Collisions – Application to Full SHA1, EUROCRYPT 2019, Lecture Notes in Computer Science, vol. 11478, 2019-]
[\-T. Dierks, C. Allen: RFC 2246, The TLS Protocol Version 1.0, Januar 1999-]
[\-T. Dierks, E. Rescorla: RFC 4346, The Transport Layer Security (TLS) Protocol Version 1.1,-]
[\-April 2006-]
[\-T. Dierks, E. Rescorla: RFC 5246, The Transport Layer Security (TLS) Protocol Version 1.2,-]
[\-August 2008-]
[\-E. Rescorla: RFC 5289, TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois-]
[\-Counter Mode (GCM), August 2008-]
[\-M. Badra: RFC 5487, Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES-]
[\-Galois Counter Mode, März 2009-]
[\-M. Badra, I. Hajjeh: RFC 5289, ECDHE_PSK Cipher Suites for Transport Layer Security (TLS),-]
[\-März 2009-]
[\-M. Lochter, J. Merkle: RFC 5639, Elliptic Curve Cryptography (ECC) Brainpool Standard-]
[\-Curves and Curve Generation, März 2010-]
[\-E. Rescorla, M. Ray, S. Dispensa, N. Oskov: RFC 5746, Transport Layer Security (TLS)-]
[\-Renegotiation Indication Extension, Februar 2010-]
[\-D. Eastlake 3rd: RFC 6066, Transport Layer Security (TLS) Extensions: Extension Definitions,-]
[\-Januar 2011-]
[\-S. Turner, T. Polk: RFC 6176, Prohibiting Secure Sockets Layer (SSL) Version 2.0, März 2011-]
[\-D. McGrew, D. Bailey: RFC 6655, AES-CCM Cipher Suites for Transport Layer Security (TLS),-]
[\-Juli 2012-]
[\-M. Lochter, J. Merkle: RFC 7027, Elliptic Curve Cryptography (ECC) Brainpool Curves for-]
[\-Transport Layer Security (TLS), Oktober 2013-]
[\-D. McGrew, D. Bailey, M. Campagna, R. Dugal: RFC 7251, AES-CCM Elliptic Curve-]
[\-Cryptography (ECC) Cipher Suites for TLS, Juni 2014-]
[\-A. Popov: RFC 7465, Prohibiting RC4 Cipher Suites, Februar 2015-]
[\-R. Barnes, M. Thomson, A. Pironti, A. Langley: RFC 7568, Deprecating Secure Sockets Layer-]
[\-Version 3.0, Juni 2015-]
[\-K. Bhargavan, A. Delignat-Lavaud, A. Pironti, A. Langley, M. Ray: RFC 7627, Transport Layer-]
[\-Security (TLS) Session Hash and Extended Master Secret Extension, September 2015-]
[\-D. Gillmor: RFC 7919, Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for-]
[\-Transport Layer Security (TLS), August 2016-]
[\-Y. Nir, J. Josefsson, M. Pegourie-Gonnard: RFC 8422, Elliptic Curve Cryptography (ECC)-]
[\-Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier, August 2018-]
[\-J. Mattsson, D. Migault: RFC 8442, ECDHE_PSK with AES-GCM and AES-CCM Cipher Suites-]
[\-for TLS 1.2 and DTLS 1.2, September 2018-]
[\-E. Rescorla: RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3, August 2018-]
[\-L. Bruckert, J. Merkle, M. Lochter: RFC 8734, Elliptic Curve Cryptography (ECC) Brainpool-]
[\-Curves for Transport Layer Security (TLS) Version 1.3, February 2020-]
[\-M. Stevens, E. Bursztein, P. Karpman, A. Albertini, Y. Markov: The first collision for full SHA1. CRYPTO 2017, Lecture Notes in Computer Science, vol. 10401, 2017-]
Bundesamt für Sicherheit in der Informationstechnik

Literaturverzeichnis

[\-SSLv2-]
[\-SSLv3-]
[\-TR-02102-1-]
[\-TR-02103-]
[\-TR-03116-4-]{+[RFC 8734] L. Bruckert, J. Merkle, M. Lochter: RFC 8734, Elliptic Curve Cryptography (ECC) Brainpool Curves+}
{+for Transport Layer Security (TLS) Version 1.3, 2020+}
{+[RFC 8996] K. Moriarty, S. Farrell: RFC 8996, Deprecating TLS 1.0 and TLS 1.1, 2021+}
{+[SSLv2]\+} Netscape: Hickman, Kipp: [\-"The-]{+The+} SSL [\-Protocol", April-]{+Protocol,+} 1995
{+[SSLv3]\+} Netscape: A. Frier, P. Karlton, P. Kocher: [\-"The-]{+The+} SSL 3.0 [\-Protocol",-]{+Protocol,+} 1996
{+[TR-02102-1]\+} BSI: Technische Richtlinie TR-02102-1, Kryptographische Verfahren: Empfehlungen und
Schlüssellängen, [\-2021-]{+2024+}
{+[TR-02103]\+} BSI: Technische Richtlinie TR-02103, X.509-Zertifikate und Zertifizierungspfadvalidierung,
Version 1.0, 2020
{+[TR-03116-4]\+} BSI: Technische Richtlinie TR-03116-4, Kryptographische Vorgaben für Projekte der
Bundesregierung, Teil 4: Kommunikationsverfahren in Anwendungen, [\-2021-]{+2024+}

[\-Bundesamt für Sicherheit in der Informationstechnik-]{+18+}

[\-21-]{+Bundesamt für Sicherheit in der Informationstechnik+}