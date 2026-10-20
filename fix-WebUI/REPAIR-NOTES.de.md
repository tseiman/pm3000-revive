# PM3000 Revive: Übergabe der WebUI-Reparatur an Hermes

Stand: 20. Oktober 2026. Zusammenfassung des gesamten bisherigen Reparaturverlaufs, ergänzt um einen tatsächlichen Dateivergleich der abschließend gesicherten Webdateien mit Firmware 2.0.1.23.

## 1. Auftrag und Arbeitsgrenzen

Die alte Avocent-PM3000-Weboberfläche soll mit heutigen Browsern wieder funktionieren. Die bisherigen Änderungen sind schrittweise Kompatibilitätsreparaturen, keine vollständige Modernisierung und keine Freigabe sämtlicher Verwaltungs- oder Schaltfunktionen.

Für Hermes gilt: zunächst lokal analysieren, konsolidieren, nachvollziehbare Patches und Tests abliefern. Keine eigenständigen Änderungen auf der PDU, keine Firmwareinstallation, kein Neustart, kein Austausch der Authentifizierung und keine Steckdosenaktionen. Der Benutzer verlangt vor tatsächlichen Änderungen am Gerät eine Abstimmung. Korrekturscripte und lokale Artefakte dürfen vorbereitet werden. Zugangsdaten und private Schlüssel nicht in Repository, Fixtures oder Logs aufnehmen.

Bei manueller Textbearbeitung mcedit verwenden und empfehlen. Shellbefehle vollständig auf einer Zeile schreiben, keine Backslash-Zeilenfortsetzungen.

## 2. Was hier tatsächlich vorliegt

- `webui-2.0.1.23-to-tested-state.patch`: konsolidierter Unified Diff für `scripts-20150511.js` und `transformation.xsl`, gegen die Originaldateien aus dem gelieferten Firmwareimage.
- `file-hashes.json`: SHA-256 und Größen der Original- und Sicherungsdateien.
- Diese Reparaturnotizen mit Ursachen, Einzelschritten, Grenzen und weiterem Arbeitsauftrag.

Der Patch bildet den tatsächlich gesicherten Gerätestand ab. Er enthält deshalb auch einzelne schon vor dieser Reparatur vorhandene Debugänderungen. Er ist kein vollständig bereinigter Upstream-Patch.

Lokale Verifikation bei dieser Übergabe: Der Patch wurde in einem separaten Arbeitsverzeichnis erfolgreich auf beide Originaldateien angewendet. Beide Ergebnisse stimmen nach Vereinheitlichung der Zeilenenden mit der aktuellen Sicherung überein. Der Diff ist textuell mit LF normalisiert; die Hashliste beschreibt dagegen die tatsächlichen Eingabedateien bytegenau. Die aktive JS-Sicherung wurde zusätzlich mit `node --check` erfolgreich auf Syntax geprüft. Dies sind keine Gerätetests.

**Wichtige zusätzliche Abhängigkeit:** `document.load_client_injection.js` und die bereits früher veränderte `xwire/xWireClientFull.jsb` sind nicht im Zwei-Dateien-Patch enthalten. Ein frisches Herstellerimage ist mit diesem Patch allein deshalb nicht fertig repariert. Die Kompatibilitätsdatei und xWire müssen separat beschafft, verglichen und getestet werden.

## 3. Hardware und System

| Bestandteil | Beobachteter Stand |
| --- | --- |
| Gerät | Avocent PM3000 PDU |
| Firmwareimage | zImage_pmhd_2.0.1.23.bin, Build vom 11. Mai 2015 |
| CPU | PowerPC e300c3, ca. 328 MHz, 32-Bit-Big-Endian-Userspace |
| Kernel | Linux 2.6.23 |
| libc | glibc 2.3.5 |
| Webserver | Apache 2.2.23, Prefork |
| TLS-Bibliothek | OpenSSL 1.0.1l |
| Werkzeuge | BusyBox 1.5.0; zusätzlich GNU Wget 1.9.1 |
| Benutzerpartition | /mnt/hdUser, JFFS2, 4 MiB |
| Konfiguration | /etc liegt im beobachteten Flash-Boot auf einer separat eingebundenen Konfigurationspartition |
| Laufzeitdaten | /var ist tmpfs, Limit ca. 28,6 MiB |

`/var` war vor dem Neustart voll. Das erschwerte Transfers und Here-Documents und war eine mögliche zusätzliche Fehlerquelle. Nach dem Neustart war es wieder klein; die konkrete frühere Ursache wurde nicht ermittelt. Nicht pauschal löschen und nicht jeden Loginfehler auf das Passwort zurückführen.

## 4. Webserver und Dateipfade

```text
/etc/apache2/httpd.conf
/etc/apache2/conf.d/listen.conf
/etc/apache2/extra/httpd-avworks.conf
/etc/apache2/extra/httpd-ssl.conf
/usr/share/apache2/htdocs/index.xml
/usr/share/apache2/htdocs/transformation.xsl
/usr/share/apache2/htdocs/scripts-20150511.js
/usr/share/apache2/htdocs/document.load_client_injection.js
/usr/share/apache2/htdocs/xwire/xWireClientFull.jsb
```

DocumentRoot ist `/usr/share/apache2/htdocs`, DirectoryIndex ist `index.xml`. Das Dokument enthält:

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="transformation.xsl"?>
<index></index>
```

Apache lädt Herstellermodule `mod_avtrans.so` und `mod_fileTransfer.so`. `/appliance/avtrans` wird über den Handler `avtrans` bedient; `/appliance/fileTransfer` über `filetransfer`. Für DSView existieren separate `/plugin/`-Pfade und ein separater SSL-VirtualHost auf Port 3502. Diese wurden nicht verändert.

Ein neues Zertifikat aus der privaten PKI wurde vom Benutzer eingerichtet. HTTPS konnte anschließend mit normaler Zertifikatsprüfung und HTTP 200 abgerufen werden. Interne Hostnamen und konkrete Zertifikatspfade wurden für die öffentliche Ablage entfernt. TLS- und Browserabsturzprobleme dürfen nicht mit den nachgewiesenen JavaScriptfehlern vermischt werden.

## 5. Datenfluss und Login-Diagnose

1. Der Browser lädt `index.xml` und transformiert es mit `transformation.xsl`.
2. Die Hauptseite bindet Kompatibilitäts-JS, Haupt-JS und xWire ein.
3. `XML_request()` baut ein Avocent-XML-Dokument.
4. `load_XML()` sendet dieses per POST an `/appliance/avtrans`.
5. Der Content-Type ist historisch `application/x-www-form-urlencoded`, obwohl der Body unmittelbar XML enthält. Bei der Diagnose wurde das unverändert nachgebildet.
6. `processReqChange()` parst die Antwort mit `DOMParser` als `text/xml`.
7. xWire lädt und cached die XSL-Datei und verwendet `XSLTProcessor.transformToDocument()`.
8. `transformToString()` serialisiert das Ergebnis mit `XMLSerializer`.
9. Die Anwendung setzt HTML über `innerHTML` ein und zerlegt es zusätzlich mit empfindlichen Stringmustern.

Die Login-Anfrage für das Formular lässt sich strukturell so darstellen; keine realen Zugangsdaten in Tests übernehmen:

```xml
<avtrans><sid></sid><action>login</action><agents><src>wmi</src><dest>controller</dest></agents><paths><path>units.topology</path></paths><payload><section structure="login"><parameter id="username" structure="RWtext"><value>TEST_USER</value></parameter><parameter id="password" structure="password"><value>TEST_PASSWORD</value></parameter></section></payload></avtrans>
```

Mit dem temporären Testkonto gelang die direkte Anmeldung: Antwortaktion `header`, nichtleere SID, kein Fehler. Das Passwort war somit nicht die Ursache des damaligen Browserabbruchs. Session-IDs wurden nicht in den Bericht aufgenommen.

Eine lokale lxml-Transformation dieser Antwort enthielt alle 18 vom JS erwarteten Stringmuster. Das erwies sich **nicht als vollständige Browsernachbildung**: Im realen Browser entstanden zusätzliche HTML-/HEAD-/BODY-/TBODY-Strukturen und andere Serialisierungsdetails.

## 6. Bereits vorhandener Reparaturversuch von 2019

Auf der PDU lagen vor Beginn bereits `document.load_client_injection.js`, Änderungen an XSL/Hauptscript und xWire-Debugausgaben. Zeitstempel mehrerer Dateien waren September 2019. Diese Änderungen sind von den aktuellen Reparaturen zu unterscheiden.

Die XSL bindet vor dem Hauptscript ein:

```xml
<script language="JavaScript" src="document.load_client_injection.js"></script>
<script language="JavaScript" src="scripts-20150511.js"></script>
<script language="JavaScript" src="xwire/xWireClientFull.jsb"></script>
```

Referenz des damals übernommenen Userscripts:
https://gist.github.com/ixs/58381ed5f8109b6a988a2eb06036b348

Das Script ergänzt `Document.prototype.load` über XMLHttpRequest. xWire benötigt die Funktion in `abstractBrowser_getXSLStylesheet()` und ruft `doc.load(urlOrDocument)` auf. Der vermeintlich fehlende `.load()`-Aufruf lag in xWire, nicht im Hauptscript.

Die damals gepostete Kompatibilitätsdatei enthält:

- Userscript-Metadaten; `@match` ist bei direkter Script-Einbindung wirkungslos.
- Einen Template-String mit der Implementierung und nachträgliche Script-Injektion.
- Den inzwischen veralteten Mutation-Event `DOMNodeInserted`.
- Einfügen des geklonten XML-Wurzelelements über `appendChild`.

xWire erzeugt an dieser Stelle ein Dokument mit `createDocument("", "test", null)` und entfernt dessen Wurzel sofort. Deshalb war die zwischenzeitliche Vermutung, der Fix würde beim ersten Laden zwangsläufig eine zusätzliche verschachtelte Wurzel erzeugen, für diesen Codepfad nicht zutreffend.

**Noch offen:** Kompatibilitätscode als direkt ausgeführtes Script ohne Userscript-Injektionshülle sauber neu aufsetzen; Timing, Fehlerfälle und mehrfaches Laden testen. Im Verlauf wurde diese Datei nicht neu implementiert. Keine unklare Lizenz des Gists stillschweigend als MIT behandeln.

## 7. Reparaturen in chronologischer Reihenfolge

Zeilennummern aus Konsolenmeldungen verschoben sich durch Patches. Für die Umsetzung nach Funktionsnamen und Codekontext suchen.

### 7.1 HTML-Ausgabe für die XSL-Transformation

Ausgangsfehler: `Extra content at the end of the document`, Zeile 3, Spalte 387. Die Login-Vorlage liefert eine Tabelle plus ein separates verborgenes `requestMsg`-DIV; die Header-Vorlage viele nebeneinanderstehende DIVs.

Direkt unter dem öffnenden `xsl:stylesheet` wurde eingefügt:

```xml
<xsl:output method="html" encoding="UTF-8" omit-xml-declaration="yes"/>
```

Die XML-Fehlerkette wurde damit durch nachfolgende DOM-Fehler abgelöst. Diese globale Einstellung beeinflusst auch andere Vorlagen und muss Bestandteil der Regressionstests sein. Sie ist nicht losgelöst von den folgenden JS-Änderungen zu betrachten. Bei einer späteren Architekturverbesserung kann `transformToFragment()` statt Dokument-Serialisierung untersucht werden; das wurde bisher nicht umgesetzt.

### 7.2 Benutzername und Passwort in get_elements()

Fehler: `text_filter`, Zugriff auf `text.length`, nachdem `.value` undefined war.

Die zwei festen `childNodes[1]`-Fallunterscheidungen für Text-/Passwortfelder wurden durch gezielte Feldsuche ersetzt. Ein früher Zwischenpatch suchte auch beim Textarea-Zweig nur INPUT und wurde später korrigiert. Der abschließende Stand verwendet in beiden Zweigen:

```javascript
var input = parameters[i].getElementsByTagName(parameters[i].id == "textarea" ? "textarea" : "input")[0];
var p_id = input.id;
var p_value = input.value;
```

### 7.3 Enter-Taste beim Login und erste Navigationsfunktionen

Fehler beim Enter-Login: `login_button.childNodes[1].href` ist undefined.

```javascript
document.getElementById("login_button").getElementsByTagName("a")[0].href
```

Die vorhandene eval-/Pfadlogik blieb erhalten; sie wurde nicht neu entworfen.

Fehler in `toggle_all()`: `subelements[0].childNodes[1].className`.
In diesen vier Funktionen wurden strukturelle `.childNodes` auf `.children` umgestellt:

- `toggle()`
- `toggle_open()`
- `toggle_all()`
- `toggle_loop()`

### 7.4 Weitere Navigation

Fehler: `first_navcall()` erhält einen undefinierten Link und scheitert an `link.previousSibling`.

In `change_tree()`, `first_navcall()`, `navcall()` und `parent_name()` erfolgten die passenden strukturellen Ersetzungen:

```text
.childNodes       -> .children
.previousSibling  -> .previousElementSibling
.nextSibling      -> .nextElementSibling
```

### 7.5 Größenberechnung und Tabellenzeilen

- `form_size()`: vier `.firstChild` durch `.firstElementChild` ersetzt; Fehler war fehlendes `.style.width`.
- `getRows()` (großes R): `table.childNodes` durch `table.children` ersetzt; Fehler war `cells[i].style.display`.
- `resetBGcolor()`: zwei `.childNodes` und vier `.firstChild` auf Elementzugriffe umgestellt; Fehler war `rows[i].style.backgroundColor`.

### 7.6 Popup-Positionierung

Fehler in `getPopupLocation()`: `currentRowObj.lastChild.firstChild.firstChild` ergibt null.

```javascript
actionObj = currentRowObj.lastElementChild.firstElementChild.firstElementChild;
```

Nur diese Zeile wurde verändert. Bestehende Parent-Ketten und Layoutkonstanten sind weiterhin vorhanden und nicht generell validiert.

### 7.7 Ausgewählte Tabellenzeilen für Requests

`get_rows()` (kleines r, Unterstrich) ist eine andere Funktion als `getRows()`.
Fehler: `lines[i].firstChild.firstChild.checked`.
Hier wurden zwei `.childNodes` und zwei `.firstChild` auf Elementzugriffe umgestellt.

### 7.8 Abhängige Formularfelder

Fehler in `deckUpdateDependencies()`: `elem.firstChild.tagName.toLowerCase()`.

```javascript
if (elem.firstElementChild && elem.firstElementChild.tagName.toLowerCase() == 'span') {
    elem.firstElementChild.style.display = elem.style.display;
}
```

### 7.9 Originalformular und Änderungsvergleich

Fehler in `getTFOriValue()`: `parameter.split`, weil das Feld in `originalForm` fehlte.
Keine bloße undefined-Abfrage eingebaut: Stattdessen wurde die Erzeugung der Formularfeldliste korrigiert.

Derselbe Ausdruck wurde an drei Stellen ersetzt: `initializeForm()`, `getNewFormInfo()` und `XML_request()`.

```javascript
document.getElementById("form_table").firstElementChild.children
```

Vorher stand dort `.firstChild.childNodes`. Das erste Kind konnte ein Textknoten sein; damit konnte die serialisierte Formularvorlage keine sinnvolle Feldliste enthalten.

### 7.10 Gesamte strukturelle Traversierung innerhalb get_elements()

Nächster Fehler: `parameters[i].nextSibling.firstChild.firstChild`, unter anderem im Titel-Zweig.
Nach Lesen der vollständigen Funktion wurden dort die verbleibenden strukturellen Zugriffe gemeinsam ersetzt:

| Alter Ausdruck | Neuer Ausdruck | Anzahl beim damaligen Patch |
| --- | --- | --- |
| .childNodes | .children | 34 |
| .firstChild | .firstElementChild | 40 |
| .nextSibling | .nextElementSibling | 16 |
| .previousSibling | .previousElementSibling | 1 |

Die Ersetzung war auf `get_elements()` begrenzt. Die Zähler sind Patch-Vorbedingungen für den damaligen Zwischenstand, keine universellen Sollwerte für andere Firmwareversionen. Tiefe feste Elementindizes und Checkbox-Sonderfälle bleiben bestehen und brauchen weitere Tests.

### 7.11 Zeilenauswahl

Fehler in `select_check()`: `lines[i].style.visibility`.
Nur innerhalb dieser Funktion wurden einmal `.childNodes` und viermal `.firstChild` auf Elementzugriffe umgestellt.

## 8. Warum keine globale Ersetzung

`childNodes` enthält Text-, Kommentar- und Elementknoten. `.children` enthält nur Elemente. Die alte Oberfläche nahm vielerorts kompakte Elementfolgen an, während die beobachtete HTML-Verarbeitung Leertext und implizite Tabellenelemente mit sich bringt.

Ein globales Suchen/Ersetzen würde jedoch korrekte Textverarbeitung zerstören. Besonders `getTextValue()` durchläuft absichtlich `TEXT_NODE`, `ELEMENT_NODE` und BR-Knoten. Diese Funktion muss ihre Textknoten behalten.

Auch Elementzugriffe mit festen Indizes sind nicht automatisch robust: Ein zusätzliches TBODY oder ein anderes Layout kann weiterhin Probleme auslösen. Mittelfristig sind gezielte Selektoren, `.rows`/`.cells` an passenden Tabellentypen und explizite DOM-Verträge sinnvoll. Nicht gleichzeitig ohne Tests die gesamte Serialisierung und Feldlogik austauschen.

## 9. Praktisches Vorgehen auf der alten Appliance

- Ursprünglich lief `/` read-only; der Benutzer konnte es zum Bearbeiten auf rw remounten und anschließend wieder ro setzen. Aktive Mounts prüfen, nicht pauschal dauerhaft beschreibbar lassen.
- Statische JS-/XSL-Änderungen erforderten keinen Apache-Neustart. Browsercache bei jedem Test deaktivieren und vollständig neu laden.
- Sicherungen außerhalb des Webroots anlegen; `.bak` im Webroot könnte ausgeliefert werden.
- BusyBox-grep unterstützt `-r`, nicht `-R`.
- Here-Documents scheiterten bei vollem `/var` an temporären Dateien; TMPDIR allein half in der damaligen Sitzung nicht. Für PEM-Dateien funktionierte direktes `cat > datei` mit anschließender Eingabe und Strg+D als vorgeschlagener Ausweichweg. Für Reparaturscripte wurden deshalb häufig einzeilige awk-Programme ohne Here-Document verwendet.
- Ein erster awk-Patch scheiterte an unmaskierten geschweiften Klammern im Regex. Danach wurden Literalprüfungen mit `index()` und eng begrenzte Regex verwendet.
- Ein Ausrufezeichen in einem doppelt gequoteten Meldungstext löste interaktive Bash-History-Expansion aus. Solche Texte vermeiden.
- Patchscripte sicherten zuerst, prüften erwartete Trefferzahlen, erzeugten eine neue Datei, überschrieben erst dann das Ziel und verglichen mit `cmp`. Fehlende Treffer bedeuteten Abbruch, keine blinde weitere Ersetzung.
- Die alten Gerätetools bieten nicht zwingend heutige Optionen. Nicht ungeprüft moderne wget-, nc-, ssh- oder scp-Optionen einsetzen.

## 10. Gesicherte Ergebnisse und Grenzen

Beobachtet beziehungsweise berichtet:

- Vertrauenswürdige HTTPS-Verbindung und Abruf der Webdateien funktionierten.
- Direkte Backend-Anmeldung mit dem Testkonto funktionierte.
- Nach den Tabellen-/Navigationspatches meldete der Benutzer: Laden ohne Fehler; ein Großteil der GUI war sichtbar.
- Weitere Fehler traten erst beim Öffnen von Popups, Navigieren, Fokussieren/Bearbeiten von Feldern und bei Zeilenauswahl auf und wurden wie oben korrigiert.
- Der zuletzt gesicherte Hauptscriptstand besteht eine lokale `node --check`-Syntaxprüfung.

Nicht nachgewiesen:

- Vollständige Fehlerfreiheit aller Seiten und Feldtypen.
- Korrektes Speichern aller Einstellungen und Erhalt unveränderter Werte.
- Sichere Ausführung sämtlicher Steckdosenaktionen.
- Gleiches Verhalten in Safari, Firefox, Chrome und eingebettetem Browser.
- Vollständige Browseremulation durch lxml oder einen Syntaxcheck.

Der integrierte Browser stürzte laut Benutzer ab; das Browserwerkzeug meldete anschließend eine ausdrückliche URL-Policy-Sperre. Daher stammten die tatsächlichen Browserkonsolenmeldungen und manuellen Interaktionstests vom Benutzer. Eine bestehende SSH-Werkzeugsitzung war ebenfalls durch eine Ausführungsrichtlinie nicht bedienbar; die Gerätepatches führte der Benutzer selbst aus. Keine automatisierten End-to-End-Tests am Gerät behaupten.

## 11. Empfohlener Arbeitsauftrag für Hermes

1. Den beigefügten Diff gegen exakt die dokumentierte Firmwarebasis prüfen und in klar getrennte Änderungen zerlegen: historische Debugänderungen, XSL-Ausgabe, Kompatibilitätsloader, DOM-Reparaturen.
2. Den endgültigen Gerätestand als Referenz übernehmen, nicht die alte Zwischenkopie `scripts-20150511-fixed.js`. Diese war nur ein früher Teilstand.
3. Fehlende Dateien `document.load_client_injection.js` und die aktuelle xWire-Datei separat vom Benutzer anfordern beziehungsweise aus dessen expliziter Sicherung beziehen. Keine Annahme, dass die Firmwareoriginale deren Änderungen enthalten.
4. Einen reproduzierbaren Offline-Patcher erstellen. Bekannte Basis über Hash identifizieren; bei unbekanntem Stand abbrechen. Bereits angewendete Patches erkennen. Zeilenenden und Metadaten bewusst behandeln.
5. Statische Analyse aller verbliebenen strukturellen DOM-Zugriffe mit Liste der geprüften und ungeprüften Funktionen. Nicht pauschal alles ersetzen.
6. Tests mit echten Browser-DOMs und passenden Tabellen/Formularfixtures ergänzen. XSLT-Unterstützung des gewählten Browsers prüfen. HTML/TBODY-, Whitespace-, Checkbox-/Radiobutton- und verschachtelte Formularfälle nachbilden.
7. Für `get_elements()` XML semantisch prüfen: Text, Textarea, Passwort, Checkbox samt Kindfeldern, Select/Multiselect, Membership, Radiobox und Titelabschnitte. Werte, IDs und unveränderte Felder müssen erhalten bleiben.
8. Fehlende DOM-Elemente nicht stillschweigend überspringen und keine leeren Werte als Ersatz senden. Bei nicht unterstützter Struktur vor dem Absenden mit einer verständlichen Meldung abbrechen.
9. Debuglogs mit vollständigen Dokumenten entfernen oder hinter explizite Diagnoseoption stellen. Headerantworten enthalten Sitzungsinformationen; keine ungefilterten Produktionsantworten protokollieren.
10. Read-only-Navigation, Formularvorschau und XML-Request-Erzeugung zuerst testen. Schreibtests nur nach Freigabe an einer unkritischen Einstellung. Niemals Steckdosenaktionen als gewöhnlichen UI-Smoke-Test verwenden.
11. Abliefern: bereinigte Patches, genaue Basisversion/Hashes, Offline-Build-/Patchanleitung, Testbericht, verbleibende Unsicherheiten und Rückweg. Kein Autodeployment und keine eigenständigen Gerätetests.

Für eine größere Modernisierung ist langfristig eine neue Oberfläche über dem bestehenden Backend realistischer als eine sofortige Neuimplementierung der Hardwaresteuerung. REST und openHAB sind mögliche spätere Adapter. Die bisherige Reparatur liefert dafür Hinweise auf das Backend, ist aber noch keine spezifizierte öffentliche API.

## 12. Aktueller Betriebs- und Sicherungsstand

SSH wurde unabhängig von dieser WebUI-Arbeit modernisiert. Die produktive Port-, Dienst-, Schlüssel- und Dateianordnung wurde für die öffentliche Ablage entfernt und darf durch die WebUI-Reparatur nicht verändert werden. Private Hostschlüssel gehören nicht ins Projekt.

Der Benutzer erstellte vor der Bereinigung lokale und geräteseitige Sicherungen der relevanten Web- und SSH-Dateien. Konkrete private Speicherorte wurden entfernt. Die aktiven Webdateien wurden beim Erstellen dieser Übergabe tatsächlich gelesen und verglichen; ältere Sicherungen stellen unterschiedliche Zwischenstände dar und sind nicht automatisch mit Herstelleroriginal oder aktivem Endstand identisch.

## 13. Firmwareanalyse und Lizenzgrenze

Das Originalimage wurde lokal zerlegt: Herstellercontainer, gzip-Kernel, Device Tree, gzip-komprimiertes ext2-Dateisystem mit 70 MiB und U-Boot-Komponente. Updatelogik ruft `/sbin/checkImage` auf und enthält Hinweise auf trusted-key-Prüfungen. Ein neu gepacktes, sicher bootendes Community-Image ist noch nicht nachgewiesen.

Original-Webdateien sind aus dem Dateisystem extrahierbar; daraus folgt kein Recht zur beliebigen Veröffentlichung. Der beigefügte Patch enthält Hersteller-Codekontext. Vor öffentlicher Veröffentlichung Rechte und Lizenzen prüfen. MIT kann für eigene neue Projektanteile gelten, ersetzt aber keine Fremdlizenzen. Keine Herstellerfirmware, realen Zertifikatschlüssel oder ungefilterten Sicherungsarchive ungeprüft in GitHub übernehmen.
