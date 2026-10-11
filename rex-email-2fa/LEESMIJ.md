# Dares E-mail 2FA 1.2.2

Een WordPress-plugin voor wachtwoordlogin gevolgd door een eenmalige e-mailcode.
Nederlandse, donkere inlogkaart via `[rex_login]`; ook de gewone WordPress-login
wordt voor gekozen rollen beschermd. Vereist WordPress 6.2+, PHP 7.4+ en HTTPS.
Bedoeld voor één site; niet netwerkactiveren op WordPress Multisite.

## Installeren
1. WordPress → Plugins → Nieuwe plugin → Plugin uploaden.
2. Upload de ZIP, installeer en activeer.
3. Instellingen → Dares E-mail 2FA.
4. Verstuur een testmail naar je eigen account. Controleer daadwerkelijk je inbox.
   Een geslaagde wp_mail-aanroep bevestigt alleen dat de mail is aangenomen.
   Gebruik jullie bestaande SMTP-plugin; deze plugin bevat geen SMTP-server.
5. Wordfence → Login Security: deactiveer actieve Wordfence-2FA voor accounts die
   Dares E-mail 2FA gaan gebruiken. Zet verplichte Wordfence-2FA voor deze rollen uit
   (voor beheerders kan de instelling Optional nodig zijn). Firewall en scans
   blijven aan. Een verplichte Wordfence-2FA of actieve tweede 2FA-provider kan
   onze wachtwoordstap blokkeren. Test reCAPTCHA; schakel die alleen uit als de
   eigen inlogpagina hierdoor geblokkeerd wordt.
6. Houd je beheerderssessie open. Selecteer voor de eerste test uitsluitend de
   rol van een aparte testgebruiker, bijvoorbeeld Abonnee. Schakel verificatie in.
7. Klik Inlogpagina aanmaken, of plaats `[rex_login]` op een bestaande pagina.
8. Test in een privévenster: juist wachtwoord → mail → code → toegang. Test ook
   /wp-login.php. Kies daarna de overige rollen waarvoor codes verplicht zijn.

Verificatie staat na installatie uit. De bestaande inlogpagina blijft beschikbaar voor bestaande WordPress-accounts.
Registratie op uitnodiging is apart inschakelbaar, zoals hieronder beschreven.
Geen aanpassingen aan Wordfence-configuratie worden automatisch uitgevoerd.

## Beveiliging en gedrag
- Cryptografisch willekeurige zescijferige code; 5 minuten geldig.
- Alleen code-HMAC en token-HMAC worden in de database opgeslagen.
- De verificatie is gebonden aan een willekeurig browsercookie (HttpOnly,
  SameSite=Lax, Secure op HTTPS). Open de code in dezelfde browser.
- Maximaal 5 codepogingen per uitdaging; atomair verbruik tegen hergebruik.
- Maximaal 3 e-mails per uitdaging, met 60 seconden tussen opnieuw versturen.
- Opnieuw versturen maakt de vorige code ongeldig en verlengt de 5 minuten niet.
- Maximaal 10 e-mails per gebruiker per uur. De eigen login heeft daarnaast
  limieten per gebruikersnaam en direct IP-adres. Wordfence houdt zijn eigen
  bescherming op de standaard WordPress-login.
- Wijziging van e-mailadres of wachtwoord maakt een openstaande code ongeldig.
- Bestaande ingelogde sessies blijven bestaan; iedere nieuwe wachtwoordlogin
  voor gekozen rollen vereist de code.
- App-wachtwoorden en gewone wachtwoordauthenticatie via API/XML-RPC worden
  voor gekozen rollen geblokkeerd: API-klanten kunnen geen e-mailcode invoeren.
- Automatische logins die direct WordPress-authcookies zetten (bijvoorbeeld
  registratie- of SSO-plugins) worden voor gekozen rollen geblokkeerd totdat
  onze code is gecontroleerd. Test integraties op een staging-site.
- Pagina-inhoud is niet automatisch afgeschermd. Gebruik de bestaande
  toegangscontrole voor ledenpagina's als je inhoud alleen voor leden wilt tonen.
- Mailteksten ondersteunen {site}, {name} en {code}. Verzending via wp_mail.
- Verwijderde/verlopen uitdagingen en limieten worden elk uur door WP-Cron
  opgeruimd. Verlopen records geven ook vóór die opruiming geen toegang.

## Cache / hosting
Sluit de pagina met `[rex_login]`, wp-login.php en login-POST-verzoeken uit van
alle WordPress-, reverse-proxy- en CDN-caches. De plugin stuurt no-cacheheaders,
maar een cache vóór WordPress moet apart worden ingesteld.
Configureer HTTPS-detectie correct bij een reverse proxy. Een foutieve
HTTPS-detectie blokkeert inschakelen en inloggen.

## Noodherstel
Via Plesk-bestandsbeheer of SFTP kun je in wp-config.php, vóór de afsluitende
"stop editing"-regel, tijdelijk toevoegen:

    define('REX_EMAIL_2FA_DISABLE', true);

Je kunt ook de pluginmap `rex-email-2fa` tijdelijk hernoemen. Dit schakelt de
plugin uit; Wordfence blijft actief en zijn eventuele eigen 2FA blijft gelden.
Verwijder de noodinstelling zodra het probleem verholpen is.

## Gegevens / verwijderen
De tabellen `<prefix>rex2fa_challenges` en `<prefix>rex2fa_limits` bevatten tijdelijke
verificatiegegevens en HMAC-limietsleutels. Codes worden niet gelogd. E-mails
kunnen door je SMTP-plugin worden gelogd; beperk toegang tot die logs.
Deactiveren bewaart instellingen. Verwijderen via WordPress verwijdert de
plugininstellingen en de vier tabellen. Accounts worden niet automatisch verwijderd; uitnodigingsaccounts
zonder goedkeuring hebben geen rol. Hun aanvraagstatus blijft in gebruikersmeta
bewaard voor eventuele herinstallatie. De loginblokkade vereist een actieve plugin. Een aangemaakte inlogpagina blijft staan,
zodat je hem zelf kunt aanpassen of verwijderen.

## Validatie
Zie VALIDATIE.md voor uitgevoerde controles en praktische beperkingen.

GPL-2.0-or-later.

## Nieuw in 1.0.1: automatisch menu
Voeg de pagina met `[rex_login]` aan je bestaande WordPress-menu toe. De plugin
herkent deze pagina automatisch: gasten zien Inloggen, ingelogde gebruikers
zien Uitloggen. De uitloglink bevat een WordPress-nonce en stuurt terug naar
de homepage. Dit werkt voor klassieke menu’s en core Navigatie-linkblokken.
Een eigen link naar dezelfde pagina of wp-login.php wordt ook herkend.

Als een pagebuilder een afwijkende pagina of link gebruikt, geef het menu-item
de CSS-klasse `rex-login`. Bij klassieke menu’s kun je het veld CSS-klassen
aanvinken onder Scherminstellingen. Bij een Navigatie-linkblok staat de klasse
onder Geavanceerd. Losse HTML-links of menusystemen van pagebuilders die geen
WordPress-menufilters gebruiken vallen buiten deze automatische koppeling.

Bijwerken: upload de nieuwe ZIP en kies Huidige vervangen door geüploade.
Verwijder de plugin niet eerst: verwijderen wist de instellingen. De bestaande
inlogpagina en instellingen blijven bij een normale vervanging behouden.
Wis na de update de website-cache. Zorg dat ingelogde pagina’s en hun menu’s
niet met gasten worden gedeeld via een publieke pagina-cache.

## Nieuw in 1.1.0: uitnodigingen en accountgoedkeuring

### Inschakelen
1. Update de plugin via ZIP-upload → Huidige vervangen door geüploade. Je
   bestaande 2FA-instellingen en inlogpagina blijven behouden.
2. Ga naar Gebruikers → Uitnodigingen en aanvragen.
3. Vink Registratie op uitnodiging inschakelen aan. Kies de voorgestelde rol
   voor nieuwe goedgekeurde accounts en sla op. Standaard staat de functie uit.
4. Maak een persoonlijke link of een deelbare uitnodigingscode. Kies geldigheid
   (1–365 dagen) en optioneel een e-mailadres waaraan de uitnodiging gebonden is.
   Een persoonlijke link kan één keer worden gebruikt; een code heeft een
   instelbaar maximum van 1–1000 aanvragen.
5. Kopieer de code/link uit het eenmalige scherm. De code wordt als HMAC
   opgeslagen en is daarna niet opnieuw op te vragen. Maak zo nodig een nieuwe
   uitnodiging en trek de oude in. Vink direct e-mailen aan om een persoonlijke uitnodiging naar het gebonden
   e-mailadres te sturen, of deel de code/link zelf.

### Registratie en beoordeling
- De genodigde opent de link of voert de code in op het registratieadres.
- Naam, e-mailadres en een wachtwoord van minstens 12 tekens zijn verplicht.
- Het account wordt zonder rol gemaakt met status Wacht op e-mailbevestiging.
- De genodigde krijgt een bevestigingslink, geldig voor 24 uur. Die opent een
  scherm met een bevestigingsknop; openen alleen verandert de status niet.
- Na bevestiging wordt de status Wacht op goedkeuring. Beheerders ontvangen
  een melding per e-mail en zien een melding in het WordPress-beheer.
- In Gebruikers → Uitnodigingen en aanvragen kiest een beheerder de rol en
  klikt Goedkeuren of Afwijzen. Het account krijgt alleen bij goedkeuring een rol.
- E-mail-2FA blijft gelden voor de rollen die je bij Dares E-mail 2FA hebt gekozen.
  Controleer dus dat de nieuwe gebruikersrol daar is aangevinkt.
- Beheerdersrollen of rollen met gebruikers-/pluginbeheerrechten zijn niet
  beschikbaar via uitnodigingen. Ken zulke rechten zo nodig afzonderlijk toe
  aan een al goedgekeurd account via WordPress Gebruikers.
- Aanvragers krijgen bericht bij goedkeuring of afwijzing. Afgewezen accounts
  blijven geblokkeerd. Verwijder een afgewezen account eerst als die persoon
  opnieuw mag aanvragen. De nieuwe aanvraag heeft weer een uitnodiging nodig.
- Bij niet aangekomen/verlopen bevestiging kan een beheerder de bevestigingsmail
  opnieuw versturen. Dit vervangt de oude link; maximaal 3 keer per uur.
- Een mislukte e-mailverzending laat het account veilig geblokkeerd staan. De
  beheerder kan de bevestigingsmail opnieuw versturen na herstel van SMTP.

### Aan/uit en pagina’s
- Uitschakelen stopt nieuwe uitnodigingsregistraties. Goedgekeurde accounts
  blijven werken en bestaande openstaande aanvragen blijven geblokkeerd.
- Bestaande aanvragen kunnen nog worden bevestigd en beoordeeld als de functie
  uit staat. Uitschakelen keurt niemand automatisch goed.
- Intrekken of verlopen van een uitnodiging stopt nieuwe aanvragen via die
  uitnodiging. Een al aangemaakte aanvraag blijft afzonderlijk te beoordelen.
- De registratiepagina staat op het adres in het beheerscherm. Een eigen
  pagina kan de shortcode `[rex_register]` gebruiken. De login toont automatisch
  een aanmeldlink zolang uitnodigingsregistratie is ingeschakeld.
- Open standaard WordPress-registratie wordt gesloten zolang uitnodigingen
  zijn ingeschakeld. Registratie via WooCommerce of andere plugins valt buiten
  deze module; schakel zulke routes zelf uit als iedereen een uitnodiging moet
  gebruiken. Bestaande accounts worden niet alsnog in een wachtrij geplaatst.
- Sluit de registratiepagina en wp-login.php uit van caches. HTTPS is verplicht.
- De overzichten bieden zoeken, filters en paginering met 25 regels per pagina.
  Bewaar de gedeelde uitnodigingsgegevens zelf.

### Techniek / gegevens
Uitnodigingen gebruiken een willekeurig geheim van 128 bits; bevestigingslinks
256 bits. Geheimen staan niet in de uitnodigingstabel of gebruikersmeta in
platte tekst. Gebruikstellers zijn atomair zodat een uitnodiging niet boven
het ingestelde maximum kan worden verbruikt. Een voltooide registratie gebruikt
een uitnodigingsplaats ook als de latere bevestigingsmail mislukt.
Wachtwoorden worden door WordPress gehasht. Geen wachtwoorden worden gemaild.
Een ongekeurd account heeft geen rol en wordt ook bij authcookies, bestaande
sessies en app-wachtwoorden geweigerd, zolang de plugin actief is.

De extra tabel `<prefix>rex2fa_invitations` bevat uitnodigingslimieten en
HMAC-geheimen. Gebruikersmeta met prefix `_rex2fa_` bevat de aanvraagstatus,
verificatiegegevens en datum/beheerder van beoordeling. Gebruikers worden
bewaard; de plugin verwijdert bij verwijderen alleen de plugininstellingen
en tabellen. Een actieve plugin is nodig voor de aanvullende loginblokkade.

## Nieuw in 1.1.1: 2FA-status bij gebruikers
Het eigen profiel en Gebruikers → Gebruiker bewerken tonen het blok Dares E-mail
2FA: de actuele rolgebaseerde 2FA-status, verificatiemethode, het opgeslagen
e-mailadres en de account-/goedkeuringsstatus. Beheerders krijgen een knop
naar de 2FA-instellingen en bij geblokkeerde aanvragen een knop naar de
aanvragen. Normale gebruikers kunnen de instelling niet wijzigen.
Ook het gebruikersoverzicht krijgt een aparte kolom Dares E-mail 2FA.

Actief betekent dat de huidige plugininstelling voor de huidige gebruikersrol
een e-mailcode verplicht stelt. Dit is geen bevestiging van SMTP-aflevering.
De Wordfence-status wordt niet overschreven; beide plugins tonen hun eigen
status. Nieuwe profiel- of rolwijzigingen zijn zichtbaar na opslaan/vernieuwen.

De zichtbare pluginnaam is vanaf 1.1.1 Dares E-mail 2FA. De pluginmap,
instellingssleutels en bestaande shortcodes blijven behouden voor een veilige
update over de eerdere Rex E-mail 2FA-installatie.

## Nieuw in 1.1.2: ingetrokken uitnodigingen verwijderen
Bij een ingetrokken uitnodiging staat nu Verwijderen. Alleen beheerders
kunnen deze actie uitvoeren, met een beveiligd POST-verzoek. Alleen records
die daadwerkelijk zijn ingetrokken kunnen worden verwijderd. Accounts en
bestaande aanvragen blijven behouden en moeten nog afzonderlijk worden
beoordeeld. Actieve uitnodigingen moeten eerst worden ingetrokken.

## Nieuw in 1.2.0: uitgebreid beheer en GitHub-updates
- Gebruikers → Uitnodigingen en aanvragen: zoeken, statusfilters, paginering en bulkacties. Goedkeuren vereist nog steeds e-mailbevestiging. Verwijderen geldt alleen voor ingetrokken uitnodigingen.
- Persoonlijke uitnodigingen kunnen direct worden gemaild. De geheime link wordt alleen bij aanmaken beschikbaar; maak een nieuwe uitnodiging als die opnieuw nodig is.
- Instellingen → Dares 2FA beheer: gebeurtenissenlog, sessiebeheer, opruiming, huisstijl en mailteksten.
- Beheerders kunnen in een gebruikersprofiel de rolinstelling volgen, 2FA verplichten of vrijstellen. De algemene 2FA-schakelaar blijft leidend.
- Sessies beëindigen trekt alle WordPress-sessies en openstaande codes van de gekozen gebruiker in. Bij je eigen account log je jezelf uit.
- Het gebeurtenissenlog bewaart standaard 90 dagen en bevat geen codes, wachtwoorden, geheime links of IP-adressen. Retentie is instelbaar van 1 tot 365 dagen.
- Automatische opruiming staat uit. Bij inschakelen worden alleen oude, nog niet per e-mail bevestigde aanvragen verwijderd. Accounts met rollen, beheerdersrechten of eigen berichten/uploads blijven behouden. WP-Cron verwerkt maximaal 100 kandidaten per ronde; activiteit op de site bepaalt wanneer cron draait.
- Logo, kleuren, afzender en uitnodigings-/bevestigings-/beoordelingsmails zijn instelbaar. Verplichte links blijven in de relevante sjablonen staan. De code-mail staat bij de oorspronkelijke 2FA-instellingen. SMTP bepaalt de uiteindelijke aflevering.
- Broncode en releases: https://github.com/spikerm/wordpress-2fa. WordPress controleert publieke releases en biedt nieuwere versies aan als plugin-update. Alleen de meegeleverde release-ZIP met de vaste pluginmap is geschikt. GitHub hoeft geen toegang tot je WordPress-site te krijgen.

Voor beheerders van de repository: verhoog `Version` in het hoofdpluginbestand, werk RELEASE-NOTES.md bij en commit naar main. GitHub Actions controleert PHP-syntax, maakt de ZIP en publiceert eenmaal per versienummer een release. Bestaande releases worden niet overschreven.

## 1.2.1: leesbare tekst
Tekst, labels, velden en knoppen krijgen expliciete kleuren om conflicten met het thema te beperken. Te weinig contrast in de huisstijl wordt automatisch gecorrigeerd bij weergave; opgeslagen kleuren blijven behouden.

## 1.2.2: veldnamen registratie
Registratielabels krijgen rechtstreeks contrastveilige kleuren en leesbare lettergrootte, inclusief WebKit-tekstkleur, zodat themaregels de veldnamen niet donker maken.
