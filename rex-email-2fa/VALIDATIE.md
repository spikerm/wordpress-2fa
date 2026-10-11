# Validatie versie 1.0.0

Gecontroleerd op 11 oktober 2026 in een tijdelijke WordPress-installatie:
WordPress 7.1.3, PHP 8.3.6, MariaDB 10.11.14.

- PHP-syntaxcontrole geslaagd voor hoofdbestand en uninstall.php.
- Activering en aanmaken van de database-tabellen geslaagd.
- 28 integratiechecks geslaagd, waaronder browserbinding, CSRF, blokkeren van
  authcookies zonder verificatie, HMAC-opslag, HTTPS, e-mailfouten, redirect-
  validatie, verlopen codes, veranderde accountgegevens, resend-cooldown,
  behoud van pogingenteller en vervaltijd bij resend, limieten, wp_signon,
  shortcodeweergave en eenmalig verbruik na een juiste code.
- Afzonderlijke standaard-wp-login.php-test geslaagd: wachtwoordauthenticatie
  start de uitdaging en leidt naar de codepagina, zonder authcookie af te geven.

Mail is in de tests onderschept via pre_wp_mail; daadwerkelijke SMTP-aflevering
is niet getest. Jullie Wordfence-versie/configuratie, thema, pagina-cache,
WooCommerce, SSO en andere loginplugins zijn niet aanwezig in de testomgeving.
Test daarom eerst met een aparte gebruiker op je eigen site of staging-site.
Er is geen externe security-audit uitgevoerd.

De minimale versies in de pluginheader zijn gebaseerd op gebruikte WordPress-
API's en PHP-syntax, niet op een volledige testmatrix van alle oudere versies.

# Validatie versie 1.0.1
PHP-syntaxcontrole geslaagd. 17 menuchecks geslaagd in WordPress 7.1.3 en
PHP 8.3.6: gasten versus ingelogde bezoekers, uitlogactie met nonce en homepage-
redirect, intacte bronobjecten, andere menu-items, externe links en wachtwoord-
resetlinks, herkenning van eigen URL’s en de CSS-klasse rex-login, werkelijk
gerenderde Navigatie-linkblokken en geneste Navigatieblokken, en ongemoeid
laten van het menu in de beheeromgeving. De checks van 1.0.0 hierboven zijn
in die versie uitgevoerd; de authenticatielogica is in 1.0.1 niet gewijzigd.

# Validatie versie 1.1.0
Gecontroleerd in WordPress 7.1.3, PHP 8.3.6 en MariaDB 10.11.14.

- PHP-syntaxcontrole geslaagd voor hoofdplugin, invitations.php en uninstall.php.
- 52 checks geslaagd voor uitnodigingen/aanvragen: standaard uit, HTTPS,
  onbekende/verlopen/ingetrokken codes, e-mailbinding, eenmalig verbruik,
  deelbare gebruikslimiet, rol-loze accounts, bevestiging en replay, verplichte
  beheerdergoedkeuring, ontbreken van toegang via cookies/sessies/API,
  roltoewijzing, afwijzing, mailfouten/herversturen, uit-schakelaar, bewaren van
  andere beveiligingsfouten, admin-scherm en werkelijk aanmaken van links/codes.
- 28 bestaande 2FA-integratiechecks opnieuw geslaagd.
- 17 bestaande menuchecks opnieuw geslaagd.
- Standaard wp-login.php-test opnieuw geslaagd.

E-mailverzending is onderschept in de tests; daadwerkelijke aflevering op jullie
SMTP-server en interactie met jullie Wordfence-configuratie moet op de eigen
site worden gecontroleerd. Er is geen externe security-audit uitgevoerd.

# Validatie versie 1.1.1
PHP-syntaxcontrole geslaagd. 13 profiel-/kolomchecks geslaagd in WordPress
7.1.3 en PHP 8.3.6: uitgeschakelde en actieve rolpolicy, niet-geselecteerde
rollen, e-mailadres, beheerknoppen, behouden van andere plugin-kolommen,
accountblokkering, eigen profiel en toegangscontrole tot andermans profiel.
Deze update voegt alleen statusweergave toe; authenticatie en registratie
zijn niet gewijzigd.

# Validatie versie 1.1.2
De nieuwe verwijderactie gebruikt de bestaande beheerder- en noncecontrole
en beperkt de databaseverwijdering tot ingetrokken uitnodigingen. De wijziging
is gecontroleerd op correcte aansluiting van knop, POST-actie en handler.

## Versie 1.2.0
PHP-syntaxcontrole van alle pluginbestanden geslaagd. Bestaande controles: 28 code-/authenticatiecontroles, native login, 17 menucontroles, 13 profielcontroles en 52 uitnodigingscontroles geslaagd. Aanvullend 33 beheercontroles en 53 controles op formulieren, rechten, filters, sessies, logs en opruiming geslaagd. GitHub-updater: geldige release, updateaanbod, geen downgrade, geen prerelease en geen vreemde downloadhost gecontroleerd.

Geen volledige automatische WordPress-installatie van een GitHub-release getest. Werkelijke SMTP-aflevering en jullie eigen Wordfence-/cacheconfiguratie moeten op de website worden gecontroleerd.
