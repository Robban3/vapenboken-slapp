"""
Signerade uppdateringar: butiken hämtar ingenting som inte du har signerat.

Vid hundratals butiker går manuell utrullning inte — en rättad bugg som
ligger outskickad hos 300 butiker skyddar ingen. Men en uppdaterare som
hämtar en exe från en adress och kör den betyder att den som kontrollerar
adressen kontrollerar varje butiks vapenregister. Ett kapat GitHub-konto, en
läckt token, en kapad DNS: vilket som helst av det blir 300 komprometterade
register, och det är sämre än långsam utrullning.

Därför: programmet bär en PUBLIK nyckel. Varje släpp signeras med den privata
på utgivarens egen maskin — aldrig i CI, aldrig i repot. Uppdateraren hämtar
ett manifest, verifierar signaturen mot den inbakade nyckeln, och hämtar först
därefter filen. Sedan kontrolleras filens SHA-256 mot manifestet. Att komma åt
utgivningskanalen räcker alltså inte; man behöver den privata nyckeln också.

Lager två, när certifikatet finns: Windows egen signatur på den nedladdade
filen prövas med WinVerifyTrust. Saknas certifikatet rapporteras det som
okänt och manifestsignaturen får stå ensam — så koden går att skriva nu och
skärpa senare utan att göras om.

NÄTET. Resten av programmet rör inte internet, och det är en egenskap butiken
ska kunna stå för. Den här modulen är enda undantaget. Den
* kontaktar bara den adress som står i UPPDATERINGS_URL,
* skickar ingenting om butiken — ingen identitet, inga poster, ingen
  statistik; det är en GET av en manifestfil,
* har alltid en tidsgräns och ett tak för hur mycket som läses,
* får aldrig fälla eller fördröja uppstarten, och
* går att stänga av helt i inställningarna.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

# Var butiken hämtar sina uppdateringar.
#
# Ett EGET repo, skilt från källkoden. Källkoden är privat, och GitHub
# svarar 404 på privata repon för alla som inte är inloggade — både på
# api.github.com, raw.githubusercontent.com och nedladdningslänkarna. En
# butik hade alltså aldrig kunnat hämta någonting.
#
# Att lägga en token i exe:n löser det inte: vem som helst kan plocka ut
# den ur filen och därmed läsa hela källkodsrepot. Därför ligger bara de
# BYGGDA filerna och manifestet publikt — de ska ändå ut till hundratals
# butiker och är inte hemliga — medan källkoden stannar privat.
#
# Bytet till en egen domän senare ändrar bara de här raderna.
SLAPP_REPO = "Robban3/vapenboken-slapp"
_SLAPP_BAS = f"https://github.com/{SLAPP_REPO}/releases"

UPPDATERINGS_URL = f"{_SLAPP_BAS}/latest/download/manifest.json"
SIGNATUR_URL = f"{_SLAPP_BAS}/latest/download/manifest.json.sig"

# Utgivarens publika Ed25519-nyckel, hex. Den PRIVATA halvan finns bara hos
# utgivaren, på en maskin som inte är en byggserver — ligger den i CI är
# CI-intrång samma sak som flottan komprometterad.
#
# Den här halvan är ofarlig att sprida. Den kan bara kontrollera signaturer,
# inte skapa dem, och den måste följa med i exe:n för att butiken ska kunna
# avgöra om en uppdatering kommer från utgivaren.
#
# Tom sträng = ingen nyckel inbakad, och då vägrar verifieringen allt
# (se verifiera_manifest). Byts nyckeln måste butikerna få en ny exe en
# sista gång för hand — därför ska den privata filen kopieras och läggas
# undan, inte bara ligga på en dator.
PUBLIK_NYCKEL_HEX = (
    "55196ac4f03f681e6a32ae2710a35fcf6e743b37ac4bdb5679dda36d7d19d392"
)

# Tak och tidsgränser. Ett manifest är några hundra byte; en exe är ~30 MB.
MAX_MANIFEST_BYTE = 64 * 1024
MAX_SIGNATUR_BYTE = 1024
MAX_FIL_BYTE = 200 * 1024 * 1024
TIDSGRANS_SEK = 15


class UppdateringsFel(Exception):
    """Något gick fel på vägen. Uppstarten ska aldrig fällas av detta."""


# ── Versionsjämförelse ───────────────────────────────


def _versionsdelar(version: str) -> tuple[int, ...]:
    """
    "1.5.1" -> (1, 5, 1). Tolererar suffix: "1.5.1-bygge.76" -> (1, 5, 1).

    Jämförelsen får inte kasta på något som står i ett manifest vi inte
    skrivit — då hade en felskriven version blivit ett fel i butiken i
    stället för ett ignorerat manifest.
    """
    if not isinstance(version, str):
        return ()
    siffror = re.match(r"\s*(\d+(?:\.\d+)*)", version)
    if not siffror:
        return ()
    return tuple(int(d) for d in siffror.group(1).split("."))


def ar_nyare(kandidat: str, nuvarande: str) -> bool:
    """Om kandidat är en högre version än nuvarande."""
    a, b = _versionsdelar(kandidat), _versionsdelar(nuvarande)
    if not a or not b:
        return False
    langd = max(len(a), len(b))
    return a + (0,) * (langd - len(a)) > b + (0,) * (langd - len(b))


# ── Manifestet ───────────────────────────────────────


def verifiera_manifest(ratt: bytes, signatur: bytes,
                       publik_nyckel_hex: str | None = None) -> dict:
    """
    Manifestet som dict, eller UppdateringsFel.

    Signaturen prövas FÖRE innehållet tolkas. Ett manifest vi inte kan
    verifiera ska inte ens parsas — json.loads på obetrodd indata är ingen
    stor risk, men ordningen är principen: inget obetrott innehåll får röra
    något som fattar beslut.
    """
    nyckel_hex = (PUBLIK_NYCKEL_HEX if publik_nyckel_hex is None
                  else publik_nyckel_hex)
    if not nyckel_hex:
        raise UppdateringsFel(
            "Ingen publik nyckel är inbakad i programmet, så uppdateringar "
            "går inte att verifiera.")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        nyckel = Ed25519PublicKey.from_public_bytes(bytes.fromhex(nyckel_hex))
    except ValueError as e:
        raise UppdateringsFel(f"Den inbakade nyckeln är ogiltig: {e}") from e
    try:
        nyckel.verify(signatur, ratt)
    except InvalidSignature as e:
        raise UppdateringsFel(
            "Manifestets signatur stämmer inte. Filen kommer inte från "
            "utgivaren, eller har ändrats på vägen.") from e

    try:
        manifest = json.loads(ratt.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise UppdateringsFel("Manifestet går inte att läsa.") from e
    return krav_manifestform(manifest)


def krav_manifestform(manifest) -> dict:
    """Att manifestet har den form resten av koden räknar med."""
    if not isinstance(manifest, dict):
        raise UppdateringsFel("Manifestet är inte ett objekt.")
    if not isinstance(manifest.get("version"), str) \
            or not _versionsdelar(manifest["version"]):
        raise UppdateringsFel("Manifestet saknar ett läsbart versionsnummer.")
    filer = manifest.get("filer")
    if not isinstance(filer, dict) or not filer:
        raise UppdateringsFel("Manifestet listar inga filer.")
    for namn, post in filer.items():
        # Kontrollen görs tecken för tecken, inte med os.path.basename.
        # basename följer plattformen: på Linux är omvänt snedstreck ett
        # vanligt tecken, så "..\\Vapenboken.exe" gled igenom där men hade
        # stoppats på Windows. En säkerhetskontroll får inte bero på vilken
        # dator den råkar köra på.
        if not isinstance(namn, str) or namn in ("", ".", "..") \
                or any(t in namn for t in ("/", "\\", ":", "\x00")) \
                or namn != namn.strip():
            raise UppdateringsFel(f"Ogiltigt filnamn i manifestet: {namn!r}")
        if not isinstance(post, dict):
            raise UppdateringsFel(f"Ogiltig post för {namn} i manifestet.")
        summa = post.get("sha256")
        if not isinstance(summa, str) or not re.fullmatch(r"[0-9a-fA-F]{64}",
                                                          summa):
            raise UppdateringsFel(f"{namn} saknar en giltig SHA-256 i "
                                  "manifestet.")
        storlek = post.get("storlek")
        if not isinstance(storlek, int) or isinstance(storlek, bool) \
                or not 0 < storlek <= MAX_FIL_BYTE:
            raise UppdateringsFel(f"{namn} har en orimlig storlek i "
                                  "manifestet.")
    return manifest


def filnamn_for_denna_plattform() -> str:
    """
    Vilken fil i manifestet som hör till den här datorn.

    Mac-byggena är inte utbytbara: en app byggd för Apple Silicon startar
    inte alls på en Intel-Mac. Arkitekturen läses av, den gissas inte.
    """
    if sys.platform == "win32":
        return "Vapenboken.exe"
    if sys.platform == "darwin":
        import platform
        if platform.machine() == "arm64":
            return "Vapenboken-mac-apple-silicon.zip"
        return "Vapenboken-mac-intel.zip"
    raise UppdateringsFel(
        "Automatisk uppdatering finns bara för Windows och Mac.")


# ── Hämtning ─────────────────────────────────────────


def _hamta(url: str, max_byte: int) -> bytes:
    """
    GET med tidsgräns och tak. Inget om butiken skickas med.

    Taket är inte kosmetik: utan det kunde en kapad eller trasig server
    mata in obegränsat mycket i minnet hos butikens dator.
    """
    import urllib.error
    import urllib.request

    begaran = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Vapenboken-uppdatering",
        "Accept": "application/octet-stream",
    })
    try:
        with urllib.request.urlopen(begaran, timeout=TIDSGRANS_SEK) as svar:
            data = svar.read(max_byte + 1)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UppdateringsFel(f"Kunde inte nå {url}: {e}") from e
    if len(data) > max_byte:
        raise UppdateringsFel(
            f"Svaret från {url} är större än {max_byte} byte och avbröts.")
    return data


def hamta_manifest(*, manifest_url: str = "", signatur_url: str = "",
                   hamtare=None) -> dict:
    """
    Det verifierade manifestet. hamtare finns för testerna.

    Kastar UppdateringsFel vid allt — nät, signatur, form. Anroparen ska
    logga och gå vidare, aldrig stanna.
    """
    hamta = hamtare or _hamta
    rått = hamta(manifest_url or UPPDATERINGS_URL, MAX_MANIFEST_BYTE)
    sig = hamta(signatur_url or SIGNATUR_URL, MAX_SIGNATUR_BYTE)
    return verifiera_manifest(rått, sig)


def hamta_fil(url: str, forvantad_sha256: str, storlek: int, mal: str,
              *, hamtare=None) -> str:
    """
    Hämtar en fil och skriver den bara om summan stämmer mot manifestet.

    Filen skrivs till mal + ".del" och byts på plats först när den är hel.
    Annars hade ett avbrutet bygge legat kvar som en halv exe med rätt namn.
    """
    hamta = hamtare or _hamta
    data = hamta(url, min(storlek, MAX_FIL_BYTE))
    if len(data) != storlek:
        raise UppdateringsFel(
            f"Hämtade {len(data)} byte men manifestet säger {storlek}.")
    fick = hashlib.sha256(data).hexdigest()
    if fick.lower() != forvantad_sha256.lower():
        raise UppdateringsFel(
            "Den hämtade filens kontrollsumma stämmer inte med manifestet. "
            "Filen är skadad eller utbytt.")
    del_fil = mal + ".del"
    with open(del_fil, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(del_fil, mal)
    return mal


# ── Lager två: Windows egen signatur ─────────────────

SIGNATUR_OKAND = "okand"
SIGNATUR_GILTIG = "giltig"
SIGNATUR_OGILTIG = "ogiltig"


def windows_signatur(fil: str) -> str:
    """
    Vad WinVerifyTrust säger om filen.

    Finns för dagen certifikatet är på plats. Utan certifikat svarar Windows
    att filen är osignerad, och då är svaret SIGNATUR_OKAND — inte ogiltig.
    Manifestsignaturen får stå ensam tills dess, och den här kontrollen kan
    skärpas till ett krav utan att resten görs om.
    """
    if sys.platform != "win32":
        return SIGNATUR_OKAND
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE),
                        ("pgKnownSubject", ctypes.POINTER(GUID))]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p),
                        ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD),
                        ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                        ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE),
                        ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD),
                        ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE = 2, 0, 1
        info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), fil,
                                  None, None)
        data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None,
                             WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE,
                             ctypes.pointer(info), 0, None, None, 0, 0, None)
        guid = GUID(0xAAC56B, 0xCD44, 0x11D0,
                    (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F,
                                        0xC2, 0x95, 0xEE))
        resultat = ctypes.windll.wintrust.WinVerifyTrust(
            None, ctypes.byref(guid), ctypes.byref(data))
    except Exception:
        return SIGNATUR_OKAND
    if resultat == 0:
        return SIGNATUR_GILTIG
    # 0x800B0100 = ingen signatur alls. Allt annat är en signatur som inte
    # håller, och det är ett nej.
    if resultat in (0x800B0100, -2146762496):
        return SIGNATUR_OKAND
    return SIGNATUR_OGILTIG


# ── Byta ut programfilen ─────────────────────────────

GAMMAL_SUFFIX = ".gammal"
NY_SUFFIX = ".ny"


def ar_paketerad() -> bool:
    """Om programmet körs som exe. Ur källkoden finns inget att byta ut."""
    return bool(getattr(sys, "frozen", False))


def programfil() -> str:
    """Filen som ska bytas ut."""
    return os.path.abspath(sys.executable)


def stada_gammal_programfil() -> bool:
    """
    Tar bort förra versionens fil. Anropas vid uppstart.

    Att vi kör är beviset att utbytet lyckades — den nya filen startade.
    Ligger .gammal kvar betyder det att den nya versionen aldrig kom igång,
    och då är filen butikens väg tillbaka: byt namn på den till
    Vapenboken.exe igen. Därför raderas den FÖRST när vi vet att det gick.
    """
    if not ar_paketerad():
        return False
    gammal = programfil() + GAMMAL_SUFFIX
    if not os.path.isfile(gammal):
        return False
    try:
        os.unlink(gammal)
        return True
    except OSError:
        return False


def byt_ut_programfil(ny_fil: str) -> str:
    """
    Byter ut den körande programfilen mot den nedladdade.

    Returnerar sökvägen till den gamla filen, som butiken kan byta tillbaka
    till om något är fel.

    Windows låser en körande exe för SKRIVNING men tillåter att den byter
    NAMN — handtaget pekar på filobjektet, inte på namnet. Därför:

        1. Vapenboken.exe      -> Vapenboken.exe.gammal
        2. Vapenboken.exe.ny   -> Vapenboken.exe

    Faller steg 2 byts steg 1 tillbaka, så butiken aldrig står utan
    program. Det är den enda delen av den här filen som inte går att prova
    härifrån — den kräver en riktig Windows-maskin.
    """
    if not ar_paketerad():
        raise UppdateringsFel(
            "Programmet körs ur källkoden. Det finns ingen exe att byta ut.")
    nuvarande = programfil()
    if not os.path.isfile(ny_fil):
        raise UppdateringsFel(f"Hittar inte den nedladdade filen {ny_fil}.")
    gammal = nuvarande + GAMMAL_SUFFIX

    # En kvarglömd .gammal från ett tidigare försök är i vägen.
    if os.path.exists(gammal):
        try:
            os.unlink(gammal)
        except OSError as e:
            raise UppdateringsFel(
                f"Kunde inte ta bort {os.path.basename(gammal)}: {e}") from e

    try:
        os.rename(nuvarande, gammal)
    except OSError as e:
        raise UppdateringsFel(
            "Kunde inte byta namn på programfilen. Ligger den i en mapp "
            f"ni får skriva i? ({e})") from e
    try:
        os.rename(ny_fil, nuvarande)
    except OSError as e:
        # Tillbaka till utgångsläget. Butiken ska aldrig stå utan program
        # bara för att en uppdatering gick fel.
        try:
            os.rename(gammal, nuvarande)
        except OSError:
            raise UppdateringsFel(
                "Uppdateringen avbröts och programfilen kunde inte läggas "
                f"tillbaka. Byt namn på {os.path.basename(gammal)} till "
                f"{os.path.basename(nuvarande)} för hand.") from e
        raise UppdateringsFel(
            f"Kunde inte lägga den nya filen på plats ({e}). Den gamla "
            "versionen är tillbaka och fungerar.") from e
    return gammal


# ── Hela kontrollen, som uppstarten använder den ─────


class Uppdatering:
    """Det uppstarten behöver veta om en ny version."""

    def __init__(self, version: str, manifest: dict, filnamn: str):
        self.version = version
        self.manifest = manifest
        self.filnamn = filnamn

    @property
    def storlek(self) -> int:
        return self.manifest["filer"][self.filnamn]["storlek"]

    @property
    def sha256(self) -> str:
        return self.manifest["filer"][self.filnamn]["sha256"]

    def __repr__(self):
        return f"<Uppdatering {self.version} {self.filnamn}>"


def kolla_efter_uppdatering(nuvarande_version: str, *, hamtare=None):
    """
    En Uppdatering om det finns en nyare version, annars None.

    Kastar UppdateringsFel vid nät- eller signaturfel. Anroparen ska logga
    och gå vidare — en uppdateringskontroll som inte går igenom får aldrig
    hindra butiken från att arbeta.
    """
    manifest = hamta_manifest(hamtare=hamtare)
    if not ar_nyare(manifest["version"], nuvarande_version):
        return None
    filnamn = filnamn_for_denna_plattform()
    if filnamn not in manifest["filer"]:
        raise UppdateringsFel(
            f"Den nya versionen {manifest['version']} saknar en fil för den "
            "här datorn.")
    return Uppdatering(manifest["version"], manifest, filnamn)


def las_hem(uppdatering: Uppdatering, mapp: str, *, hamtare=None) -> str:
    """
    Hämtar och verifierar filen. Returnerar sökvägen till den.

    Filnamnet kommer ur manifestet men används inte som det är — bara den
    plattformens kända namn får bli en fil på disken. Ett manifest vi
    verifierat kan ändå vara skrivet av någon som fått tag i nyckeln, och
    då ska inte filnamnet också vara deras val.
    """
    vantat = filnamn_for_denna_plattform()
    if uppdatering.filnamn != vantat:
        raise UppdateringsFel(
            f"Filen i manifestet heter {uppdatering.filnamn}, väntade "
            f"{vantat}.")
    url = f"{_SLAPP_BAS}/download/v{uppdatering.version}/{vantat}"
    mal = os.path.join(mapp, vantat + NY_SUFFIX)
    return hamta_fil(url, uppdatering.sha256, uppdatering.storlek, mal,
                     hamtare=hamtare)
