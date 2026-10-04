"""
Signerar ett släpp. Körs på DIN maskin, aldrig i CI.

Hela poängen med signeringen är att ett kapat GitHub-konto inte ska räcka för
att nå butikerna. Ligger den privata nyckeln i Actions secrets är CI-intrång
samma sak som flottan komprometterad, och då var signeringen teater. Nyckeln
ska ligga på en maskin du äger, och det här skriptet körs där.

ENGÅNGSUPPSÄTTNING

    python signera_slapp.py nyckel --ut ~/vapenboken-signeringsnyckel.pem

Skriptet skriver den privata nyckeln till filen (rättighet 600) och den
publika som hex i terminalen. Klistra in hex-värdet i uppdatering.py:

    PUBLIK_NYCKEL_HEX = "..."

Committa det. Den PRIVATA filen committas aldrig, läggs aldrig i repot och
kopieras aldrig till en byggmaskin. Tappar du den kan inga nya uppdateringar
signeras, och butikerna måste få en ny exe för hand en sista gång — så ta en
kopia på ett USB-minne i ett kassaskåp.

VID VARJE SLÄPP

    python signera_slapp.py signera dist/ \\
        --version 1.5.2 --nyckel ~/vapenboken-signeringsnyckel.pem

Skriptet hashar filerna i mappen, skriver manifest.json och
manifest.json.sig, och säger vad du ska ladda upp till releasen. Ladda upp
BÅDA — utan signaturen kan ingen butik verifiera manifestet, och
uppdateringen går inte igenom (vilket är rätt, men förvirrande).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

FILER_ATT_SIGNERA = (
    "Vapenboken.exe",
    "Vapenboken-mac-apple-silicon.zip",
    "Vapenboken-mac-intel.zip",
)
MANIFEST_NAMN = "manifest.json"
SIGNATUR_NAMN = "manifest.json.sig"


def _skapa_nyckel(utfil: str) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    utfil = os.path.abspath(os.path.expanduser(utfil))
    if os.path.exists(utfil):
        print(f"FEL: {utfil} finns redan. Skriv inte över en nyckel som "
              "butikerna litar på — flytta den gamla först om du verkligen "
              "vill byta.", file=sys.stderr)
        return 1

    nyckel = Ed25519PrivateKey.generate()
    pem = nyckel.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(utfil) or ".", exist_ok=True)
    # Skriv med rättigheterna satta från början. Hade filen skapats öppen och
    # chmod:ats efteråt fanns ett glapp där vem som helst kunde läsa nyckeln.
    fd = os.open(utfil, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)

    publik = nyckel.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    print(f"Privat nyckel skriven till {utfil} (rättighet 600).")
    print("Ta en kopia på ett USB-minne och lägg undan den.\n")
    print("Klistra in den här raden i uppdatering.py:\n")
    print(f'PUBLIK_NYCKEL_HEX = "{publik}"\n')
    return 0


def _las_nyckel(sokvag: str):
    from cryptography.hazmat.primitives import serialization

    sokvag = os.path.abspath(os.path.expanduser(sokvag))
    with open(sokvag, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def bygg_manifest(mapp: str, version: str) -> dict:
    """Hashar de byggda filerna. Saknade filer hoppas över med ett besked."""
    filer = {}
    for namn in FILER_ATT_SIGNERA:
        sokvag = os.path.join(mapp, namn)
        if not os.path.isfile(sokvag):
            print(f"  hoppar över {namn} (finns inte i {mapp})")
            continue
        with open(sokvag, "rb") as f:
            rått = f.read()
        filer[namn] = {
            "storlek": len(rått),
            "sha256": hashlib.sha256(rått).hexdigest(),
        }
        print(f"  {namn}: {len(rått) / 1048576:.1f} MB  "
              f"{filer[namn]['sha256'][:16]}…")
    if not filer:
        raise SystemExit(f"FEL: hittade inga byggda filer i {mapp}")
    return {"version": version, "filer": filer}


def _signera(mapp: str, version: str, nyckelfil: str) -> int:
    import uppdatering

    print(f"Hashar byggena i {mapp}:")
    manifest = bygg_manifest(mapp, version)
    uppdatering.krav_manifestform(manifest)

    # Kanonisk form: samma manifest ger samma byte varje gång, annars
    # stämmer inte signaturen mot det butiken hämtar.
    rått = json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    nyckel = _las_nyckel(nyckelfil)
    signatur = nyckel.sign(rått)

    # Pröva med samma kod butiken kör, innan något laddas upp. Går det inte
    # igenom här går det inte igenom hos dem heller.
    from cryptography.hazmat.primitives import serialization
    publik = nyckel.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    uppdatering.verifiera_manifest(rått, signatur, publik_nyckel_hex=publik)

    manifestfil = os.path.join(mapp, MANIFEST_NAMN)
    signaturfil = os.path.join(mapp, SIGNATUR_NAMN)
    with open(manifestfil, "wb") as f:
        f.write(rått)
    with open(signaturfil, "wb") as f:
        f.write(signatur)

    print(f"\nSignerat med nyckeln i {nyckelfil}.")
    if publik != uppdatering.PUBLIK_NYCKEL_HEX:
        print("\nVARNING: den publika nyckeln i uppdatering.py är inte den "
              "här nyckelns.\nButikerna kommer att avvisa manifestet. "
              f"Rätt värde:\n\nPUBLIK_NYCKEL_HEX = \"{publik}\"\n")
    print("Ladda upp BÅDA filerna till releasen:")
    print(f"  {manifestfil}")
    print(f"  {signaturfil}")
    print("\n  gh release upload v<tagg> "
          f"{manifestfil} {signaturfil}")
    return 0


# ── Allt i ett: hämta, signera, ladda upp ────────────

# Samma publika repo som butikerna hämtar ifrån. Kallkoden ar privat och
# ger 404 for alla utan inloggning.
from uppdatering import SLAPP_REPO as GITHUB_REPO
API = f"https://api.github.com/repos/{GITHUB_REPO}"
UPPLADDNING = f"https://uploads.github.com/repos/{GITHUB_REPO}"


def version_ur_tagg(tagg: str) -> str:
    """
    "v1.6.1-bygge.87" -> "1.6.1".

    Versionen hamnar i manifestet och är det butiken jämför mot. Blir den
    fel får antingen ingen notis, eller alla en notis om en version som inte
    finns — därför en egen funktion med egna tester, i stället för en rad
    kedjade strängoperationer mitt i släppet.

    lstrip("v") hade varit fel: det skalar av ALLA inledande v:n.
    """
    namn = tagg.strip()
    if namn[:1].lower() == "v":
        namn = namn[1:]
    version = namn.split("-")[0].strip()
    if not re.fullmatch(r"\d+(?:\.\d+)*", version):
        raise SystemExit(
            f"FEL: kan inte läsa ut ett versionsnummer ur taggen {tagg!r}.")
    return version


def _api(url: str, token: str = "", data: bytes = None,
         innehallstyp: str = "") -> dict:
    """Ett anrop mot GitHubs API. Token behövs bara för uppladdning."""
    import urllib.error
    import urllib.request

    huvuden = {"Accept": "application/vnd.github+json",
               "User-Agent": "Vapenboken-slapp"}
    if token:
        huvuden["Authorization"] = f"Bearer {token}"
    if innehallstyp:
        huvuden["Content-Type"] = innehallstyp
    begaran = urllib.request.Request(url, data=data, headers=huvuden)
    try:
        with urllib.request.urlopen(begaran, timeout=120) as svar:
            rått = svar.read()
    except urllib.error.HTTPError as e:
        kropp = e.read().decode("utf-8", "replace")[:300]
        raise SystemExit(f"FEL: GitHub svarade {e.code} på {url}\n{kropp}")
    except urllib.error.URLError as e:
        raise SystemExit(f"FEL: kunde inte nå GitHub: {e}")
    return json.loads(rått) if rått else {}


def _radera_tillgang(tillgangs_id: int, token: str) -> None:
    """
    Tar bort en släppfil. GitHub tillåter inte två med samma namn, så ett
    tidigare manifest måste bort innan det nya kan laddas upp.
    """
    import urllib.error
    import urllib.request

    begaran = urllib.request.Request(
        f"{API}/releases/assets/{tillgangs_id}", method="DELETE",
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": f"Bearer {token}",
                 "User-Agent": "Vapenboken-slapp"})
    try:
        urllib.request.urlopen(begaran, timeout=60).read()
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"FEL: kunde inte ta bort den gamla filen ({e.code}). "
            "Ta bort manifest.json och manifest.json.sig i releasen för "
            "hand och kör igen.")


def _hamta_tillgang(url: str, mal: str) -> int:
    """Laddar ner en släppfil. Publikt repo, ingen token behövs."""
    import urllib.request

    begaran = urllib.request.Request(url, headers={
        "Accept": "application/octet-stream",
        "User-Agent": "Vapenboken-slapp"})
    with urllib.request.urlopen(begaran, timeout=300) as svar, \
            open(mal, "wb") as f:
        while True:
            bit = svar.read(1024 * 256)
            if not bit:
                break
            f.write(bit)
    return os.path.getsize(mal)


def _token() -> str:
    """
    Token för uppladdningen, om det finns någon.

    Letas i GITHUB_TOKEN eller GH_TOKEN. Finns ingen laddar skriptet inte
    upp, utan säger vad du ska dra in i webbläsaren i stället — det är fullt
    dugligt och slipper en token som ligger och skräpar.
    """
    for namn in ("GITHUB_TOKEN", "GH_TOKEN"):
        varde = os.environ.get(namn, "").strip()
        if varde:
            return varde
    return ""


def _slapp(tagg: str, nyckelfil: str, mapp: str = "") -> int:
    """
    Hela släppet i ett kommando: hämta, signera, ladda upp.

    Varje släpp behöver ett eget manifest — signaturen gäller exakt de
    filerna, annars kunde en utbytt exe glida igenom under samma
    versionsnummer. Det går inte runt. Men det ska vara ETT kommando, inte
    sex handgrepp.
    """
    import tempfile

    url = f"{API}/releases/latest" if not tagg else f"{API}/releases/tags/{tagg}"
    print(f"Läser {'senaste släppet' if not tagg else tagg} ...")
    slapp = _api(url)
    tagg = slapp["tag_name"]
    version = version_ur_tagg(tagg)
    print(f"  {tagg}  (version {version})")

    tillgangar = {a["name"]: a for a in slapp.get("assets", [])}
    saknas = [n for n in FILER_ATT_SIGNERA if n not in tillgangar]
    if len(saknas) == len(FILER_ATT_SIGNERA):
        raise SystemExit(f"FEL: {tagg} har inga byggda filer att signera.")
    for n in saknas:
        print(f"  saknas i släppet: {n}")

    arbetsmapp = mapp or tempfile.mkdtemp(prefix="vb_slapp_")
    os.makedirs(arbetsmapp, exist_ok=True)
    print(f"\nHämtar till {arbetsmapp}:")
    for namn in FILER_ATT_SIGNERA:
        if namn not in tillgangar:
            continue
        mal = os.path.join(arbetsmapp, namn)
        storlek = _hamta_tillgang(tillgangar[namn]["url"], mal)
        # Jämför mot GitHubs egen summa direkt — en avhuggen nedladdning
        # ska inte bli ett signerat manifest.
        pa_github = (tillgangar[namn].get("digest") or "").replace(
            "sha256:", "")
        with open(mal, "rb") as f:
            vår = hashlib.sha256(f.read()).hexdigest()
        if pa_github and pa_github != vår:
            raise SystemExit(
                f"FEL: {namn} kom inte hel ner. GitHub säger "
                f"{pa_github[:16]}…, filen är {vår[:16]}…")
        print(f"  {namn}: {storlek / 1048576:.1f} MB  OK mot GitHubs summa")

    print()
    if _signera(arbetsmapp, version, nyckelfil) != 0:
        return 1

    manifestfil = os.path.join(arbetsmapp, MANIFEST_NAMN)
    signaturfil = os.path.join(arbetsmapp, SIGNATUR_NAMN)
    token = _token()
    if not token:
        print("\nIngen GITHUB_TOKEN satt, så uppladdningen får göras för "
              "hand.\nGå till releasen, klicka Edit release och dra in:")
        print(f"  {manifestfil}")
        print(f"  {signaturfil}")
        return 0

    print("\nLaddar upp till", tagg)
    for fil in (manifestfil, signaturfil):
        namn = os.path.basename(fil)
        # Ett tidigare manifest måste bort först — GitHub tillåter inte två
        # filer med samma namn i ett släpp.
        gammal = tillgangar.get(namn)
        if gammal:
            _radera_tillgang(gammal["id"], token)
            print(f"  (tog bort det gamla {namn})")
        with open(fil, "rb") as f:
            kropp = f.read()
        _api(f"{UPPLADDNING}/releases/{slapp['id']}/assets?name={namn}",
             token=token, data=kropp,
             innehallstyp="application/octet-stream")
        print(f"  {namn} uppladdad ({len(kropp)} byte)")

    print(f"\nKlart. Butiker som kör en äldre version ser nu {version}.")
    return 0


def main(argv=None) -> int:
    tolk = argparse.ArgumentParser(
        description="Signerar ett Vapenboken-släpp. Körs på din egen maskin.")
    under = tolk.add_subparsers(dest="kommando", required=True)

    n = under.add_parser("nyckel", help="skapa signeringsnyckeln (en gång)")
    n.add_argument("--ut", required=True, help="var den privata nyckeln ska bo")

    r = under.add_parser(
        "slapp", help="hämta, signera och ladda upp i ett steg")
    r.add_argument("--tagg", default="",
                   help="vilket släpp, t.ex. v1.6.1-bygge.87 "
                        "(standard: det senaste)")
    r.add_argument("--nyckel", required=True, help="den privata nyckelfilen")
    r.add_argument("--mapp", default="",
                   help="var filerna hämtas (standard: en temporär mapp)")

    s = under.add_parser("signera", help="signera ett redan hämtat släpp")
    s.add_argument("mapp", help="mappen med de byggda filerna, t.ex. dist/")
    s.add_argument("--version", required=True, help="versionen släppet gäller")
    s.add_argument("--nyckel", required=True, help="den privata nyckelfilen")

    args = tolk.parse_args(argv)
    if args.kommando == "nyckel":
        return _skapa_nyckel(args.ut)
    if args.kommando == "slapp":
        return _slapp(args.tagg, args.nyckel, args.mapp)
    return _signera(args.mapp, args.version, args.nyckel)


if __name__ == "__main__":
    raise SystemExit(main())
