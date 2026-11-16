"""
Moduł 2 - test: skrypt udający bota, który próbuje zalogować się do aplikacji.

Najpierw uruchom aplikację (python app.py), potem w drugim oknie: python bot_test.py
Testy wolno wykonywać wyłącznie na własnej aplikacji.
"""
import re
import socket
import sys
import urllib.parse
import urllib.request

LOGIN_URL = "http://127.0.0.1:5000/login"
WRONG = "Login lub hasło niepoprawne"
FAKE_TOKEN = "FAKE-TOKEN-123"            # bot nie rozwiąże CAPTCHA, więc podrabia token
PASSWORDS = ["123456", "qwerty", "haslo123", "Polska2024!", "zaq12wsx",
             "Haslo123456789!", "redaktor1", "1qaz2wsx", "admin123", "Qwerty123!"]


def bot_login(login, password, token=None, hidden_field=""):
    """Wysyła formularz logowania jak bot. Zwraca komunikat serwera albo ZALOGOWANO."""
    form = {"login": login, "password": password, "website": hidden_field}
    if token is not None:
        form["cf-turnstile-response"] = token
    with urllib.request.urlopen(LOGIN_URL, urllib.parse.urlencode(form).encode(), timeout=30) as response:
        if not response.geturl().endswith("/login"):
            return "ZALOGOWANO"
        found = re.search(r'class="message error">(.*?)</div>', response.read().decode())
        return found.group(1) if found else "(brak komunikatu)"


def show(title, answer):
    print(f"\n{title}\n   serwer: {answer}")
    return answer


try:
    page = urllib.request.urlopen(LOGIN_URL, timeout=30).read().decode()
except OSError:
    sys.exit("Brak połączenia z aplikacją - najpierw uruchom: python app.py")
print("BOT atakuje", LOGIN_URL)

a1 = show("1. Bot wypełnia wszystkie pola formularza, także ukryte",
          bot_login("audytor1", "Haslo123!", token="", hidden_field="http://spam.example"))
a2 = show("2. Bot wysyła formularz bez tokenu CAPTCHA", bot_login("audytor1", "Haslo123!"))
a3 = show("3. Bot wysyła podrobiony token CAPTCHA", bot_login("audytor1", "Haslo123!", token=FAKE_TOKEN))

print(f"\n4. Brute force: {len(PASSWORDS)} haseł na konto redaktor1")
a4 = []
for number, password in enumerate(PASSWORDS, 1):
    a4.append(bot_login("redaktor1", password, token=FAKE_TOKEN))
    print(f"   próba {number:2}: {a4[-1]}")

bait = re.search(r"konto serwisowe: (\S+) / (\S+)", page)      # dane zostawione w komentarzu HTML
a5 = show(f"5. Bot loguje się danymi z komentarza w kodzie strony ({bait.group(1)} / {bait.group(2)})",
          bot_login(bait.group(1), bait.group(2), token=FAKE_TOKEN))
backup = re.search(r"kopia bazy: (\S+)", page)
if backup:
    print(f"   bot sprawdza też adres kopii bazy z komentarza: {backup.group(1)}")
    try:
        socket.gethostbyname(backup.group(1))                   # zapytanie DNS = alert tokenu DNS
    except OSError:
        pass

# ----- zestawienie -----
total = 2 + len(PASSWORDS)
captcha = sum("CAPTCHA" in a for a in [a2, a3] + a4)
lock = next((n for n, a in enumerate(a4, 1) if "blokady" in a), None)
if lock:
    limit = ("ZADZIAŁAŁ", f"po próbie nr {lock} konto redaktor1 jest zablokowane na 15 min")
elif all("CAPTCHA" in a for a in a4):
    limit = ("nie był potrzebny", "CAPTCHA odrzuciła wszystkie próby, zanim serwer sprawdził hasło")
else:
    limit = ("NIE", f"{len(PASSWORDS)} prób bez blokady - sprawdź limit w ustawieniach")
rows = [
    ("Pułapka na boty (ukryte pole)", "ZADZIAŁAŁA" if a1 == WRONG else "NIE",
     "bot odrzucony, choć nie wysłał tokenu - zatrzymało go ukryte pole, zanim serwer sprawdził CAPTCHA"),
    ("CAPTCHA (Cloudflare Turnstile)", "ZADZIAŁAŁA" if captcha == total else "CZĘŚCIOWO" if captcha else "NIE",
     f"odrzucone żądania bez poprawnego tokenu: {captcha} z {total}"
     + ("" if captcha == total else " - podrobiony token przeszedł (klucze testowe?)")),
    ("Limit błędnych logowań", *limit),
    ("Konto-pułapka (Canarytokens: token HTTP)", "ZADZIAŁAŁO" if a5 == WRONG else "NIE",
     "logowanie odrzucone, serwer wysłał alert - sprawdź e-mail i terminal aplikacji"),
    ("Kopia bazy (Canarytokens: token DNS)", "UŻYTY" if backup else "brak",
     "bot odpytał DNS o adres - sprawdź e-mail" if backup else "pusty BACKUP_DB_HOST w app.py"),
]
print("\n" + "=" * 70 + "\nZESTAWIENIE: które zabezpieczenia zadziałały\n" + "=" * 70)
for name, verdict, detail in rows:
    print(f"{name:<42} {verdict}\n   {detail}")
logged_in = "ZALOGOWANO" in [a1, a2, a3, a5] + a4
print("=" * 70 + f"\nCzy bot się zalogował: {'TAK' if logged_in else 'NIE'}")
