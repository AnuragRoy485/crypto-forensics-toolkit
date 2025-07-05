window.onload = function() {
  // ===== LOGIN SYSTEM (browser-only, safe for Netlify/static hosting) =====
  const DEMO_USER = "admin";
  const DEMO_PASS = "lawenforce@123";
  function showLogin() {
    document.getElementById('login-modal').style.display = "flex";
    document.getElementById('main-content').style.display = "none";
  }
  function showMain() {
    document.getElementById('login-modal').style.display = "none";
    document.getElementById('main-content').style.display = "block";
    window.scrollTo(0,0);
  }
  if (localStorage.getItem("forensics_logged_in") === "yes") showMain();
  else showLogin();
  document.getElementById("login-form").onsubmit = function() {
    let uid = document.getElementById("login-id").value.trim();
    let pwd = document.getElementById("login-password").value;
    let errBox = document.getElementById("login-error");
    if (uid === DEMO_USER && pwd === DEMO_PASS) {
      localStorage.setItem("forensics_logged_in","yes");
      showMain();
      document.getElementById("login-id").value = "";
      document.getElementById("login-password").value = "";
      errBox.textContent = "";
    } else {
      errBox.textContent = "Invalid Login ID or Password!";
      document.getElementById("login-password").value = "";
    }
  };
  document.getElementById("logout-btn").onclick = function(e) {
    e.preventDefault();
    localStorage.removeItem("forensics_logged_in");
    showLogin();
  };

  // ===== DESKTOP PYTHON SCRIPT (Robust & No Dummy Output) =====
  const pythonScript = `import os, re, platform, hashlib, sys

APPS = [
    "Trust", "MetaMask", "Coinbase", "Binance", "Phantom", "TokenPocket", "TronLink",
    "Exodus", "Blockchain.com", "Atomic Wallet", "Ledger Live"
]
EXTENSIONS = [".dat", ".key", ".bin", ".wallet", ".ldb", ".log", ".json", ".sqlite", ".txt", ".pdf", ".docx"]
KEYWORDS = [
    "wallet", "crypto", "seed", "mnemonic", "key", "backup", "keystore", "phrase", "ledger", "address",
    "0x", "bnb", "bc1", "ltc1", "trx", "doge", "exchange", "coinbase", "binance", "metamask", "phantom", "tronlink"
]
BROWSER_WALLETS = ["metamask", "phantom", "tronlink", "keplr", "coinbase", "wallet"]

HOME = os.path.expanduser("~")
REPORT = []
ERRORS = []

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        ERRORS.append(f"[SHA256 ERROR] {path}: {e}")
        return f"ERR:{e}"

def find_files(root, exts, keywords):
    found = []
    for r, d, f in os.walk(root, topdown=True, onerror=lambda e: ERRORS.append(f"[DIR ERROR] {e}")):
        for file in f:
            l = file.lower()
            if any(l.endswith(e) for e in exts) or any(k in l for k in keywords):
                p = os.path.join(r, file)
                found.append((p, sha256_file(p)))
    return found

def check_apps():
    plat = platform.system()
    found = []
    try:
        if plat == "Windows":
            try:
                import winreg
                for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        key = winreg.OpenKey(hive, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            skey = winreg.EnumKey(key, i)
                            try:
                                subkey = winreg.OpenKey(key, skey)
                                disp = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                if any(app.lower() in disp.lower() for app in APPS):
                                    found.append(disp)
                            except: pass
                    except Exception as e:
                        ERRORS.append(f"[WINREG ERROR] {e}")
            except Exception as e:
                ERRORS.append(f"[WINREG IMPORT ERROR] {e}")
        else:
            for d in ["/Applications", os.path.join(HOME, ".local/share/applications")]:
                if os.path.exists(d):
                    for f in os.listdir(d):
                        if any(app.lower() in f.lower() for app in APPS):
                            found.append(f)
    except Exception as e:
        ERRORS.append(f"[APPS SCAN ERROR] {e}")
    return found

def check_browser_wallet_extensions():
    found = []
    chromepaths = [
        os.path.join(HOME, ".config/google-chrome/Default/Extensions"),
        os.path.join(HOME, "AppData/Local/Google/Chrome/User Data/Default/Extensions"),
        os.path.join(HOME, "Library/Application Support/Google/Chrome/Default/Extensions"),
        os.path.join(HOME, ".mozilla/firefox")
    ]
    for p in chromepaths:
        if os.path.exists(p):
            try:
                for r, dirs, f in os.walk(p, onerror=lambda e: ERRORS.append(f"[EXT DIR ERROR] {e}")):
                    for d in dirs:
                        if any(b in d.lower() for b in BROWSER_WALLETS):
                            found.append(os.path.join(r, d))
            except Exception as e:
                ERRORS.append(f"[BROWSER WALLET ERROR] {e}")
    return found

def check_clipboard():
    try:
        import pyperclip
        cb = pyperclip.paste()
        if cb and any(k in cb.lower() for k in KEYWORDS):
            return cb
    except Exception as e:
        ERRORS.append(f"[CLIPBOARD ERROR] {e}")
    return None

def scan_notes_and_docs():
    files = []
    for base in ["Documents", "Downloads", "Desktop", "Notes", "OneDrive"]:
        path = os.path.join(HOME, base)
        if os.path.exists(path):
            try:
                files += find_files(path, EXTENSIONS, KEYWORDS)
            except Exception as e:
                ERRORS.append(f"[NOTES/DOCS ERROR] {e}")
    return files

def scan_screenshots():
    found = []
    pictures = os.path.join(HOME, "Pictures")
    if os.path.exists(pictures):
        try:
            for r, d, f in os.walk(pictures, onerror=lambda e: ERRORS.append(f"[PICTURES DIR ERROR] {e}")):
                for file in f:
                    if "screenshot" in file.lower() or any(k in file.lower() for k in KEYWORDS):
                        p = os.path.join(r, file)
                        found.append((p, sha256_file(p)))
        except Exception as e:
            ERRORS.append(f"[SCREENSHOT ERROR] {e}")
    return found

def scan_browser_history():
    try:
        from shutil import copy2
        import sqlite3
        plat = platform.system()
        if plat == "Windows":
            hp = os.path.join(HOME, "AppData/Local/Google/Chrome/User Data/Default/History")
        elif plat == "Darwin":
            hp = os.path.join(HOME, "Library/Application Support/Google/Chrome/Default/History")
        else:
            hp = os.path.join(HOME, ".config/google-chrome/Default/History")
        if os.path.exists(hp):
            tmp = "temp_history"
            copy2(hp, tmp)
            con = sqlite3.connect(tmp)
            c = con.cursor()
            matches = []
            for row in c.execute("SELECT url FROM urls"):
                url = row[0].lower()
                if any(kw in url for kw in KEYWORDS):
                    matches.append(url)
            con.close()
            os.remove(tmp)
            return matches
    except Exception as e:
        ERRORS.append(f"[BROWSER HISTORY ERROR] {e}")
    return []

def scan_password_managers():
    found = []
    try:
        for name in ["LastPass", "Bitwarden", "Dashlane", "KeePass", "Chrome", "Edge"]:
            try:
                if name.lower() in [x.lower() for x in os.listdir(HOME)]:
                    found.append(name)
            except: pass
    except Exception as e:
        ERRORS.append(f"[PASSWORD MANAGER ERROR] {e}")
    return found

def main():
    REPORT.append("=== [Crypto Forensics Report] ===")
    REPORT.append(f"[System]: {platform.system()} - {platform.node()}")
    REPORT.append("\\n--- Installed Crypto Wallet Apps ---")
    apps = check_apps()
    if apps:
        REPORT.extend(apps)
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Browser Wallet Extensions ---")
    exts = check_browser_wallet_extensions()
    if exts:
        REPORT.extend(exts)
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Password Managers Detected ---")
    pwds = scan_password_managers()
    if pwds:
        REPORT.extend(pwds)
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Notes/Docs/Downloads/Seed files (SHA256) ---")
    docs = scan_notes_and_docs()
    if docs:
        for p, h in docs:
            REPORT.append(f"{p} [SHA256: {h}]")
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Screenshots with Wallet or Seed (SHA256) ---")
    shots = scan_screenshots()
    if shots:
        for p, h in shots:
            REPORT.append(f"{p} [SHA256: {h}]")
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Browser History URLs (wallet/seed/crypto) ---")
    hist = scan_browser_history()
    if hist:
        REPORT.extend(hist)
    else:
        REPORT.append("None detected.")
    REPORT.append("\\n--- Clipboard (if suspicious) ---")
    cb = check_clipboard()
    if cb: REPORT.append(cb)
    else: REPORT.append("No relevant data.")
    if ERRORS:
        REPORT.append("\\n--- WARNINGS/ERRORS DURING SCAN ---")
        REPORT.extend(ERRORS)
    REPORT.append("\\n=== Scan completed. ===")
    with open("crypto_forensics_report.txt", "w", encoding="utf8") as f:
        for line in REPORT:
            f.write(str(line)+"\\n")
    print("\\n".join(REPORT))
    print("\\nReport saved as crypto_forensics_report.txt")

if __name__ == "__main__":
    main()
`;

  // ===== ANDROID BASH SCRIPT (Robust & No Dummy Output) =====
  const androidScript = `echo "=== Android Crypto Forensics Scan ==="

ERR=""

echo "[1] Installed Crypto Apps:"
pm list packages 2>/dev/null | grep -Ei "wallet|crypto|metamask|trust|exodus|electrum|tron|phantom|keplr|atomic|coinomi|binance|monero|zcash|litecoin|bnb|blockchain|coinbase"
if [ $? -ne 0 ]; then echo "Could not access package manager."; fi

echo "[2] APK remnants and wallet files:"
find /data/app -type d 2>/dev/null | grep -Ei "wallet|crypto|metamask|trust|exodus|electrum|tron|phantom|keplr|atomic|coinomi|binance|blockchain|coinbase"
if [ $? -ne 0 ]; then echo "Could not search /data/app (maybe no root)."; fi

find /sdcard/ -type f -iregex ".*\\(wallet\\|crypto\\|metamask\\|trust\\|exodus\\|electrum\\|tron\\|phantom\\|keplr\\|atomic\\|coinomi\\|binance\\|blockchain\\|coinbase\\|seed\\|mnemonic\\|backup\\|keystore\\|phrase\\|key\\|address\\|0x\\|bnb\\|bc1\\|ltc1\\|trx\\).*" -exec shasum -a 256 {} \\; 2>/dev/null
if [ $? -ne 0 ]; then echo "File scan error or no shasum utility."; fi

echo "[3] WhatsApp, Documents, Downloads, Screenshots:"
find /sdcard/WhatsApp/Media/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Download/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Documents/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Pictures/ -type f -iname "*screenshot*" -exec shasum -a 256 {} \\; 2>/dev/null

echo "[4] SMS/WhatsApp databases for wallet/seed phrases (if accessible):"
grep -Eri "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address" /sdcard/WhatsApp/Databases/ 2>/dev/null
grep -Eri "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address" /sdcard/Documents/ 2>/dev/null

echo "[5] Clipboard (if available):"
if command -v termux-clipboard-get >/dev/null 2>&1; then
  termux-clipboard-get | grep -Ei "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address"
else
  echo "Clipboard access not available (install Termux:API or not supported on this shell)."
fi

echo ""
echo "=== Scan Complete. If nothing is shown above, no obvious crypto traces found, or scan couldn't access some areas (no root/permissions). ==="
`;

  // ==== BUTTON HANDLERS ====
  window.copyScript = function(type) {
    let code = (type === "python") ? pythonScript : androidScript;
    navigator.clipboard.writeText(code).then(() => {
      alert('Script copied to clipboard!');
    });
  };

  window.downloadScript = function(type, filename) {
    let code = (type === "python") ? pythonScript : androidScript;
    let blob = new Blob([code], {type:'text/plain'});
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url; a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  window.downloadPython = function() {
    window.open('https://www.python.org/ftp/python/3.13.5/python-3.13.5-amd64.exe', '_blank');
  };

  window.showReport = function() {
    let txt = document.getElementById('report-input').value.trim();
    if (!txt) { alert('Please paste a report.'); return; }
    let lines = txt.split(/\r?\n/).filter(x=>x);
    let suspicious = lines.filter(l=>l.match(/sha256|wallet|metamask|mnemonic|bitcoin|ethereum|exodus|trust|phantom|seed|key|address|coinbase|binance/i));
    let summary = "<b>=== SCAN SUMMARY ===</b><br>";
    summary += suspicious.length
      ? `<span style='color:#00ffd0;font-weight:bold'>Suspicious traces found:</span><br>` +
        suspicious.slice(0,10).map(l=>"<div style='margin-bottom:2px'>" + l + "</div>").join("")
      : "<span style='color:#aaf'>No major crypto traces found in this report.</span>";
    summary += "<br><br><b>Full Report:</b><br><div style='font-size:0.98em;background:#181d2a;padding:1em 0.5em;border-radius:9px;margin:1em 0;max-height:300px;overflow-y:auto'>" +
      lines.slice(0, 200).join("<br>") + (lines.length > 200 ? "<br>...(truncated)" : "") +
      "</div>";
    document.getElementById('report-summary').innerHTML = summary;
  };

}; // end window.onload
