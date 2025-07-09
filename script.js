// =============== Modal / Auth / AutoLogout ===============
let sessionTimer = null;
let isLoggedIn = false;
const twofaSecretKey = "JBSWY3DPEHPK3PXP"; // Use a strong random base32 in real usage

window.onload = function () {
  showLawEnfModal();
  setLoginFormHandlers();
  setPythonDownload();
  setTabHandlers();
  setAutoLogout();
  setReportExport();
  logClientIP();
  setLogoutHandler();
  setTwoFAFormHandler();
};

// ====== 2FA Modal Logic ======
function show2FAModal() {
  document.getElementById('login-section').style.display = 'none';
  const modal = document.getElementById('twofa-modal');
  modal.style.display = 'flex';

  // Show QR code first time only
  if (!window._twofa_qr_generated) {
    const otpauth = otplib.authenticator.keyuri(
      "admin",
      "CryptoTracesToolkit",
      twofaSecretKey
    );
    document.getElementById('2fa-instructions').innerHTML =
      'Scan this QR code with <b>Google Authenticator</b> app.<br>Next, enter the 6-digit code below.';
    QRCode.toCanvas(
      document.getElementById('qrcode-2fa'),
      otpauth,
      { width: 210 },
      function (error) { }
    );
    window._twofa_qr_generated = true;
  }
  document.getElementById('twofa-code').value = '';
  document.getElementById('twofa-error').textContent = '';
}

function setTwoFAFormHandler() {
  const form = document.getElementById('twofa-form');
  if (!form) return;
  form.onsubmit = function (e) {
    e.preventDefault();
    const code = document.getElementById('twofa-code').value.trim();
    const valid = otplib.authenticator.check(code, twofaSecretKey);
    if (valid) {
      document.getElementById('twofa-modal').style.display = 'none';
      document.getElementById('main-content').style.display = 'block';
      isLoggedIn = true;
      setAutoLogout();
      logClientIP();
    } else {
      document.getElementById('twofa-error').textContent = "Invalid 2FA code. Try again!";
    }
  };
}

function showLawEnfModal() {
  const modal = document.getElementById('law-modal');
  const contBtn = document.getElementById('law-continue');
  const check = document.getElementById('law-check');
  if (!modal) return;
  modal.style.display = 'flex';

  contBtn.onclick = function () {
    if (check.checked) {
      modal.style.display = 'none';
    } else {
      check.focus();
      alert('You must acknowledge before proceeding.');
    }
  };
}

function setLoginFormHandlers() {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;
  loginForm.onsubmit = function (e) {
    e.preventDefault();
    const id = loginForm.querySelector('input[type="text"]').value.trim();
    const pass = loginForm.querySelector('input[type="password"]').value.trim();
    if (id === 'admin' && pass === 'forensics@321') {
      // Show 2FA Modal instead of main-content
      show2FAModal();
    } else {
      alert('Invalid Login');
    }
  };
}

function setAutoLogout() {
  clearTimeout(sessionTimer);
  sessionTimer = setTimeout(() => {
    document.getElementById('main-content').style.display = 'none';
    document.getElementById('login-section').style.display = 'flex';
    document.getElementById('twofa-modal').style.display = 'none';
    isLoggedIn = false;
    alert('Session expired. Please login again.');
  }, 1000 * 60 * 15); // 15 minutes
}

function setLogoutHandler() {
  const btn = document.getElementById('logout-btn');
  if (btn) {
    btn.onclick = function () {
      document.getElementById('main-content').style.display = 'none';
      document.getElementById('login-section').style.display = 'flex';
      document.getElementById('twofa-modal').style.display = 'none';
      isLoggedIn = false;
      alert('You have been logged out.');
    };
  }
}

// =============== Python Download Button ===============
function setPythonDownload() {
  const py1 = document.getElementById('py-download');
  const py2 = document.getElementById('py-download-inline');
  function downloadPy() {
    window.open('https://www.python.org/ftp/python/3.13.5/python-3.13.5-amd64.exe', '_blank');
  }
  if (py1) py1.onclick = downloadPy;
  if (py2) py2.onclick = downloadPy;
}

// =============== Navigation Tabs ===============
function setTabHandlers() {
  let tabLinks = [
    { btn: 'tab-desktop', sec: 'section-desktop' },
    { btn: 'tab-android', sec: 'section-android' },
    { btn: 'tab-instructions', sec: 'section-instructions' }
  ];
  tabLinks.forEach((tab, idx) => {
    document.getElementById(tab.btn).onclick = function (e) {
      e.preventDefault();
      tabLinks.forEach((tb) => {
        document.getElementById(tb.btn).classList.remove('active');
        document.getElementById(tb.sec).style.display = 'none';
      });
      this.classList.add('active');
      document.getElementById(tab.sec).style.display = 'block';
    };
  });
}

// =============== Report Export (to PDF) ===============
function setReportExport() {
  const btn = document.getElementById('export-pdf');
  if (!btn) return;
  btn.onclick = function () {
    const content = document.getElementById('report-summary').innerText;
    if (!content.trim()) return alert('No report to export.');
    const win = window.open('', '_blank');
    win.document.write(
      `<pre style="font-size:15px;font-family:monospace;padding:2em;background:#111b29;color:#00ffe1;">
      <b>Crypto Traces Forensics Toolkit<br>Forensic Report Summary</b><br><br>${content.replace(
        /</g,
        '&lt;'
      )}</pre>`
    );
    win.print();
  };
}

// =============== Forensics Scripts ===============
const desktopPythonScript = `import os, platform, hashlib

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

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERR:{e}"

def find_files(root, exts, keywords):
    found = []
    for r, d, f in os.walk(root):
        for file in f:
            l = file.lower()
            if any(l.endswith(e) for e in exts) and any(k in l for k in keywords):
                p = os.path.join(r, file)
                found.append((p, sha256_file(p)))
    return found

def check_apps():
    plat = platform.system()
    found = []
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
                except: pass
        except: pass
    else:
        for d in ["/Applications", os.path.join(HOME, ".local/share/applications")]:
            if os.path.exists(d):
                for f in os.listdir(d):
                    if any(app.lower() in f.lower() for app in APPS):
                        found.append(f)
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
            for r, dirs, f in os.walk(p):
                for d in dirs:
                    if any(b in d.lower() for b in BROWSER_WALLETS):
                        found.append(os.path.join(r, d))
    return found

def check_clipboard():
    try:
        import pyperclip
        cb = pyperclip.paste()
        if any(k in cb.lower() for k in KEYWORDS):
            return cb
    except: pass
    return None

def scan_notes_and_docs():
    files = []
    for base in ["Documents", "Downloads", "Desktop", "Notes", "OneDrive"]:
        path = os.path.join(HOME, base)
        if os.path.exists(path):
            files += find_files(path, EXTENSIONS, KEYWORDS)
    return files

def scan_screenshots():
    found = []
    pictures = os.path.join(HOME, "Pictures")
    if os.path.exists(pictures):
        for r, d, f in os.walk(pictures):
            for file in f:
                if "screenshot" in file.lower() or any(k in file.lower() for k in KEYWORDS):
                    p = os.path.join(r, file)
                    found.append((p, sha256_file(p)))
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
    except: pass
    return []

def scan_password_managers():
    found = []
    for name in ["LastPass", "Bitwarden", "Dashlane", "KeePass", "Chrome", "Edge"]:
        if name.lower() in os.listdir(HOME):
            found.append(name)
    return found

def main():
    REPORT.append("=== [Crypto Forensics Report] ===")
    REPORT.append(f"[System]: {platform.system()} - {platform.node()}")
    REPORT.append("\\n--- Installed Crypto Wallet Apps ---")
    REPORT += check_apps()
    REPORT.append("\\n--- Browser Wallet Extensions ---")
    REPORT += check_browser_wallet_extensions()
    REPORT.append("\\n--- Password Managers Detected ---")
    REPORT += scan_password_managers()
    REPORT.append("\\n--- Notes/Docs/Downloads/Seed files (SHA256) ---")
    for p, h in scan_notes_and_docs():
        REPORT.append(f"{p} [SHA256: {h}]")
    REPORT.append("\\n--- Screenshots with Wallet or Seed (SHA256) ---")
    for p, h in scan_screenshots():
        REPORT.append(f"{p} [SHA256: {h}]")
    REPORT.append("\\n--- Browser History URLs (wallet/seed/crypto) ---")
    REPORT += scan_browser_history()
    REPORT.append("\\n--- Clipboard (if suspicious) ---")
    cb = check_clipboard()
    if cb: REPORT.append(cb)
    with open("crypto_forensics_report.txt", "w", encoding="utf8") as f:
        for line in REPORT:
            f.write(str(line)+"\\n")
    print("\\n".join(REPORT))
    print("\\nReport saved as crypto_forensics_report.txt")

if __name__=="__main__":
    main()
`;

const androidScript = `echo "=== Android Crypto Forensics Scan ==="
echo "[1] Installed Crypto Apps:"
pm list packages | grep -Ei "wallet|crypto|metamask|trust|exodus|electrum|tron|phantom|keplr|atomic|coinomi|binance|monero|zcash|litecoin|bnb|blockchain|coinbase"
echo "[2] APK remnants and wallet files:"
find /data/app -type d 2>/dev/null | grep -Ei "wallet|crypto|metamask|trust|exodus|electrum|tron|phantom|keplr|atomic|coinomi|binance|blockchain|coinbase"
find /sdcard/ -type f -iregex ".*\\(wallet\\|crypto\\|metamask\\|trust\\|exodus\\|electrum\\|tron\\|phantom\\|keplr\\|atomic\\|coinomi\\|binance\\|blockchain\\|coinbase\\|seed\\|mnemonic\\|backup\\|keystore\\|phrase\\|key\\|address\\|0x\\|bnb\\|bc1\\|ltc1\\|trx\\).*" -exec shasum -a 256 {} \\;
echo "[3] WhatsApp, Documents, Downloads, Screenshots:"
find /sdcard/WhatsApp/Media/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Download/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Documents/ -type f 2>/dev/null | grep -Ei "wallet|crypto|seed|mnemonic|key|address"
find /sdcard/Pictures/ -type f -iname "*screenshot*" -exec shasum -a 256 {} \\;
echo "[4] SMS/WhatsApp databases for wallet/seed phrases (if accessible):"
grep -Eri "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address" /sdcard/WhatsApp/Databases/ 2>/dev/null
grep -Eri "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address" /sdcard/Documents/ 2>/dev/null
echo "[5] Clipboard (if available):"
if command -v termux-clipboard-get >/dev/null 2>&1; then
  termux-clipboard-get | grep -Ei "wallet|seed|mnemonic|bitcoin|ethereum|metamask|address"
else
  echo "Clipboard access not available (install Termux:API)"
fi
echo "=== Scan Complete. Review above for evidence (SHA256 hashes for files). ==="
`;

function copyScript(scriptType) {
  let code = scriptType === 'desktop' ? desktopPythonScript : androidScript;
  navigator.clipboard.writeText(code).then(() =>
    alert('Script copied to clipboard!')
  );
}

function downloadScript(scriptType) {
  let filename =
    scriptType === 'desktop'
      ? 'crypto_desktop_scan.py'
      : 'crypto_android_scan.sh';
  let code = scriptType === 'desktop' ? desktopPythonScript : androidScript;
  let blob = new Blob([code], { type: 'text/plain' });
  let url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// =============== Report Summary, Validation ===============
function showReport() {
  let txt = document.getElementById('report-input').value.trim();
  if (!txt) {
    alert('Please paste a report.');
    return;
  }
  if (
    !/^=+\s*\[Crypto Forensics Report\]/im.test(txt) ||
    !/---/m.test(txt)
  ) {
    alert('This report appears incomplete or invalid. Please check and try again.');
    return;
  }
  let lines = txt.split(/\r?\n/).filter((x) => x);
  let suspicious = lines.filter((l) =>
    l.match(
      /sha256|wallet|metamask|mnemonic|bitcoin|ethereum|exodus|trust|phantom|seed|key|address|coinbase|binance/i
    )
  );
  let summary = "<b>=== SCAN SUMMARY ===</b><br>";
  summary += suspicious.length
    ? `<span style='color:#00ffd0;font-weight:bold'>Suspicious traces found:</span><br>` +
      suspicious
        .map((l) => l.replace(/(.{80})/g, '$1<br>'))
        .join('<br>')
    : "<span style='color:#ff6380;font-weight:bold'>No crypto traces detected.</span>";
  summary += "<br><br><b>Full Report:</b><br><pre style='font-size:1em;max-height:180px;overflow:auto;background:#081019cc;padding:1em;border-radius:7px;'>" +
    txt.replace(/</g, '&lt;') + "</pre>";
  document.getElementById('report-summary').innerHTML = summary;
}

// =============== IP Logging Feature ===============
function logClientIP() {
  fetch('https://api.ipify.org?format=json')
    .then((resp) => resp.json())
    .then((data) => {
      const ipEl = document.getElementById('ip-log');
      if (ipEl) ipEl.textContent = "Your IP: " + data.ip;
    });
}
