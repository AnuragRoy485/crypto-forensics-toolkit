// ====== LOGIN FEATURE ======
let isLoggedIn = false;
const AUTO_LOGOUT_MS = 10 * 60 * 1000; // 10 minutes
let logoutTimer;

// Credentials (change as needed)
const VALID_USERNAME = "admin";
const VALID_PASSWORD = "forensics@25";

// ====== DESKTOP PYTHON SCRIPT ======
const pythonScript = `import os, re, platform, hashlib
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
            if any(l.endswith(e) for e in exts) or any(k in l for k in keywords):
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

// ====== ANDROID BASH SCRIPT ======
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

// ====== LOGIN & LOGOUT ======
function showLogin() {
  document.body.innerHTML = `
    <div class="login-container">
      <div class="login-card glass">
        <h2 style="margin-bottom:1.2em;">Crypto Traces Forensics Toolkit</h2>
        <input id="login-username" type="text" placeholder="Login ID">
        <input id="login-password" type="password" placeholder="Password">
        <button onclick="tryLogin()">Login</button>
      </div>
    </div>
  `;
}
function tryLogin() {
  let u = document.getElementById("login-username").value.trim();
  let p = document.getElementById("login-password").value.trim();
  if (u === VALID_USERNAME && p === VALID_PASSWORD) {
    isLoggedIn = true;
    document.body.innerHTML = window._main_html;
    window.onload();
    document.getElementById('logout-link').style.display = "inline";
    startLogoutTimer();
  } else {
    alert("Invalid credentials. Please try again.");
  }
}
function logout() {
  isLoggedIn = false;
  showLogin();
  clearTimeout(logoutTimer);
}
function resetLogoutTimer() {
  clearTimeout(logoutTimer);
  if (isLoggedIn) startLogoutTimer();
}
function startLogoutTimer() {
  logoutTimer = setTimeout(() => {
    alert("Session expired due to inactivity. Please login again.");
    logout();
  }, AUTO_LOGOUT_MS);
}
["click", "keydown", "mousemove", "touchstart"].forEach(evt => {
  document.addEventListener(evt, resetLogoutTimer, true);
});

// ====== SCRIPT COPY/DOWNLOAD ======
function copyScript(id) {
  if (!isLoggedIn) { alert("Please login first."); return; }
  let text = (id === 'py-script') ? pythonScript : androidScript;
  navigator.clipboard.writeText(text).then(() => {
    alert('Script copied to clipboard!');
  });
}
function downloadScript(id, filename) {
  if (!isLoggedIn) { alert("Please login first."); return; }
  let text = (id === 'py-script') ? pythonScript : androidScript;
  let blob = new Blob([text], {type:'text/plain'});
  let url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url; a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
function downloadPython() {
  window.open('https://www.python.org/ftp/python/3.13.5/python-3.13.5-amd64.exe', '_blank');
}

// ====== REPORT SUMMARY ======
let lastSummaryHTML = "";
let lastFullReport = "";

function showReport() {
  if (!isLoggedIn) { alert("Please login first."); return; }
  let txt = document.getElementById('report-input').value.trim();
  if (!txt) { alert('Please paste a report.'); return; }
  let lines = txt.split(/\r?\n/).filter(x=>x);
  let suspicious = lines.filter(l=>
    l.match(/sha256|wallet|metamask|mnemonic|bitcoin|ethereum|exodus|trust|phantom|seed|key|address|coinbase|binance/i)
  );
  let summary = "<b>=== SCAN SUMMARY ===</b><br>";
  summary += suspicious.length
    ? `<span style='color:#00ffd0;font-weight:bold'>Suspicious traces found:</span><br>` +
      suspicious.slice(0,10).map(l=>"<div style='margin-bottom:2px'>" + l + "</div>").join("")
    : "<span style='color:#aaf'>No major crypto traces found in this report.</span>";
  summary += "<br><br><b>Full Report:</b><br><div style='font-size:0.98em;background:#181d2a;padding:1em 0.5em;border-radius:9px;margin:1em 0;max-height:300px;overflow-y:auto'>" +
    lines.slice(0, 200).join("<br>") + (lines.length > 200 ? "<br>...(truncated)" : "") +
    "</div>";
  document.getElementById('report-summary').innerHTML = summary;
  lastSummaryHTML = summary;
  lastFullReport = txt;
  document.getElementById('export-pdf-btn').style.display = "inline-block";
}

// ====== EXPORT TO PDF ======
function exportReportPDF() {
  if (!isLoggedIn) { alert("Please login first."); return; }
  const { jsPDF } = window.jspdf;
  let doc = new jsPDF({ unit: "pt", format: "a4" });
  let now = new Date();
  let dateStr = now.toLocaleString();
  let y = 42;
  // Title & header
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.setTextColor("#026CFF");
  doc.text("Crypto Traces Forensics Toolkit", 36, y);
  y += 28;
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor("#111");
  doc.text(`For Law Enforcement Use Only — Report generated: ${dateStr}`, 36, y);
  y += 22;
  doc.setDrawColor(100, 180, 255);
  doc.line(36, y, 540, y);
  y += 18;

  // Summary
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("Scan Summary:", 36, y);
  y += 20;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  let summaryLines = lastSummaryHTML.replace(/<[^>]+>/g,'').split('\n');
  summaryLines.forEach(line => {
    doc.text(line.trim(), 36, y);
    y += 14;
    if (y > 740) { doc.addPage(); y = 42; }
  });

  // Full Report
  y += 20;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("Full Forensic Report:", 36, y);
  y += 20;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  let repLines = lastFullReport.split('\n');
  repLines.forEach(line => {
    doc.text(line.substring(0,140), 36, y);
    y += 12;
    if (y > 760) { doc.addPage(); y = 42; }
  });

  // Footer
  doc.setFont("helvetica", "italic");
  doc.setTextColor("#1477dd");
  doc.setFontSize(11);
  doc.text("© Anurag Roy | Crypto Traces Forensics Toolkit | Strictly for Law Enforcement Use | Jai Hind", 36, 810);

  doc.save(`crypto_forensics_report_${now.getFullYear()}${now.getMonth()+1}${now.getDate()}_${now.getHours()}${now.getMinutes()}.pdf`);
}

// ====== MAIN UI INIT ======
window.onload = function() {
  if (!isLoggedIn) {
    window._main_html = document.body.innerHTML;
    showLogin();
    return;
  }
  if (document.getElementById('py-script'))
    document.getElementById('py-script').textContent = pythonScript;
  if (document.getElementById('android-script'))
    document.getElementById('android-script').textContent = androidScript;
  let btn = document.getElementById('export-pdf-btn');
  if (btn) btn.style.display = "none";
  document.getElementById('logout-link').style.display = "inline";
};
