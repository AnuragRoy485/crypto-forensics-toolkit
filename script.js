// ========== LOGIN SYSTEM ==========
const VALID_USERNAME = "admin";
const VALID_PASSWORD = "forensics2025"; // Change to your desired password
let isLoggedIn = false;

function showLogin() {
  document.getElementById("login-wrapper").style.display = "flex";
  document.getElementById("main-content").style.display = "none";
}
function hideLogin() {
  document.getElementById("login-wrapper").style.display = "none";
  document.getElementById("main-content").style.display = "";
}
function doLogin(event) {
  event.preventDefault();
  const u = document.getElementById("login-user").value.trim();
  const p = document.getElementById("login-pass").value.trim();
  if (u === VALID_USERNAME && p === VALID_PASSWORD) {
    isLoggedIn = true;
    hideLogin();
  } else {
    alert("Invalid credentials. Try again.");
    document.getElementById("login-pass").value = "";
  }
}

// ========== ADVANCED PYTHON SCAN SCRIPT ==========
const pythonScript = `import os
import re
import platform
import hashlib

APPS = [
    "Trust", "MetaMask", "Coinbase", "Binance", "Phantom", "TokenPocket", "TronLink",
    "Exodus", "Blockchain.com", "Atomic Wallet", "Ledger Live"
]
EXTENSIONS = [".dat", ".key", ".bin", ".wallet", ".ldb", ".log", ".json", ".sqlite", ".txt", ".pdf", ".docx"]
KEYWORDS = [
    "wallet", "crypto", "seed", "mnemonic", "key", "backup", "keystore", "phrase", "ledger", "address",
    "0x", "bnb", "bc1", "ltc1", "trx", "doge", "exchange", "coinbase", "binance", "metamask", "phantom", "tronlink"
]

CRYPTO_ADDRESS_PATTERNS = [
    r'(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}',  # Bitcoin
    r'0x[a-fA-F0-9]{40}',                  # Ethereum
    r't[1-9A-HJ-NP-Za-km-z]{33}',          # Tron, etc.
]
MNEMONIC_WORDS = set([
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access",
    # ... Add more BIP39 words for better accuracy
])

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

def is_possible_mnemonic(text):
    words = text.strip().lower().split()
    if len(words) in [12, 15, 18, 21, 24]:
        matched = sum(1 for w in words if w in MNEMONIC_WORDS)
        return matched > (len(words) * 0.7)
    return False

def is_crypto_content(text):
    for pat in CRYPTO_ADDRESS_PATTERNS:
        if re.search(pat, text):
            return True
    if is_possible_mnemonic(text):
        return True
    if re.search(r'\\b[a-fA-F0-9]{64}\\b', text):
        return True
    return False

def find_crypto_files(root, exts, keywords):
    found = []
    for r, d, f in os.walk(root):
        for file in f:
            l = file.lower()
            if any(l.endswith(e) for e in exts) or any(k in l for k in keywords):
                p = os.path.join(r, file)
                try:
                    with open(p, 'r', encoding='utf8', errors='ignore') as fp:
                        sample = fp.read(2048)
                        if is_crypto_content(sample):
                            found.append((p, sha256_file(p)))
                except Exception as e:
                    continue
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

def main():
    REPORT.append("=== [Crypto Forensics Report] ===")
    REPORT.append(f"[System]: {platform.system()} - {platform.node()}")
    REPORT.append("\\n--- Installed Crypto Wallet Apps ---")
    REPORT.extend(check_apps())
    REPORT.append("\\n--- Notes/Docs/Downloads/Seed files (SHA256, content-matched) ---")
    for p, h in find_crypto_files(HOME, EXTENSIONS, KEYWORDS):
        REPORT.append(f"{p} [SHA256: {h}]")
    with open("crypto_forensics_report.txt", "w", encoding="utf8") as f:
        for line in REPORT:
            f.write(str(line)+"\\n")
    print("\\n".join(REPORT))
    print("\\nReport saved as crypto_forensics_report.txt")

if __name__=="__main__":
    main()
`;

// ========== ANDROID SCRIPT ==========
const androidScript = `echo "=== Android Crypto Forensics Scan ==="
# ... You may update this for advanced detection as above ...
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

function copyScript(id) {
  if (!isLoggedIn) { alert("Please login first."); return; }
  let text = '';
  if (id === 'py-script') text = pythonScript;
  if (id === 'android-script') text = androidScript;
  navigator.clipboard.writeText(text).then(() => {
    alert('Script copied to clipboard!');
  });
}
function downloadScript(id, filename) {
  if (!isLoggedIn) { alert("Please login first."); return; }
  let text = '';
  if (id === 'py-script') text = pythonScript;
  if (id === 'android-script') text = androidScript;
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
window.onload = () => {
  showLogin();
};
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
}
