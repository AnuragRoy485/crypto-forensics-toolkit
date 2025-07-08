// ===== Security Modal Handling =====
window.onload = function () {
  document.getElementById("security-modal").classList.add("show");
  document.getElementById("login-modal").style.display = "none";
  document.getElementById("dashboard").style.display = "none";
  getUserIP();
};
document.getElementById("accept-btn").onclick = function () {
  if (!document.getElementById("security-check").checked) {
    alert("You must acknowledge the security notice!");
    return;
  }
  document.getElementById("security-modal").style.display = "none";
  document.getElementById("login-modal").style.display = "flex";
  getUserIP();
};

// ===== Login Handling & Auto-Logout =====
const VALID_USER = "admin", VALID_PASS = "forensics@485";
let loginTimeout;

function resetAutoLogout() {
  clearTimeout(loginTimeout);
  loginTimeout = setTimeout(() => {
    logout();
    alert("Logged out due to inactivity.");
  }, 5 * 60 * 1000); // 5 minutes
}

document.getElementById("login-form").onsubmit = function(e){
  e.preventDefault();
  const u = document.getElementById("login-username").value.trim();
  const p = document.getElementById("login-password").value;
  if (u === VALID_USER && p === VALID_PASS) {
    document.getElementById("login-modal").style.display = "none";
    document.getElementById("dashboard").style.display = "block";
    resetAutoLogout();
    ["mousemove","keydown","click"].forEach(ev =>
      window.addEventListener(ev, resetAutoLogout)
    );
  } else {
    document.getElementById("login-error").textContent = "Invalid Login ID or Password";
  }
  return false;
};
function logout() {
  document.getElementById("dashboard").style.display = "none";
  document.getElementById("login-modal").style.display = "flex";
  document.getElementById("login-error").textContent = "";
}
document.getElementById("logout-btn").onclick = logout;

// ===== IP Logger (Frontend Demo) =====
function getUserIP(){
  fetch('https://api.ipify.org?format=json')
    .then(res=>res.json())
    .then(data=>{
      const ipDiv = document.getElementById("user-ip");
      if(ipDiv) ipDiv.innerHTML = "Your IP: <b>" + data.ip + "</b>";
    });
}

// ===== Python (Desktop) Script =====
const pythonScript = `import os, re, platform, hashlib

APPS = [
    "Trust", "MetaMask", "Coinbase", "Binance", "Phantom", "TokenPocket", "TronLink",
    "Exodus", "Blockchain.com", "Atomic Wallet", "Ledger Live"
]
EXTENSIONS = [".dat", ".key", ".wallet", ".ldb", ".json", ".sqlite"]
KEYWORDS = [
    "wallet", "crypto", "seed", "mnemonic", "key", "keystore", "phrase", "ledger", "address",
    "0x", "bnb", "bc1", "ltc1", "trx", "exchange", "coinbase", "binance", "metamask", "phantom", "tronlink"
]
HOME = os.path.expanduser("~")
REPORT = []

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

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

def main():
    global REPORT
    REPORT.append("=== [Crypto Forensics Report] ===")
    REPORT.append(f"[System]: {platform.system()} - {platform.node()}")
    REPORT.append("\\n--- Installed Crypto Wallet Apps ---")
    REPORT += check_apps()
    REPORT.append("\\n--- Notes/Docs/Downloads/Seed files (SHA256) ---")
    for p, h in find_files(HOME, EXTENSIONS, KEYWORDS):
        if h:
            REPORT.append(f"{p} [SHA256: {h}]")
    with open("crypto_forensics_report.txt", "w", encoding="utf8") as f:
        for line in REPORT:
            f.write(str(line)+"\\n")
    print("\\n".join(REPORT))
    print("\\nReport saved as crypto_forensics_report.txt")

if __name__=="__main__":
    main()
`;

// ===== Android Forensics Script =====
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

// Set scripts on page load
document.getElementById('py-script').textContent = pythonScript;
document.getElementById('android-script').textContent = androidScript;

// ===== Copy/Download Script Functions (Desktop/Android) =====
function copyScript(id) {
  let el = document.getElementById(id);
  let text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('Script copied to clipboard!');
  });
}
function downloadScript(id, filename) {
  let el = document.getElementById(id);
  let text = el.textContent || el.innerText;
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

// ======= Report Validation, Summary, and PDF =======
function showReport() {
  let txt = document.getElementById('report-input').value.trim();
  if (!txt || txt.length < 50) {
    alert('Please paste a valid report!');
    return;
  }
  // Validation for truncation/error
  if (/truncated|error|failed/i.test(txt) || txt.split('\n').length < 8) {
    alert('Report appears incomplete or may have errors!');
  }
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
}

// ======= PDF Export =======
function exportPDF() {
  let summary = document.getElementById("report-summary");
  if (!summary || !summary.innerText.trim()) {
    alert("Please generate a summary before exporting.");
    return;
  }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  doc.setFontSize(17);
  doc.text("Crypto Traces Forensics Toolkit", 14, 18);
  doc.setFontSize(12);
  doc.text(summary.innerText, 14, 28, {maxWidth: 180});
  doc.save("Forensics_Report_Summary.pdf");
}
