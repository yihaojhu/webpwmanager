// main.js
// Depends on CryptoJS loaded by index.html
// Data model: services -> { serviceName: {cipher: "<salt:ct>"} } stored in localStorage
const STORAGE_KEY = "ppm_services_v1";

let services = {}; // in-memory: {service: {accountCipher, passwordCipher} }
let lang = {};
const LANGS = { "English": "lang_en.json", "Chinese": "lang_zh.json" };

function setStatus(t, timeout=3000){
  const s = document.getElementById("status");
  s.textContent = t;
  if(timeout>0) setTimeout(()=> s.textContent = "", timeout);
}

// Derive a key from magicNumber and salt using PBKDF2
function deriveKey(magic, salt, iterations=10000){
  return CryptoJS.PBKDF2(magic, CryptoJS.enc.Hex.parse(salt), { keySize: 256/32, iterations: iterations });
}
// helper to create random hex salt
function randomHex(lenBytes=8){
  const array = CryptoJS.lib.WordArray.random(lenBytes);
  return CryptoJS.enc.Hex.stringify(array);
}

// AES encrypt: returns "salt:cipherBase64"
function aesEncrypt(plaintext, magic){
  const salt = randomHex(8);
  const key = deriveKey(magic, salt);
  const iv = CryptoJS.lib.WordArray.random(16);
  const ct = CryptoJS.AES.encrypt(plaintext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  // we'll store salt + iv + ciphertext as base64 parts joined by ':'
  return salt + ":" + CryptoJS.enc.Base64.stringify(iv.concat(ct.ciphertext));
}

// AES decrypt accepts "salt:ivAndCipher"
function aesDecrypt(blob, magic){
  try{
    const [salt, ivAndCipherB64] = blob.split(":");
    if(!salt || !ivAndCipherB64) return "";
    const ivAndCipherWA = CryptoJS.enc.Base64.parse(ivAndCipherB64);
    // iv is first 16 bytes -> WordArray of 16 bytes = 128 bits
    const iv = CryptoJS.lib.WordArray.create(ivAndCipherWA.words.slice(0,4), 16);
    const ciphertext = CryptoJS.lib.WordArray.create(ivAndCipherWA.words.slice(4), ivAndCipherWA.sigBytes - 16);
    const key = deriveKey(magic, salt);
    const res = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return res.toString(CryptoJS.enc.Utf8);
  }catch(e){
    return "";
  }
}

// UI wiring
window.addEventListener("load", () => {
  // DOM refs
  const el = id => document.getElementById(id);
  // populate language selector
  const langSelect = el("langSelect");
  for(const name in LANGS){
    const opt = document.createElement("option");
    opt.value = name;
    opt.text = name;
    langSelect.appendChild(opt);
  }
  langSelect.value = "English";
  loadLang("English");

  // Buttons
  el("btnAdd").addEventListener("click", addService);
  el("btnRemove").addEventListener("click", removeService);
  el("btnFind").addEventListener("click", findService);
  el("btnClear").addEventListener("click", clearFields);
  el("btnExport").addEventListener("click", exportJson);
  el("btnImport").addEventListener("click", importFromFile);
  el("btnAbout").addEventListener("click", showAbout);
  el("closeAbout").addEventListener("click", hideAbout);

  langSelect.addEventListener("change", (e)=> loadLang(e.target.value));
  loadFromStorage();
  updateList();
  setStatus(lang.ready || "Ready", 1500);
  // clicking a service name loads it into the Service field
  el("serviceList").addEventListener("click", (evt)=>{
    if(evt.target && evt.target.nodeName==="LI"){
      el("service").value = evt.target.getAttribute("data-service");
    }
  });
});

// load localized strings
async function loadLang(name){
  const path = LANGS[name];
  try{
    const resp = await fetch(path);
    lang = await resp.json();
  }catch(e){
    console.warn("failed to load language", e);
    lang = {};
  }
  // update UI text
  document.getElementById("labelMagicNumber").textContent = lang.labelMagicNumber || "Magic Number:";
  document.getElementById("labelService").textContent = lang.labelService || "Service:";
  document.getElementById("labelAccount").textContent = lang.labelAccount || "Account:";
  document.getElementById("labelPassword").textContent = lang.labelPassword || "Password:";
  document.getElementById("btnAdd").textContent = lang.buttonAdd || "Add";
  document.getElementById("btnRemove").textContent = lang.buttonRemove || "Remove";
  document.getElementById("btnFind").textContent = lang.buttonFind || "Find";
  document.getElementById("btnClear").textContent = lang.buttonClear || "Clear";
  document.getElementById("servicesTitle").textContent = lang.dockWidgetServices || "List of Services";
  document.getElementById("title").textContent = lang.titleMainWindow || "Account Password Manager";
  document.getElementById("aboutText").textContent = lang.aboutText || "";
  document.getElementById("aboutTitle").textContent = lang.aboutTitle || "About";
  setStatus(lang.ready || "Ready");
}

// Add service: encrypt account/password with AES derived from magic and save
function addService(){
  const magic = document.getElementById("magicNumber").value;
  const service = document.getElementById("service").value.trim();
  const account = document.getElementById("account").value;
  const password = document.getElementById("password").value;
  if(!service){ alert("Please provide service name"); return; }
  if(!magic){ alert("Magic Number required to encrypt"); return; }
  services[service] = {
    account: aesEncrypt(account, magic),
    password: aesEncrypt(password, magic)
  };
  saveToStorage();
  updateList();
  setStatus((lang.addService || "Added \"%s\"").replace("%s", service));
}

// Remove service
function removeService(){
  const service = document.getElementById("service").value.trim();
  if(!service) { alert("Service required"); return; }
  if(services[service]) delete services[service];
  saveToStorage();
  updateList();
  setStatus((lang.removeService || "Removed \"%s\"").replace("%s", service));
}

// Find service: decrypt with magic
function findService(){
  const magic = document.getElementById("magicNumber").value;
  const service = document.getElementById("service").value.trim();
  if(!service || !magic){ alert("Provide service and Magic Number"); return; }
  const entry = services[service];
  if(!entry){
    alert((lang.findNoService || 'Can\\'t find "%s"').replace("%s", service));
    return;
  }
  const acc = aesDecrypt(entry.account, magic);
  const pwd = aesDecrypt(entry.password, magic);
  if(acc==="" && pwd===""){
    alert("Decryption failed — ensure the Magic Number is correct.");
    return;
  }
  document.getElementById("account").value = acc;
  document.getElementById("password").value = pwd;
  setStatus((lang.findService || 'Found "%s"').replace("%s", service));
}

// clear fields
function clearFields(){
  document.getElementById("magicNumber").value = "";
  document.getElementById("service").value = "";
  document.getElementById("account").value = "";
  document.getElementById("password").value = "";
  setStatus(lang.ready || "Ready");
}

// update service list UI
function updateList(){
  const ul = document.getElementById("serviceList");
  ul.innerHTML = "";
  Object.keys(services).sort().forEach(s=>{
    const li = document.createElement("li");
    li.textContent = s;
    li.setAttribute("data-service", s);
    ul.appendChild(li);
  });
}

// persistent storage (localStorage)
function saveToStorage(){
  localStorage.setItem(STORAGE_KEY, JSON.stringify(services));
}
function loadFromStorage(){
  const raw = localStorage.getItem(STORAGE_KEY);
  if(raw) services = JSON.parse(raw);
  else services = {};
}

// export decrypted? no — we export the AES-encrypted JSON blob (so file can be imported later)
function exportJson(){
  const blob = new Blob([JSON.stringify({services: services}, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "ppm_export.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// import JSON file — two supported shapes:
// 1) converted .ppb JSON: { "services": { "svc": {"account":"plaintext","password":"plaintext"} } }
// 2) exported PPM AES JSON: { "services": { "svc": { "account": "<salt:ivct>", "password": "<...>" } } }
function importFromFile(){
  const finput = document.getElementById("importFile");
  const file = finput.files[0];
  if(!file){ alert("Choose a JSON file first (use the converter for .ppb files)."); return; }
  const reader = new FileReader();
  reader.onload = e => {
    try{
      const obj = JSON.parse(e.target.result);
      if(obj.services){
        // detect plain or encrypted by checking if values look like "salt:..."
        const keys = Object.keys(obj.services);
        for(const k of keys){
          const v = obj.services[k];
          if(v.hasOwnProperty("account") && v.hasOwnProperty("password")){
            const acc = v.account;
            const pwd = v.password;
            // if account string contains ':' and hex-salt length 16+ -> treat as encrypted; else treat as plaintext and re-encrypt
            if(typeof acc === "string" && acc.includes(":") && acc.split(":")[0].length >= 16 && acc.split(":").length===2){
              // assumes it's already AES encrypted: take as-is
              services[k] = { account: acc, password: pwd };
            }else{
              // plaintext imported: ask user for magic to encrypt locally
              const magic = prompt("Imported file contains plaintext entries. Enter Magic Number you want to encrypt them with:");
              if(!magic){ alert("Import canceled (no magic provided)"); return; }
              services[k] = { account: aesEncrypt(acc, magic), password: aesEncrypt(pwd, magic) };
            }
          }
        }
        saveToStorage();
        updateList();
        setStatus("Import finished", 3000);
      } else {
        alert("JSON missing 'services' key");
      }
    }catch(err){
      alert("Failed to parse JSON: " + err);
    }
  };
  reader.readAsText(file);
}

// About modal handling
function showAbout(){
  document.getElementById("aboutModal").classList.remove("hidden");
}
function hideAbout(){
  document.getElementById("aboutModal").classList.add("hidden");
}
