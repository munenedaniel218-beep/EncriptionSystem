const enc = new TextEncoder(), dec = new TextDecoder();

const $ = id => document.getElementById(id);

const MAXB = 10 * 1024 * 1024;

let lastCipher = "", lastName = "message", recovered = null;

function b64(buf) {
    const a = new Uint8Array(buf);
    let s = "";

    for (let i = 0; i < a.length; i += 0x8000)
        s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));

    return btoa(s);
}

const unb64 = s => Uint8Array.from(
    atob(s.replace(/\s+/g, "")),
    c => c.charCodeAt(0)
);

const fmt = n => n < 1024 ? n + " B" :
    n < 1048576 ? (n / 1024).toFixed(1) + " KB" :
    (n / 1048576).toFixed(1) + " MB";


function packText(t) {
    const b = enc.encode(t);
    const o = new Uint8Array(1 + b.length);

    o[0] = 0;
    o.set(b, 1);

    return o;
}


function packFile(name, bytes) {
    const n = enc.encode(name);
    const o = new Uint8Array(3 + n.length + bytes.length);

    o[0] = 1;
    o[1] = n.length >> 8;
    o[2] = n.length & 255;

    o.set(n, 3);
    o.set(bytes, 3 + n.length);

    return o;
}


function unpack(p) {

    if (p[0] === 0)
        return {
            type: "text",
            text: dec.decode(p.subarray(1))
        };

    const L = (p[1] << 8) | p[2];

    return {
        type: "file",
        name: dec.decode(p.subarray(3, 3 + L)),
        bytes: p.subarray(3 + L)
    };
}


async function deriveKey(pw, salt) {

    const base = await crypto.subtle.importKey(
        "raw",
        enc.encode(pw),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        base,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}


async function encryptBytes(payload, pw) {

    const salt = crypto.getRandomValues(new Uint8Array(16));

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKey(pw, salt);

    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        payload
    );

    const out = new Uint8Array(28 + ct.byteLength);

    out.set(salt, 0);
    out.set(iv, 16);
    out.set(new Uint8Array(ct), 28);

    return b64(out);
}


async function decryptBytes(data, pw) {

    const raw = unb64(data);

    if (raw.length < 45)
        throw new Error("short");

    const key = await deriveKey(pw, raw.slice(0, 16));

    return new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: raw.slice(16, 28)
            },
            key,
            raw.slice(28)
        )
    );
}


async function saveFile(name, data) {

    let dl = null;

    try {
        if (typeof claude !== "undefined")
            dl = await claude.use("downloads");
    } catch (e) {}

    if (dl)
        return dl.save({ filename: name, data });

    const a = document.createElement("a");

    a.href = URL.createObjectURL(new Blob([data]));
    a.download = name;

    document.body.appendChild(a);
    a.click();
    a.remove();

}


function saveError(e, m) {

    m.className = "msg bad";

    if (e && e.code === "declined")
        m.textContent = "Save cancelled.";

    else if (e && e.code === "rejected_extension")
        m.textContent = "This page cannot save that file type. Allowed: pdf, docx, xlsx, pptx, png, jpg, gif, webp, mp4, webm, txt, csv, json, md, zip.";

    else
        m.textContent = "Could not save the file here. Try opening this page in a regular browser tab.";
}


function tab(which) {

    const e = which === "e";

    $("encPane").hidden = !e;
    $("decPane").hidden = e;

    $("tabE").setAttribute("aria-selected", e);
    $("tabD").setAttribute("aria-selected", !e);
}


$("tabE").onclick = () => tab("e");

$("tabD").onclick = () => tab("d");

$("goDec").onclick = () => {
    tab("d");
    $("pwD").focus();
};


function toggle(btn, input) {

    btn.onclick = () => {

        const s = input.type === "password";

        input.type = s ? "text" : "password";

        btn.textContent = s ? "Hide" : "Show";
    };
}


toggle($("showE"), $("pwE"));

toggle($("showD"), $("pwD"));


$("pwE").oninput = () => {

    const p = $("pwE").value;

    let s = 0;

    if (p.length >= 8) s++;

    if (p.length >= 12) s++;

    if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;

    if (/\d/.test(p)) s++;

    if (/[^A-Za-z0-9]/.test(p)) s++;

    const labels = [
        "Very weak",
        "Weak",
        "Fair",
        "Good",
        "Strong",
        "Very strong"
    ];

    const cols = [
        "#a12626",
        "#a12626",
        "#b7791f",
        "#b7791f",
        "#1b6b3a",
        "#1b6b3a"
    ];

    $("bar").style.width = (p ? (s / 5) * 100 : 0) + "%";

    $("bar").style.background = cols[s];

    $("strength").textContent = p ? labels[s] : "";
};


$("encBtn").onclick = async () => {

    const p = $("pwE").value;

    const m = $("encMsg");

    const f = $("fileE").files[0];

    const t = $("plain").value;

    m.className = "msg";

    $("encOut").style.display = "none";

    if (!f && !t) {
        m.textContent = "Enter a message or choose a file.";
        m.classList.add("bad");
        return;
    }

    if (f && f.size > MAXB) {
        m.textContent = "File is too large. The limit is 10 MB.";
        m.classList.add("bad");
        return;
    }

    if (p.length < 6) {
        m.textContent = "Use a password of at least 6 characters.";
        m.classList.add("bad");
        return;
    }

    m.textContent = "Encrypting…";

    try {

        const payload = f
            ? packFile(f.name, new Uint8Array(await f.arrayBuffer()))
            : packText(t);

        const c = await encryptBytes(payload, p);

        lastCipher = c;

        lastName = (f ? f.name : "message") + ".vault.txt";

        $("cipherOut").textContent = c.length > 700
            ? c.slice(0, 700) + "…\n(" + fmt(c.length) + " of encrypted text in total)"
            : c;

        $("encOut").style.display = "block";

        $("cipherIn").value = c;

        $("pwD").value = "";

        $("decOut").style.display = "none";

        $("decMsg").textContent = "";

        m.textContent = (f ? "File" : "Message") +
            " encrypted. Save it, copy it, or open the Decrypt tab where it is already loaded.";

        m.classList.add("ok");

    } catch (e) {

        m.textContent = "Encryption failed. Your browser may not support secure encryption here.";

        m.classList.add("bad");

    }
};


$("saveEnc").onclick = async () => {

    const m = $("encMsg");

    try {

        await saveFile(lastName, lastCipher);

        m.className = "msg ok";

        m.textContent = "Encrypted file ready: " + lastName;

    } catch (e) {

        saveError(e, m);

    }
};


$("copyBtn").onclick = async () => {

    try {

        await navigator.clipboard.writeText(lastCipher);

        $("copyBtn").textContent = "Copied";

    } catch {

        $("copyBtn").textContent = "Copy not allowed here";

    }

    setTimeout(
        () => $("copyBtn").textContent = "Copy encrypted text",
        1800
    );
};


$("fileD").onchange = async () => {

    const f = $("fileD").files[0];

    if (!f) return;

    if (f.size > MAXB * 1.5) {

        $("decMsg").className = "msg bad";

        $("decMsg").textContent = "That file is too large.";

        return;
    }

    $("cipherIn").value = (await f.text()).trim();

    $("decMsg").className = "msg";

    $("decMsg").textContent = "Encrypted file loaded. Enter the password.";

};


$("decBtn").onclick = async () => {

    const c = $("cipherIn").value.trim();

    const p = $("pwD").value;

    const m = $("decMsg");

    m.className = "msg";

    $("decOut").style.display = "none";

    $("saveDec").hidden = true;

    recovered = null;

    if (!c || !p) {

        m.textContent = "Provide the encrypted text or file, and the password.";

        m.classList.add("bad");

        return;
    }

    m.textContent = "Decrypting…";

    try {

        const r = unpack(await decryptBytes(c, p));

        if (r.type === "text") {

            $("plainOut").textContent = r.text;

        } else {

            recovered = r;

            $("plainOut").textContent =
                "File recovered: " + r.name + " (" + fmt(r.bytes.length) + ")";

            $("saveDec").hidden = false;

        }

        $("decOut").style.display = "block";

        m.textContent = "Access granted. Password correct.";

        m.classList.add("ok");

    } catch (e) {

        m.textContent =
            "Access denied. Wrong password, or the encrypted data was changed.";

        m.classList.add("bad");

    }
};


$("saveDec").onclick = async () => {

    const m = $("decMsg");

    if (!recovered) return;

    try {

        await saveFile(recovered.name, recovered.bytes);

        m.className = "msg ok";

        m.textContent = "Decrypted file ready: " + recovered.name;

    } catch (e) {

        saveError(e, m);

    }
};