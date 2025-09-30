// public/app.js
(function () {
    // Storage keys
    const LS_CONTACTS_KEY = "p2p:contacts";
    const SS_INBOX_KEY = "p2p:inbox";
    const SS_SENT_KEY = "p2p:sent";
    const SS_CURSOR_KEY = "p2p:cursor";

    // App state
    const state = {
        ws: null,
        connected: false,
        pending: new Map(), // id -> {resolve,reject,timeout}
        cursor: 0,
        seenIds: new Set(), // to dedupe inbox messages
        contacts: []
    };

    // ---------- util: id, storage ----------
    function genId() {
        return Math.random().toString(36).slice(2) + Date.now().toString(36);
    }
    function lsGet(key, fallback) {
        try { return JSON.parse(localStorage.getItem(key)) ?? fallback; }
        catch { return fallback; }
    }
    function lsSet(key, val) {
        localStorage.setItem(key, JSON.stringify(val));
    }
    function ssGet(key, fallback) {
        try { return JSON.parse(sessionStorage.getItem(key)) ?? fallback; }
        catch { return fallback; }
    }
    function ssSet(key, val) {
        sessionStorage.setItem(key, JSON.stringify(val));
    }

    // ---------- WebSocket RPC ----------
    function rpc(action, params = {}, timeoutMs = 8000) {
        if (!state.connected) return Promise.reject(new Error("WebSocket not connected"));
        const id = genId();
        const msg = JSON.stringify({ id, action, ...params });
        state.ws.send(msg);
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                state.pending.delete(id);
                reject(new Error(`RPC ${action} timed out`));
            }, timeoutMs);
            state.pending.set(id, { resolve, reject, timeout });
        });
    }

    function connectWS() {
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        const url = `${proto}//${location.host}/ws`;
        const ws = new WebSocket(url);
        state.ws = ws;

        ws.addEventListener("open", async () => {
            state.connected = true;
            try {
                const info = await rpc("info");
                applySelf(info.data);

                // Load more messages from server since our cursor
                const list = await rpc("list", { since: state.cursor });
                const newOnes = (list.data.messages || []).filter(m => !state.seenIds.has(m.id));
                renderInbox(newOnes);
                addInboxToSession(newOnes);
                state.cursor = list.data.next ?? state.cursor;
                ssSet(SS_CURSOR_KEY, state.cursor);
            } catch (e) {
                console.error(e);
            }
        });

        ws.addEventListener("message", (ev) => {
            let data;
            try { data = JSON.parse(ev.data); } catch { return; }

            // RPC response
            if (data && data.id && state.pending.has(data.id)) {
                const p = state.pending.get(data.id);
                clearTimeout(p.timeout);
                state.pending.delete(data.id);
                if (data.ok) p.resolve(data);
                else p.reject(new Error(data.error || "unknown error"));
                return;
            }

            // Server-push
            if (data && data.event === "hello") {
                applySelf(data.data);
                return;
            }
            if (data && data.event === "message") {
                if (!state.seenIds.has(data.data.id)) {
                    appendInboxItem(data.data);
                    addInboxToSession([data.data]);
                    state.cursor += 1; // server increments by messages appended
                    ssSet(SS_CURSOR_KEY, state.cursor);
                }
                return;
            }
        });

        ws.addEventListener("close", () => {
            state.connected = false;
            for (const [id, p] of state.pending.entries()) {
                clearTimeout(p.timeout);
                p.reject(new Error("connection closed"));
            }
            state.pending.clear();
            // Backoff reconnect
            setTimeout(connectWS, 1000 + Math.random() * 1000);
        });

        ws.addEventListener("error", () => {
            try { ws.close(); } catch { }
        });
    }

    // ---------- Initial boot: load cached session + contacts ----------
    function bootFromSession() {
        const cachedInbox = ssGet(SS_INBOX_KEY, []);
        if (cachedInbox.length) {
            renderInbox(cachedInbox);
            for (const m of cachedInbox) state.seenIds.add(m.id);
        } else {
            document.getElementById("inbox").innerHTML = `<p>No messages yet.</p>`;
        }
        const cachedSent = ssGet(SS_SENT_KEY, []);
        if (cachedSent.length) renderSent(cachedSent);

        state.cursor = Number(ssGet(SS_CURSOR_KEY, 0)) || 0;

        state.contacts = lsGet(LS_CONTACTS_KEY, []);
        renderContacts();
    }

    // ---------- UI helpers ----------
    function applySelf(info) {
        if (!info) return;
        const name = info.name ?? "Peer";
        const sid = info.serverId ?? "server";
        const thumb = info.thumbprint ?? "—";
        document.getElementById("peer-name").textContent = `${name} (${sid})`;
        document.getElementById("thumb").textContent = `thumbprint: ${thumb}`;
    }

    function renderInbox(messages) {
        if (!messages || !messages.length) return;
        const root = document.getElementById("inbox");
        if (root.innerHTML.includes("No messages yet.")) root.innerHTML = "";
        const frag = document.createDocumentFragment();
        for (const m of messages) {
            state.seenIds.add(m.id);
            frag.appendChild(renderInboxItem(m));
        }
        root.appendChild(frag);
    }
    function appendInboxItem(m) {
        const root = document.getElementById("inbox");
        if (root.innerHTML.includes("No messages yet.")) root.innerHTML = "";
        state.seenIds.add(m.id);
        root.appendChild(renderInboxItem(m));
    }
    function renderInboxItem(m) {
        const div = document.createElement("div");
        div.className = "inbox-item";
        const fromDisplay = (m.fromSigPubPem || "unknown").slice(0, 40) + "...";
        const t = new Date(m.receivedAt || Date.now()).toLocaleString();
        div.innerHTML = `
      <div class="kv">
        <span class="badge">IN</span>
        <span></span>
        <span>ID</span><span>${m.id}</span>
        <span>From</span><span>${fromDisplay}</span>
        <span>Time</span><span>${t}</span>
      </div>
      <pre>${m.plaintext}</pre>
    `;
        return div;
    }

    function renderSent(items) {
        const root = document.getElementById("sentbox");
        if (!items || !items.length) {
            root.innerHTML = `<p>No sent messages yet.</p>`;
            return;
        }
        root.innerHTML = "";
        const frag = document.createDocumentFragment();
        for (const s of items) frag.appendChild(renderSentItem(s));
        root.appendChild(frag);
    }
    function appendSentItem(item) {
        const root = document.getElementById("sentbox");
        if (root.innerHTML.includes("No sent messages yet.")) root.innerHTML = "";
        root.appendChild(renderSentItem(item));
    }
    function renderSentItem(s) {
        const div = document.createElement("div");
        div.className = "sent-item";
        const t = new Date(s.time || Date.now()).toLocaleString();
        div.innerHTML = `
      <div class="kv">
        <span class="badge">OUT</span><span></span>
        <span>ID</span><span>${s.id}</span>
        <span>To</span><span>${s.to}</span>
        <span>Time</span><span>${t}</span>
      </div>
      <pre>${s.plaintext}</pre>
    `;
        return div;
    }

    // ---------- Contacts ----------
    function renderContacts() {
        const root = document.getElementById("contacts");
        root.innerHTML = "";
        if (!state.contacts.length) {
            root.innerHTML = `<p>No contacts saved yet.</p>`;
            return;
        }
        const frag = document.createDocumentFragment();
        state.contacts.forEach((c, idx) => {
            const div = document.createElement("div");
            div.className = "contact-item";
            div.innerHTML = `
        <div class="contact-head">
          <div>
            <strong>${escapeHtml(c.name || "Unnamed")}</strong>
            <div class="meta">${escapeHtml(c.url)}</div>
            <div class="meta">${c.thumbprint ? `thumb: ${c.thumbprint}` : ""}</div>
          </div>
          <div class="contact-actions">
            <button data-action="use" data-index="${idx}">Use</button>
            <button data-action="delete" data-index="${idx}">Delete</button>
          </div>
        </div>
      `;
            frag.appendChild(div);
        });
        root.appendChild(frag);
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, (ch) => (
            { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[ch]
        ));
    }

    async function addContact(name, url) {
        const normalized = (url || "").trim().replace(/\/+$/, "");
        if (!normalized) throw new Error("URL required");

        // Try to enrich with /pubkeys (CORS is allowed by the server)
        let thumbprint, remoteName;
        try {
            const r = await fetch(`${normalized}/pubkeys`);
            if (r.ok) {
                const j = await r.json();
                thumbprint = j.thumbprint;
                remoteName = j.name;
            }
        } catch { }

        const contact = {
            name: name?.trim() || remoteName || normalized,
            url: normalized,
            thumbprint: thumbprint || null,
        };

        // De-dupe by URL
        const existingIdx = state.contacts.findIndex(c => c.url === normalized);
        if (existingIdx >= 0) {
            state.contacts[existingIdx] = contact;
        } else {
            state.contacts.push(contact);
        }
        lsSet(LS_CONTACTS_KEY, state.contacts);
        renderContacts();
    }

    function deleteContact(index) {
        state.contacts.splice(index, 1);
        lsSet(LS_CONTACTS_KEY, state.contacts);
        renderContacts();
    }

    // ---------- Persistence helpers for session ----------
    function addInboxToSession(messages) {
        if (!messages || !messages.length) return;
        const current = ssGet(SS_INBOX_KEY, []);
        // Dedup by id
        const ids = new Set(current.map(m => m.id));
        const appended = [];
        for (const m of messages) {
            if (!ids.has(m.id)) {
                current.push(m);
                ids.add(m.id);
                appended.push(m);
            }
        }
        if (appended.length) ssSet(SS_INBOX_KEY, current);
    }

    function addSentToSession(item) {
        const current = ssGet(SS_SENT_KEY, []);
        current.push(item);
        ssSet(SS_SENT_KEY, current);
    }

    // ---------- Event handlers ----------
    async function onSend(e) {
        e.preventDefault();
        const out = document.getElementById("send-status");
        out.className = "";
        out.textContent = "Sending…";
        try {
            const recipientBaseUrl = document.getElementById("recipient").value.trim();
            const plaintextUtf8 = document.getElementById("message").value;
            const resp = await rpc("send", { recipientBaseUrl, plaintextUtf8 });
            out.className = "ok";
            out.textContent = "Sent ✔︎";
            document.getElementById("message").value = "";

            // Store ephemeral "sent"
            const sentItem = {
                id: resp?.data?.result?.receipt || genId(),
                to: recipientBaseUrl,
                plaintext: plaintextUtf8,
                time: Date.now(),
            };
            appendSentItem(sentItem);
            addSentToSession(sentItem);

            // Optional UX: suggest saving contact if not already present
            if (!state.contacts.some(c => c.url === recipientBaseUrl)) {
                document.getElementById("contact-url").value = recipientBaseUrl;
                document.getElementById("contact-name").focus();
            }
        } catch (err) {
            out.className = "err";
            out.textContent = `Error: ${err.message || err}`;
        }
    }

    async function onRefresh() {
        try {
            const list = await rpc("list", { since: state.cursor });
            const newOnes = (list.data.messages || []).filter(m => !state.seenIds.has(m.id));
            renderInbox(newOnes);
            addInboxToSession(newOnes);
            state.cursor = list.data.next ?? state.cursor;
            ssSet(SS_CURSOR_KEY, state.cursor);
        } catch (e) {
            console.error(e);
        }
    }

    function onContactForm(e) {
        e.preventDefault();
        const name = document.getElementById("contact-name").value;
        const url = document.getElementById("contact-url").value;
        addContact(name, url).catch(err => alert(err.message || err));
        // keep values so users can tweak; clear if you prefer:
        // document.getElementById("contact-name").value = "";
        // document.getElementById("contact-url").value = "";
    }

    function onContactsClick(e) {
        const btn = e.target.closest("button[data-action]");
        if (!btn) return;
        const idx = Number(btn.dataset.index);
        if (btn.dataset.action === "use") {
            const c = state.contacts[idx];
            if (c) document.getElementById("recipient").value = c.url;
        } else if (btn.dataset.action === "delete") {
            deleteContact(idx);
        }
    }

    // ---------- Boot ----------
    document.addEventListener("DOMContentLoaded", () => {
        bootFromSession();      // render cached Inbox/Sent + Contacts
        connectWS();            // start live connection

        // Wire up UI
        document.getElementById("send-form").addEventListener("submit", onSend);
        document.getElementById("refresh").addEventListener("click", onRefresh);
        document.getElementById("contact-form").addEventListener("submit", onContactForm);
        document.getElementById("contacts").addEventListener("click", onContactsClick);

        // Small QoL: sync "contact-url" with current recipient value on focus
        const recip = document.getElementById("recipient");
        const cUrl = document.getElementById("contact-url");
        cUrl.addEventListener("focus", () => { if (!cUrl.value) cUrl.value = recip.value; });
    });
})();
