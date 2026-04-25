(function(){
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const qs = (s, root=document) => root.querySelector(s);
  const qsa = (s, root=document) => Array.from(root.querySelectorAll(s));
  const API_BASE = "/api";
  let authToken = localStorage.getItem("chatapp_token") || "";
  let sse = null;
  let heartbeat = null;
  let booted = false;

  function injectStyles(){
    if (document.getElementById("auth-gate-style")) return;
    const style = document.createElement("style");
    style.id = "auth-gate-style";
    style.textContent = `
      #auth-gate{position:fixed;inset:0;z-index:9999;background:var(--bg);color:var(--text);display:none;align-items:stretch;justify-content:center;overflow:auto}
      #auth-gate.active{display:flex}
      #auth-gate .ag-shell{width:min(100%,480px);margin:auto;min-height:100%;display:flex;flex-direction:column}
      #auth-gate .ag-hero{padding:34px 20px 18px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,var(--bg2),var(--bg))}
      #auth-gate .ag-hero h1{font-size:28px;line-height:1.05;margin-bottom:8px}
      #auth-gate .ag-hero p{color:var(--text2);font-size:14px;line-height:1.5}
      #auth-gate .ag-body{padding:18px 20px 28px;display:grid;gap:12px}
      #auth-gate .ag-tabs{display:flex;gap:8px;flex-wrap:wrap}
      #auth-gate .ag-tab{padding:10px 14px;border-radius:999px;background:var(--bg3);color:var(--text2);font-weight:700;font-size:13px}
      #auth-gate .ag-tab.active{background:var(--accent);color:#fff}
      #auth-gate .ag-card{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:16px;display:grid;gap:12px;box-shadow:var(--shadow)}
      #auth-gate input{width:100%;background:var(--bg3);border:1px solid transparent;border-radius:14px;padding:13px 14px;font-size:15px}
      #auth-gate input:focus{border-color:var(--accent)}
      #auth-gate .ag-grid{display:grid;gap:10px}
      #auth-gate button{border:none;border-radius:14px;padding:13px 14px;font-weight:800;font-size:15px}
      #auth-gate .ag-primary{background:var(--accent);color:#fff}
      #auth-gate .ag-secondary{background:var(--bg3);color:var(--text)}
      #auth-gate .ag-muted{background:transparent;color:var(--text2);padding:4px 0}
      #auth-gate .ag-note{font-size:12px;color:var(--text3);line-height:1.5}
      #auth-gate .ag-row{display:flex;gap:10px;align-items:center}
      #auth-gate .ag-otp{letter-spacing:0.32em;font-size:18px;text-align:center}
      #auth-gate .ag-error{color:#ef4444;font-size:13px;min-height:18px}
      #auth-gate .ag-success{color:#22c55e;font-size:13px;min-height:18px}
    `;
    document.head.appendChild(style);
  }

  function ensureGate(){
    if (document.getElementById("auth-gate")) return;
    const gate = document.createElement("div");
    gate.id = "auth-gate";
    gate.innerHTML = `
      <div class="ag-shell">
        <div class="ag-hero">
          <h1>Masuk dulu</h1>
          <p>Login pakai email + OTP. Setelah masuk, profil, chat, status, dan blokir langsung sinkron ke server.</p>
        </div>
        <div class="ag-body">
          <div class="ag-tabs">
            <button class="ag-tab active" data-tab="login">Sign in</button>
            <button class="ag-tab" data-tab="signup">Sign up</button>
            <button class="ag-tab" data-tab="reset">Lupa password</button>
          </div>
          <div class="ag-card" id="ag-view-login">
            <div class="ag-grid">
              <input id="login-email" type="email" placeholder="Email asli">
              <input id="login-password" type="password" placeholder="Password">
              <button class="ag-primary" id="btn-login-req">Kirim OTP login</button>
              <input id="login-otp" class="ag-otp" inputmode="numeric" maxlength="6" placeholder="Masukkan OTP">
              <button class="ag-primary" id="btn-login-verify">Verifikasi & masuk</button>
            </div>
            <div class="ag-note">OTP yang dikirim akan disertai pesan: “Jangan sebar kode ini pada siapapun.”</div>
            <div class="ag-error" id="login-msg"></div>
          </div>
          <div class="ag-card" id="ag-view-signup" style="display:none">
            <div class="ag-grid">
              <input id="signup-name" type="text" placeholder="Nama akun">
              <input id="signup-email" type="email" placeholder="Email asli">
              <input id="signup-password" type="password" placeholder="Password">
              <button class="ag-primary" id="btn-signup-req">Kirim OTP daftar</button>
              <input id="signup-otp" class="ag-otp" inputmode="numeric" maxlength="6" placeholder="Masukkan OTP">
              <button class="ag-primary" id="btn-signup-verify">Verifikasi & daftar</button>
            </div>
            <div class="ag-note">Akun baru otomatis dapat nomor kontak 6 digit random dan tersimpan ke database.</div>
            <div class="ag-error" id="signup-msg"></div>
          </div>
          <div class="ag-card" id="ag-view-reset" style="display:none">
            <div class="ag-grid">
              <input id="reset-email" type="email" placeholder="Email akun">
              <button class="ag-primary" id="btn-reset-req">Kirim OTP reset</button>
              <input id="reset-otp" class="ag-otp" inputmode="numeric" maxlength="6" placeholder="OTP reset">
              <input id="reset-password" type="password" placeholder="Password baru">
              <button class="ag-primary" id="btn-reset-verify">Reset password</button>
            </div>
            <div class="ag-error" id="reset-msg"></div>
          </div>
          <button class="ag-muted" id="ag-dev-fill">Isi demo</button>
          <div class="ag-success" id="ag-status"></div>
        </div>
      </div>
    `;
    document.body.appendChild(gate);
  }

  function setGateVisible(v){
    const gate = document.getElementById("auth-gate");
    const app = document.getElementById("app");
    if (gate) gate.classList.toggle("active", v);
    if (app) app.style.display = v ? "none" : "flex";
  }

  function setMsg(id, text, ok=false){
    const el = document.getElementById(id);
    if (!el) return;
    el.className = ok ? "ag-success" : "ag-error";
    el.textContent = text || "";
  }

  async function request(path, body=null, method="POST"){
    const headers = {"Content-Type":"application/json"};
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    const res = await fetch(API_BASE + path, {method, headers, body: body ? JSON.stringify(body) : undefined, credentials:"include"});
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function attachAuthUI(){
    qsa("[data-tab]").forEach(btn => btn.addEventListener("click", () => {
      qsa("[data-tab]").forEach(x => x.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      ["login","signup","reset"].forEach(name => {
        const view = document.getElementById(`ag-view-${name}`);
        if (view) view.style.display = name === tab ? "grid" : "none";
      });
    }));

    document.getElementById("ag-dev-fill")?.addEventListener("click", () => {
      document.getElementById("login-email").value = "demo1@example.com";
      document.getElementById("login-password").value = "Demo Satu";
      document.getElementById("signup-name").value = "Akun Baru";
      document.getElementById("signup-email").value = "new@example.com";
      document.getElementById("signup-password").value = "password123";
      document.getElementById("reset-email").value = "demo1@example.com";
    });

    document.getElementById("btn-login-req")?.addEventListener("click", async () => {
      try {
        setMsg("login-msg", "");
        await request("/auth/request-login-otp", {email: loginEmail(), password: loginPassword()});
        setMsg("login-msg", "OTP login dikirim. Cek inbox/dev log.", true);
      } catch (e) { setMsg("login-msg", e.message); }
    });
    document.getElementById("btn-login-verify")?.addEventListener("click", async () => {
      try {
        const data = await request("/auth/verify-login-otp", {email: loginEmail(), code: document.getElementById("login-otp").value.trim()});
        authToken = data.token; localStorage.setItem("chatapp_token", authToken);
        await finishAuth(data.user);
      } catch (e) { setMsg("login-msg", e.message); }
    });
    document.getElementById("btn-signup-req")?.addEventListener("click", async () => {
      try {
        setMsg("signup-msg", "");
        await request("/auth/request-signup-otp", {email: signupEmail(), password: signupPassword(), name: signupName()});
        setMsg("signup-msg", "OTP daftar dikirim.", true);
      } catch (e) { setMsg("signup-msg", e.message); }
    });
    document.getElementById("btn-signup-verify")?.addEventListener("click", async () => {
      try {
        const data = await request("/auth/verify-signup-otp", {email: signupEmail(), code: document.getElementById("signup-otp").value.trim()});
        authToken = data.token; localStorage.setItem("chatapp_token", authToken);
        await finishAuth(data.user);
      } catch (e) { setMsg("signup-msg", e.message); }
    });
    document.getElementById("btn-reset-req")?.addEventListener("click", async () => {
      try {
        await request("/auth/request-reset-otp", {email: resetEmail()});
        setMsg("reset-msg", "OTP reset dikirim.", true);
      } catch (e) { setMsg("reset-msg", e.message); }
    });
    document.getElementById("btn-reset-verify")?.addEventListener("click", async () => {
      try {
        await request("/auth/reset-password", {email: resetEmail(), code: document.getElementById("reset-otp").value.trim(), newPassword: document.getElementById("reset-password").value});
        setMsg("reset-msg", "Password berhasil direset.", true);
      } catch (e) { setMsg("reset-msg", e.message); }
    });
  }

  const loginEmail = () => document.getElementById("login-email")?.value.trim().toLowerCase() || "";
  const loginPassword = () => document.getElementById("login-password")?.value || "";
  const signupName = () => document.getElementById("signup-name")?.value.trim() || "";
  const signupEmail = () => document.getElementById("signup-email")?.value.trim().toLowerCase() || "";
  const signupPassword = () => document.getElementById("signup-password")?.value || "";
  const resetEmail = () => document.getElementById("reset-email")?.value.trim().toLowerCase() || "";

  function patchStateFromServer(data){
    if (!window.State) return;
    State.me = { ...State.me, ...(data.me || {}), autoDownload: State.me?.autoDownload || { image:true, video:false, document:false, voice:true } };
    State.contacts = data.contacts || [];
    State.chats = data.chats || {};
    State.statuses = data.statuses || [];
    State.save?.();
  }

  function niceTime(ts){
    if (!ts) return "";
    try { return new Intl.DateTimeFormat("id-ID", {hour:"2-digit", minute:"2-digit"}).format(new Date(ts * 1000)); } catch { return ""; }
  }

  async function finishAuth(user){
    document.getElementById("ag-status").textContent = `Login sebagai ${user?.name || "user"}`;
    setGateVisible(false);
    const boot = await request("/bootstrap", null, "GET");
    patchStateFromServer(boot);
    startApp();
    openRealtime();
    pingPresence(true);
    window.dispatchEvent(new Event("chatapp:authenticated"));
  }

  function showGate(){
    setGateVisible(true);
  }

  function statusText(contact){
    if (!contact) return "";
    if (contact.online) return "online";
    return contact.lastSeenText || "offline";
  }

  function msgTick(status){
    if (status === "read") return '<span class="msg-tick" style="color:#ff8c52">✓✓</span>';
    if (status === "delivered") return '<span class="msg-tick" style="color:#a0a0a0">✓✓</span>';
    return '<span class="msg-tick" style="color:#a0a0a0">✓</span>';
  }

  async function renderChatFromServer(contactId){
    const data = await request(`/messages?chatId=${encodeURIComponent(contactId)}`, null, "GET");
    State.chats[contactId] = State.chats[contactId] || { unread:0, lastMsg:"", lastTime:"", messages:[] };
    State.chats[contactId].messages = data.messages || [];
    if (window.ChatRoom?.currentChat === contactId) {
      ChatRoom.renderMessages?.();
    }
  }

  function patchApp(){
    if (booted || !window.State || !window.ChatRoom || !window.Home || !window.Settings || !window.StatusEditor || !window.ProfileEdit || !window.Notifications) return;
    booted = true;

    if (window.Nav?.go) {
      const oldGo = Nav.go.bind(Nav);
      Nav.go = function(tab){
        oldGo(tab);
      };
    }

    if (window.Settings) {
      const oldRender = Settings.render?.bind(Settings);
      Settings.render = function(){ oldRender?.(); const el = document.getElementById("settings-content"); if (!el) return; const me = State.me || {}; const row = document.createElement("div"); row.style.padding = "0 16px 16px"; row.innerHTML = `<div class="settings-section-title">Akun</div><div class="settings-item"><div class="settings-icon">#</div><div class="settings-item-info"><h4>Nomor akun</h4><p>${me.phone || ""}</p></div></div><div class="settings-item"><div class="settings-icon">🟢</div><div class="settings-item-info"><h4>Status</h4><p>${me.online ? "Online" : "Offline"}</p></div></div>`; el.appendChild(row); };
    }

    ChatRoom.sendText = async function(){
      const input = document.getElementById("msg-input");
      const text = input?.value?.trim?.() || "";
      if (!text || !this.currentChat) return;
      const contactId = this.currentChat;
      const now = new Date().toLocaleTimeString("id-ID", {hour:"2-digit", minute:"2-digit"});
      const optimistic = { id:"tmp_"+Date.now(), from:"me", type:"text", content:text, time:now, status:"sent" };
      this.addMessage?.(optimistic);
      if (input){ input.value=""; input.style.height="auto"; }
      try {
        const data = await request("/messages/text", {chatId: contactId, text});
        const msg = data.message;
        const chat = State.chats[contactId] || {messages:[]};
        chat.messages = (chat.messages || []).filter(m => m.id !== optimistic.id).concat([msg]);
        State.chats[contactId] = chat;
        Home.render?.();
        this.renderMessages?.();
      } catch(e){
        optimistic.status = "sent";
        if (window.UI?.showToast) UI.showToast(e.message);
      }
      this.focusInput?.();
    };

    ChatRoom.addMessage = function(msg){
      if (!State.chats[this.currentChat]) State.chats[this.currentChat] = { unread:0, lastMsg:"", lastTime:"", messages:[] };
      State.chats[this.currentChat].messages.push(msg);
      State.save?.();
      this.renderMessages?.();
    };

    ChatRoom.addMediaMessage = function(type, src, caption="", extra={}){
      const msg = { id:"tmp_"+Date.now(), from:"me", type, src, caption, time:new Date().toLocaleTimeString("id-ID", {hour:"2-digit", minute:"2-digit"}), status:"sent", ...extra };
      if (!State.chats[this.currentChat]) State.chats[this.currentChat] = { unread:0, lastMsg:"", lastTime:"", messages:[] };
      State.chats[this.currentChat].messages.push(msg);
      State.save?.();
      this.renderMessages?.();
    };

    ChatRoom.addAudioMessage = function(url, duration){
      this.addMediaMessage?.("audio", url, "", {duration});
    };

    ChatRoom.renderMessages = function(){
      const area = document.getElementById("chat-area");
      const chat = State.chats[this.currentChat] || {messages:[]};
      const msgs = chat.messages || [];
      area.innerHTML = "";
      if (!msgs.length) { area.innerHTML = '<div style="text-align:center;color:var(--text3);margin-top:40px;font-size:14px">Tidak ada pesan. Mulai percakapan! 👋</div>'; return; }
      let lastDay = "";
      msgs.forEach(msg => {
        const wrap = document.createElement("div");
        wrap.className = "msg " + (msg.from === "me" ? "out" : "in");
        const isOut = msg.from === "me";
        const tick = isOut ? msgTick(msg.status) : "";
        const safe = String(msg.content || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
        if (msg.type === "text") {
          wrap.innerHTML = `<div class="bubble">${safe}</div><div class="msg-time">${msg.time || ""}${tick}</div>`;
        } else if (msg.type === "image") {
          wrap.innerHTML = `<div class="media-bubble"><img src="${msg.src || ""}" alt=""></div>${msg.caption ? `<div class="media-caption">${safe}</div>` : ""}<div class="msg-time">${msg.time || ""}${tick}</div>`;
        } else if (msg.type === "video") {
          wrap.innerHTML = `<div class="media-bubble"><video src="${msg.src || ""}"></video></div>${msg.caption ? `<div class="media-caption">${safe}</div>` : ""}<div class="msg-time">${msg.time || ""}${tick}</div>`;
        } else if (msg.type === "audio") {
          wrap.innerHTML = `<div class="audio-bubble"><button class="audio-play-btn" onclick="VoiceNote.play('${msg.src || ""}')">▶</button><div class="audio-waveform"><span style="height:10px"></span><span style="height:18px"></span><span style="height:12px"></span><span style="height:20px"></span></div><div class="audio-dur">${msg.duration || "0:00"}</div></div><div class="msg-time">${msg.time || ""}${tick}</div>`;
        } else if (msg.type === "document") {
          wrap.innerHTML = `<div class="bubble">📎 ${safe}</div><div class="msg-time">${msg.time || ""}${tick}</div>`;
        }
        area.appendChild(wrap);
      });
      area.scrollTop = area.scrollHeight;
    };

    ChatRoom.open = function(contactId){
      const c = State.contacts.find(x => x.id === contactId);
      this.currentChat = contactId;
      document.getElementById("chatroom-name").textContent = c?.name || "Chat";
      document.getElementById("chatroom-status").textContent = statusText(c);
      const avatarHost = document.getElementById("chatroom-avatar");
      if (avatarHost) avatarHost.innerHTML = c?.avatar ? `<img src="${c.avatar}" alt="">` : (c?.avatarLetter || "?");
      document.getElementById("page-home")?.classList.add("hidden");
      document.getElementById("page-chatroom")?.classList.remove("hidden");
      document.getElementById("bottom-nav")?.classList.add("hidden");
      renderChatFromServer(contactId).then(() => {
        this.renderMessages?.();
        request("/messages/read", {chatId: contactId});
      });
    };

    ChatRoom.back = function(){
      document.getElementById("page-chatroom")?.classList.add("hidden");
      document.getElementById("bottom-nav")?.classList.remove("hidden");
      document.getElementById("page-home")?.classList.remove("hidden");
      this.currentChat = null;
    };

    const oldHomeRender = Home.render?.bind(Home);
    Home.render = function(){
      oldHomeRender?.();
      qsa('.chat-item').forEach(el => {
        const txt = el.querySelector('.chat-preview');
        if (txt && txt.textContent.trim() === '') txt.textContent = 'Belum ada pesan';
      });
    };

    const oldStatusRender = Status.render?.bind(Status);
    if (window.Status) {
      Status.render = function(){ oldStatusRender?.(); };
    }

    StatusEditor.postPhoto = async function(){
      const caption = document.getElementById('se-caption-input')?.value || '';
      const dataUrl = this.canvas?.toDataURL?.('image/jpeg', 0.9) || this.img?.src || '';
      await request('/status/photo', {mediaUrl: dataUrl, caption});
      if (window.UI?.showToast) UI.showToast('Status foto terkirim');
      this.close?.();
    };
    const oldOpenVideo = StatusEditor.openVideo?.bind(StatusEditor);
    StatusEditor.openVideo = function(input){
      const file = input.files?.[0];
      if (!file) return oldOpenVideo?.(input);
      const reader = new FileReader();
      reader.onload = e => { this.videoDataUrl = String(e.target.result || ''); };
      reader.readAsDataURL(file);
      return oldOpenVideo?.(input);
    };
    StatusEditor.postVideo = async function(){
      const caption = document.getElementById('se-caption-input')?.value || '';
      await request('/status/video', {mediaUrl: this.videoDataUrl || '', caption});
      if (window.UI?.showToast) UI.showToast('Status video terkirim');
      this.close?.();
    };

    ProfileEdit.save = async function(){
      const name = document.getElementById('edit-name-input')?.value.trim() || '';
      const bio = document.getElementById('edit-bio-input')?.value.trim() || '';
      const avatar = this.canvas?.toDataURL?.('image/jpeg', 0.85) || State.me?.avatar || '';
      const res = await request('/profile', {name, bio, avatar, theme: State.me?.theme || 'dark'});
      State.me = { ...State.me, ...(res.profile || {}) };
      State.save?.();
      Settings.render?.();
      if (window.UI?.showToast) UI.showToast('Profil disimpan');
      this.close?.();
    };

    const oldNotifPush = Notifications.push?.bind(Notifications);
    Notifications.push = function(item){ oldNotifPush?.(item); };

    if (window.Profile) {
      Profile.toggleBlock = async function(){
        if (!this.current) return;
        const c = State.contacts.find(x => x.id === this.current);
        const blocked = !c?.blocked;
        await request('/block', {userId: this.current, blocked});
        if (c) c.blocked = blocked;
        if (window.UI?.showToast) UI.showToast(blocked ? 'Kontak diblokir' : 'Blokir dibuka');
      };
      Profile.toggleBlockFromMenu = Profile.toggleBlock;
    }

    if (window.Calls) {
      Calls.initVoice = async function(){
        if (!ChatRoom.currentChat) return;
        await request('/calls/start', {userId: ChatRoom.currentChat, kind: 'voice'});
        UI?.showToast?.('Panggilan suara dimulai');
      };
      Calls.initVideo = async function(){
        if (!ChatRoom.currentChat) return;
        await request('/calls/start', {userId: ChatRoom.currentChat, kind: 'video'});
        UI?.showToast?.('Panggilan video dimulai');
      };
    }

    if (window.Nav?.go) {
      const oldGo2 = Nav.go.bind(Nav);
      Nav.go = function(tab){ oldGo2(tab); if (tab !== 'home') request('/presence', {online: true}).catch(()=>{}); };
    }

    if (window.Settings?.render) Settings.render();
    if (window.Home?.render) Home.render();
    if (window.Status?.render) Status.render();
  }


    Media.handleImageFile = function(input){
      const file = input.files?.[0]; if (!file) return; input.value = '';
      const reader = new FileReader();
      reader.onload = async e => {
        const dataUrl = String(e.target.result || '');
        const chatId = ChatRoom.currentChat;
        if (!chatId) return;
        ChatRoom.addMediaMessage?.('image', dataUrl, '', {name: file.name, size: String(file.size)});
        try { await request('/messages/media', {chatId, type:'image', mediaUrl:dataUrl, name:file.name, size:String(file.size)}); } catch (err) { UI?.showToast?.(err.message); }
      };
      reader.readAsDataURL(file);
    };

    Media.handleVideoFile = function(input){
      const file = input.files?.[0]; if (!file) return; input.value = '';
      const reader = new FileReader();
      reader.onload = async e => {
        const dataUrl = String(e.target.result || '');
        const chatId = ChatRoom.currentChat;
        if (!chatId) return;
        ChatRoom.addMediaMessage?.('video', dataUrl, '', {name: file.name, size: String(file.size)});
        try { await request('/messages/media', {chatId, type:'video', mediaUrl:dataUrl, name:file.name, size:String(file.size)}); } catch (err) { UI?.showToast?.(err.message); }
      };
      reader.readAsDataURL(file);
    };

    Media.handleDocFile = function(input){
      const file = input.files?.[0]; if (!file) return; input.value = '';
      const reader = new FileReader();
      reader.onload = async e => {
        const dataUrl = String(e.target.result || '');
        const chatId = ChatRoom.currentChat;
        if (!chatId) return;
        const size = file.size > 1e6 ? (file.size/1e6).toFixed(1)+' MB' : (file.size/1e3).toFixed(0)+' KB';
        ChatRoom.addMediaMessage?.('document', dataUrl, '', {name:file.name, size});
        try { await request('/messages/media', {chatId, type:'document', mediaUrl:dataUrl, name:file.name, size}); } catch (err) { UI?.showToast?.(err.message); }
      };
      reader.readAsDataURL(file);
    };

  function openRealtime(){
    if (sse) try { sse.close(); } catch {}
    try {
      sse = new EventSource(API_BASE + '/events', { withCredentials: true });
      sse.onmessage = (ev) => {
        try {
          const payload = JSON.parse(ev.data || '{}');
          const { type, payload: data } = payload;
          if (type === 'presence' && data?.userId) {
            const c = State.contacts.find(x => x.id === data.userId);
            if (c) {
              c.online = !!data.online;
              c.lastSeen = data.lastSeen || c.lastSeen;
              c.lastSeenText = data.lastSeen ? `terakhir terlihat ${new Date(data.lastSeen * 1000).toLocaleTimeString('id-ID', {hour:'2-digit', minute:'2-digit'})}` : c.lastSeenText;
              Home.render?.();
              if (ChatRoom.currentChat === c.id) {
                document.getElementById('chatroom-status').textContent = statusText(c);
              }
            }
          }
          if (type === 'message' && data?.chatId && data?.message) {
            const chat = State.chats[data.chatId] || { unread:0, lastMsg:'', lastTime:'', messages:[] };
            const exists = (chat.messages || []).some(m => m.id === data.message.id);
            if (!exists) {
              chat.messages = chat.messages || [];
              chat.messages.push(data.message);
              State.chats[data.chatId] = chat;
              if (ChatRoom.currentChat === data.chatId) ChatRoom.renderMessages?.();
              Home.render?.();
              Notifications.push?.({ contactId: data.chatId, name: (State.contacts.find(x => x.id === data.chatId)?.name || 'Kontak'), text: data.message.type === 'text' ? data.message.content : 'Pesan baru' });
            }
          }
          if (type === 'status') {
            if (data?.status) {
              State.statuses = [data.status, ...(State.statuses || [])].slice(0, 50);
              Status.render?.();
            }
          }
          if (type === 'notification') {
            Notifications.push?.({ contactId: data.fromUserId || '', name: 'Notifikasi', text: data.text || '' });
          }
        } catch {}
      };
    } catch (e) {}
    clearInterval(heartbeat);
    heartbeat = setInterval(() => pingPresence(true), 20_000);
  }

  async function pingPresence(online){
    if (!authToken) return;
    try { await request('/presence', {online}); } catch {}
  }

  async function bootstrap(){
    injectStyles();
    ensureGate();
    attachAuthUI();
    if (!authToken) {
      showGate();
      return;
    }
    try {
      const me = await request('/auth/me', null, 'GET');
      if (!me.authenticated) throw new Error('noauth');
      const boot = await request('/bootstrap', null, 'GET');
      patchStateFromServer(boot);
      setGateVisible(false);
      startApp();
      openRealtime();
      pingPresence(true);
    } catch (e) {
      authToken = ''; localStorage.removeItem('chatapp_token');
      showGate();
    }
  }

  function startApp(){
    if (window.Settings?.render) Settings.render();
    if (window.Home?.render) Home.render();
    if (window.Status?.render) Status.render();
    document.getElementById('app')?.style && (document.getElementById('app').style.display = 'flex');
    qsa('.chat-item').forEach(el => el.addEventListener('click', () => {}));
    if (State?.me?.theme) document.documentElement.setAttribute('data-theme', State.me.theme);
    if (document.getElementById('page-chatroom')) document.getElementById('page-chatroom').classList.add('hidden');
  }

  async function waitForApp(){
    for (let i=0;i<120;i++){
      if (window.State && window.Home && window.ChatRoom && window.Settings && window.StatusEditor) break;
      await sleep(50);
    }
    bootstrap();
    const check = setInterval(() => {
      patchApp();
      if (booted) clearInterval(check);
    }, 80);
  }

  window.addEventListener('beforeunload', () => { if (authToken) navigator.sendBeacon?.(API_BASE + '/presence', new Blob([JSON.stringify({online:false})], {type:'application/json'})); });
  waitForApp();
})();
