/* =============================================================================
   QGuard Messaging promo — device UI builders
   Vector rebuilds of the real app surfaces, returned as HTML strings so the
   three desktop scenes and the two phone scenes share one shell. Every label
   is the app's own (see the source files named in css/qg-desktop.css and
   css/qg-phone.css). Each builder takes an id prefix so ids stay unique on the
   assembled page; scenes animate the hooks listed in the comments.
   ========================================================================== */
(function () {
  "use strict";
  var QG = window.QG;
  var ic = QG.icon;

  function av(initials, tone, size) {
    return (
      '<span class="dw-av ' + tone + '" style="width:' + size + "px;height:" + size + "px;font-size:" +
      Math.round(size * 0.34) + 'px">' + initials + "</span>"
    );
  }

  var NAV = [
    ["dashboard", "dashboard", "Dashboard"],
    ["chat", "chat", "Secure Chat"],
    ["vault", "vault", "Quantum Vault"],
    ["keys", "key", "Key Management"],
    ["devices", "devices", "Device Trust Center"],
    ["verification", "qr", "Security Verification"],
    ["audit", "activity", "Message Audit Logs"],
    ["quantum", "gauge", "Quantum Security"],
    ["subscription", "card", "Subscription"],
    ["settings", "settings", "Settings"],
  ];

  var TITLES = {
    chat: ["Secure Chat", "Hybrid encrypted messaging, voice notes, and file references."],
    vault: ["Quantum Vault", "Local-first encrypted files with signed metadata and hybrid grants."],
  };

  function titleBar() {
    return (
      '<div class="dw-title"><img class="dw-title-ico" src="assets/img/logo.png" alt="" /><span>QGuard Messaging</span>' +
      '<span class="dw-ctl"><span><svg viewBox="0 0 12 12"><path d="M1 6.5h10"/></svg></span>' +
      '<span><svg viewBox="0 0 12 12"><rect x="1.5" y="1.5" width="9" height="9"/></svg></span>' +
      '<span><svg viewBox="0 0 12 12"><path d="M1.5 1.5l9 9M10.5 1.5l-9 9"/></svg></span></span></div>'
    );
  }

  /* Desktop shell. opts.page: "chat" | "vault". opts.content: page HTML. */
  function desktop(p, opts) {
    var t = TITLES[opts.page];
    var nav = "";
    for (var i = 0; i < NAV.length; i++) {
      var on = NAV[i][0] === opts.page;
      nav +=
        '<div class="dw-nav-item' + (on ? " is-on" : "") + '">' + ic(NAV[i][1], 19) + "<span>" + NAV[i][2] + "</span>" +
        (NAV[i][0] === "chat" && opts.unread ? '<span class="dw-badge">' + opts.unread + "</span>" : "") + "</div>";
    }
    return (
      '<div class="dw" id="' + p + '-dw">' + titleBar() +
      '<div class="dw-app"><aside class="dw-side">' +
      '<div class="dw-brand"><span class="dw-brand-tile"><img src="assets/img/logo.png" alt="" /></span><span><b>QGUARD</b><i>Quantum Messaging</i></span></div>' +
      '<nav class="dw-nav">' + nav + "</nav>" +
      '<div class="dw-sec"><div class="dw-sec-h">' + ic("shield", 17) + 'Protected</div><div class="dw-sec-b">PQC: Hybrid Active - HNDL: Enabled</div></div>' +
      '<div class="dw-about"><span class="dw-about-ico">' + ic("info", 16) + "</span><span><b>About QGuard</b><i>Version 1.3.9</i></span></div>" +
      "</aside>" +
      '<main class="dw-main"><header class="dw-top"><div><h1>' + t[0] + "</h1><p>" + t[1] + "</p></div>" +
      '<div class="dw-top-r"><span class="dw-search">' + ic("search", 17) + "Search secure workspace</span>" +
      '<span class="dw-pill is-emerald">live</span>' +
      '<span class="dw-ib">' + ic("bell", 18) + '</span><span class="dw-ib">' + ic("help", 18) + "</span>" +
      '<span class="dw-ib">' + ic("moon", 18) + '</span><span class="dw-ib">' + ic("logout", 18) + "</span>" +
      av("AQ", "a4", 40) + "</div></header>" +
      '<div class="dw-page">' + opts.content + "</div></main></div></div>"
    );
  }

  /* The thread pane on its own.
     Hooks: #p-in (incoming message row) · #p-out (outgoing message row)
            #p-typed (composer text) · #p-caret · #p-send
            #p-optrow (message options row) · #p-optsum (options summary chip) */
  function chatThread(p) {
    return (
      '<section class="dw-card ch-thread"><div class="ch-th-h"><div style="display:flex;align-items:center;gap:12px">' + av("JR", "a1", 40) +
      '<div><h2>Jordan Reyes</h2><div class="ch-e2ee">' + ic("shield", 14) + "E2EE active - ML-KEM-1024 - Forward secrecy</div></div></div>" +
      '<div style="display:flex;align-items:center;gap:8px"><span class="dw-ib">' + ic("video", 18) + '</span><span class="dw-pill is-emerald">Ready</span></div></div>' +
      '<div class="ch-view"><div class="ch-note">Private messages are sealed locally for each trusted recipient device.</div>' +
      '<div class="ch-channel">Private channel with Jordan Reyes</div>' +
      '<div class="ch-msg" id="' + p + '-in">' + av("JR", "a1", 32) + '<div class="ch-bub">Is the board pack ready to send?<div class="ch-meta"><span>09:40</span><span>Verified</span><span>Replay-safe</span></div></div></div>' +
      '<div class="ch-msg is-mine" id="' + p + '-out"><div class="ch-bub">Sending it now. Sealed end to end.<div class="ch-meta"><span>09:41</span><span>Verified</span><span>Replay-safe</span></div></div></div>' +
      "</div>" +
      '<div class="ch-comp"><div class="ch-opts">' + ic("chevron", 14) + '<span>Message options</span><span class="dw-pill is-violet" id="' + p + '-optsum" style="height:20px;font-size:11px">Read once · Disappears 1h</span></div>' +
      '<div class="ch-opt-row" id="' + p + '-optrow"><span class="ch-opt is-on">' + ic("eyeoff", 14) + 'Read once</span><span class="ch-opt">' + ic("timer", 14) + 'View once</span><span class="ch-opt is-on">Disappear 1h' + ic("chevron", 13) + '</span><span class="ch-opt">' + ic("clock", 14) + "Time-lock</span></div>" +
      '<div class="ch-input-row"><span class="dw-ib">' + ic("paperclip", 18) + '</span><span class="dw-ib">' + ic("mic", 18) + "</span>" +
      '<span class="ch-input"><span id="' + p + '-typed"></span><i class="ch-caret" id="' + p + '-caret"></i></span>' +
      '<span class="dw-btn" id="' + p + '-send" style="height:40px;padding:0 16px;font-size:14px">' + ic("send", 17) + "Send</span></div></div></section>"
    );
  }

  /* Secure Chat page: conversations · thread · contacts. */
  function chatPage(p) {
    var convs = [
      ["JR", "a1", "Jordan Reyes", "Encrypted message", true],
      ["SD", "a2", "Security Desk", "Encrypted file", false],
      ["LC", "a3", "Legal Counsel", "Encrypted message", false],
      ["FO", "a4", "Finance Ops", "Voice note", false],
    ];
    var rows = "";
    for (var i = 0; i < convs.length; i++) {
      rows +=
        '<div class="ch-conv' + (convs[i][4] ? " is-on" : "") + '">' + av(convs[i][0], convs[i][1], 40) +
        "<span><b>" + convs[i][2] + "</b><i>" + convs[i][3] + "</i></span></div>";
    }
    var contacts = "";
    for (var k = 0; k < 3; k++) {
      contacts +=
        '<div class="ch-contact">' + av(convs[k][0], convs[k][1], 34) + "<span><b>" + convs[k][2] + "</b><i>Trusted contact</i></span></div>";
    }
    return (
      '<div class="ch">' +
      // conversations
      '<section class="dw-card"><div class="ch-list-h"><div class="ch-row-h"><h2>Secure Conversations</h2><span class="dw-pill is-gray">4</span>' +
      '<span class="dw-btn">' + ic("msgplus", 15) + "New Chat</span></div>" +
      '<div class="dw-seg"><span class="is-on">' + ic("shield", 13) + "Active<em>4</em></span><span>" + ic("archive", 13) + "Archived<em>0</em></span><span>" + ic("eyeoff", 13) + "Hidden<em>0</em></span></div></div>" +
      rows + "</section>" +
      '<div class="ch-sep"><i></i></div>' +
      // thread
      chatThread(p) +
      '<div class="ch-sep"><i></i></div>' +
      // contacts
      '<section class="dw-card"><div class="ch-right-h"><div class="dw-seg"><span class="is-on">' + ic("users", 13) + "Contacts<em>3</em></span><span>" + ic("download", 13) + "Files</span><span>" + ic("terminal", 13) + "Terminal</span></div></div>" +
      '<div style="padding:10px 12px;border-bottom:1px solid #e5e7eb"><span class="dw-search" style="width:100%;height:34px;font-size:12.5px">' + ic("search", 15) + "Search a user to add</span></div>" +
      contacts + "</section></div>"
    );
  }

  /* The vault workspace card on its own.
     Hooks: #p-drop (dropzone) · #p-btn-file · #p-status · #p-drop-ico */
  function vaultWorkspace(p, cards) {
    return (
      '<section class="dw-card vt-ws">' +
      '<div class="vt-head"><div style="display:flex;align-items:center;gap:12px"><span class="vt-num">1</span><div><h2>Quantum Vault Workspace</h2>' +
      "<p>Encrypt files or folders into local quantum-safe .qvault containers — nothing leaves this device.</p></div></div>" +
      '<div class="vt-tabs"><span class="is-on">' + ic("lock", 15) + "Encrypt</span><span>" + ic("unlock", 15) + "Decrypt</span></div></div>" +
      '<div class="vt-drop" id="' + p + '-drop"><span class="vt-drop-ico" id="' + p + '-drop-ico">' + ic("vault", 46) + "</span>" +
      "<h3>Choose a file or folder to encrypt</h3>" +
      "<p>Sealed on-device with the VMK envelope · X25519 + ML-KEM-1024 / AES-256-GCM / HKDF-SHA3-256 / ML-DSA-87</p>" +
      '<div class="vt-drop-btns"><span class="dw-btn is-cyan" id="' + p + '-btn-file">' + ic("lock", 16) + 'Encrypt File</span><span class="dw-btn is-ghost">' + ic("folder", 16) + "Encrypt Folder</span></div>" +
      "<small>Local-only, offline, any size. Encrypted .qvault files stay exactly where you save them.</small></div>" +
      '<div class="vt-status" id="' + p + '-status"></div>' +
      '<div class="vt-algos">' + cards + "</div></section>"
    );
  }

  function vaultAlgoCards() {
    var algos = [
      ["key", "ML-KEM-1024", "Key encapsulation", "Protects the VMK · X25519", ""],
      ["lock", "AES-256-GCM", "Bulk cipher", "FEK · authenticated", ""],
      ["terminal", "HKDF-SHA3-256", "Key derivation", "Wrap &amp; recovery keys", ""],
      ["filecheck", "ML-DSA-87", "Signature", "FIPS 204 L5 · Ed25519", ""],
      ["shield", "Quantum Safe", "FIPS 203 / 204", "VMK envelope", " is-emerald"],
    ];
    var cards = "";
    for (var i = 0; i < algos.length; i++) {
      cards += '<div class="vt-algo' + algos[i][4] + '">' + ic(algos[i][0], 19) + "<b>" + algos[i][1] + "</b><i>" + algos[i][2] + "</i><u>" + algos[i][3] + "</u></div>";
    }
    return cards;
  }

  /* Quantum Vault page: workspace card over the Vault Crypto Terminal. */
  function vaultPage(p) {
    var cards = vaultAlgoCards();
    return (
      '<div class="vt">' + vaultWorkspace(p, cards) +
      '<section class="vt-term"><div class="vt-term-h"><span>' + ic("terminal", 16) + "Vault Crypto Terminal</span><em>On-device vault logs</em></div>" +
      '<div class="vt-term-b">Waiting for an encrypt or decrypt action...</div></section></div>'
    );
  }

  /* The file card dropped into the vault. */
  function fileCard(p, name, meta) {
    return (
      '<div class="vt-file" id="' + p + '-file"><span class="vt-file-ico">' + ic("file", 22) + "</span><span><b>" + name + "</b><i>" + meta + "</i></span></div>"
    );
  }

  // The verification card's own sentence, with the other person's name in it.
  function sasCopy(name) {
    return "Confirm this matches " + name + "'s screen — read it to each other aloud, or copy yours and paste the number they send you below. It must match exactly.";
  }

  /* Desktop call window.
     Hooks: #p-enc / #p-ok (state pill, stacked) · #p-sas (verification card)
            #p-sas-n (safety number) · #p-sas-btn · #p-remote (their avatar) */
  function callWindow(p, opts) {
    return (
      '<div class="dw is-call" id="' + p + '-dw">' + titleBar() + '<div class="cl">' +
      '<div class="cl-top"><div class="cl-who">' + av(opts.initials, "a1", 46) + "<span><b>" + opts.name + "</b><i>Connected</i></span></div>" +
      '<div class="cl-right"><div class="cl-q"><span>Low</span><span class="is-on">Auto</span><span>HD</span></div>' +
      '<div class="cl-state"><span class="is-enc" id="' + p + '-enc">' + ic("shield", 17) + 'Quantum-encrypted</span><span class="is-ok" id="' + p + '-ok">' + ic("check", 17) + "Verified</span></div></div></div>" +
      '<div class="cl-video"><span class="dw-av a1 cl-remote" id="' + p + '-remote">' + opts.initials + "</span>" +
      '<div class="cl-pip">' + av("AQ", "a4", 56) + "</div>" +
      '<div class="cl-sas" id="' + p + '-sas"><div class="cl-sas-h">' + ic("shield", 17) + "Verify this call is private</div>" +
      '<div class="cl-sas-n" id="' + p + '-sas-n">' + opts.number + "</div>" +
      "<p>" + sasCopy(opts.name) + "</p>" +
      '<div class="cl-sas-in">Type your peer\'s number</div>' +
      '<div class="cl-sas-row"><span class="cl-sas-copy">' + ic("copy", 16) + 'Copy</span><span class="cl-sas-btn" id="' + p + '-sas-btn">They match — continue</span></div></div>' +
      '<div class="cl-note">End-to-end encrypted. The server and network cannot see this call; only the person you called can see what you share.</div>' +
      '<div class="cl-ctrls"><span>' + ic("mic", 22) + "</span><span>" + ic("video", 22) + '</span><span class="is-end">' + ic("hangup", 22) + "</span></div>" +
      "</div></div></div>"
    );
  }

  /* --- Phone ---------------------------------------------------------------- */

  function phoneStatus() {
    return (
      '<div class="ph-status"><span>9:41</span><span class="ph-status-r"><span class="ph-bars"><i style="height:4px"></i><i style="height:6px"></i><i style="height:9px"></i><i style="height:12px"></i></span>' +
      '<span class="ph-batt"><i></i></span></span></div>'
    );
  }

  function phoneTabs(active) {
    var tabs = [
      ["dashboard", "dashboard", "Home"],
      ["chat", "chat", "Chats"],
      ["vault", "vault", "Vault"],
      ["quantum", "gauge", "Security"],
      ["settings", "settings", "Settings"],
    ];
    var out = '<div class="ph-tabs">';
    for (var i = 0; i < tabs.length; i++) {
      out +=
        '<div class="ph-tab' + (tabs[i][0] === active ? " is-on" : "") + '">' + ic(tabs[i][1], 22, "stroke-width:1.6") +
        "<span>" + tabs[i][2] + "</span>" + (tabs[i][0] === "chat" ? '<span class="ph-tab-badge">2</span>' : "") + "</div>";
    }
    return out + "</div>";
  }

  function phoneShell(p, inner) {
    return '<div class="ph" id="' + p + '-ph"><div class="ph-screen">' + inner + '</div><span class="ph-cam"></span></div>';
  }

  function masthead() {
    return (
      '<div class="ph-mast"><div class="ph-mast-row"><span class="ph-word">QGUARD<i class="ph-tally"></i></span>' +
      '<span class="ph-mast-r"><span class="ph-live"><i></i>LIVE</span><span class="ph-sq">' + ic("sun", 17, "stroke-width:1.6") + '</span><span class="ph-sq">' + ic("grid", 16, "stroke-width:1.6") + "</span></span></div>" +
      '<div class="ph-kick">Quantum-safe chat &amp; vault</div></div>'
    );
  }

  /* Helix Reactor — the Android home gauge. Geometry is the app's own:
     radii 88 / 71 / 54 / 37 on a 200-unit box, a 6% breather on a full ring.
     Hooks: #p-arc-0..3 and #p-arcu-0..3 (strokeDashoffset from C to C*(1-0.94)) */
  var RADII = [88, 71, 54, 37];

  function reactor(p) {
    var defs = "";
    var rings = "";
    for (var i = 0; i < RADII.length; i++) {
      var r = RADII[i];
      var c = (2 * Math.PI * r).toFixed(2);
      defs +=
        '<linearGradient id="' + p + "-g" + i + '" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#f3f2f2" stop-opacity="0.55"/><stop offset="55%" stop-color="#f3f2f2"/><stop offset="100%" stop-color="#ec3013"/></linearGradient>';
      rings +=
        '<circle cx="100" cy="100" r="' + r + '" fill="none" stroke="rgba(243,242,242,0.38)" stroke-width="5" opacity="0.55"/>' +
        '<circle id="' + p + "-arcu-" + i + '" cx="100" cy="100" r="' + r + '" fill="none" stroke="#f3f2f2" stroke-width="13" stroke-linecap="round" opacity="0.16" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '"/>' +
        '<circle id="' + p + "-arc-" + i + '" cx="100" cy="100" r="' + r + '" fill="none" stroke="url(#' + p + "-g" + i + ')" stroke-width="5.5" stroke-linecap="round" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '"/>';
    }
    return '<svg viewBox="0 0 200 200"><defs>' + defs + '</defs><g transform="rotate(-90 100 100)">' + rings + "</g></svg>";
  }

  /* Phone — Home / Dashboard.
     Hooks: reactor arcs (above) · #p-score · #p-meter · #p-coreh */
  function phoneDashboard(p) {
    return phoneShell(
      p,
      phoneStatus() + masthead() +
        '<div class="ph-head"><div class="ph-eyebrow">Overview · Hybrid E2EE</div><div class="ph-title">Dashboard</div></div>' +
        '<div class="ph-body"><div class="ph-eyebrow">Good afternoon</div><div class="ph-greet-name">Avery</div>' +
        '<div class="ph-card"><div class="ph-core"><span class="ph-core-mark"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="12" rx="10" ry="4.2"/><ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(60 12 12)"/><ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(120 12 12)"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/></svg></span>' +
        '<span style="flex:1;min-width:0"><span class="ph-eyebrow is-accent" style="display:block">Quantum core</span>' +
        '<span class="ph-core-h" id="' + p + '-coreh" style="display:block">100% · Fully protected</span>' +
        '<span class="ph-meter" style="display:block"><i id="' + p + '-meter"></i></span>' +
        '<span class="ph-core-cap" style="display:block">4 of 4 cryptographic layers fully active across 2 enrolled devices.</span></span></div>' +
        '<div class="ph-reactor">' + reactor(p) + '<div class="ph-reactor-read"><b id="' + p + '-score">0</b><i>%</i></div></div>' +
        '<div class="ph-legend"><span><i></i>Identity</span><span class="is-accent"><i></i>Handshake</span><span><i></i>Session</span><span class="is-accent"><i></i>Runtime</span></div>' +
        '<div class="ph-pills"><span class="ph-pill">ML-KEM-1024 + X25519 / ML-DSA-65 + Ed25519</span><span class="ph-pill">AES-256-GCM</span></div>' +
        "</div></div>" + phoneTabs("dashboard"),
    );
  }

  /* Phone — in-call screen.
     Hooks: #p-enc / #p-ok · #p-sas · #p-sas-n · #p-sas-btn · #p-remote */
  function phoneCall(p, opts) {
    return phoneShell(
      p,
      '<div class="ph-call">' + phoneStatus() +
        '<div class="ph-call-top"><span class="ph-av">' + opts.initials + "</span><span><b>" + opts.name + "</b><i>Connected</i></span>" +
        '<span class="ph-call-state"><span class="is-enc" id="' + p + '-enc">Quantum-encrypted</span><span class="is-ok" id="' + p + '-ok">Verified</span></span></div>' +
        '<div class="ph-call-video"><span class="ph-call-remote" id="' + p + '-remote">' + opts.initials + "</span>" +
        '<div class="ph-sas" id="' + p + '-sas"><div class="ph-sas-h">' + ic("shield", 12) + "Verify this call is private</div>" +
        '<div class="ph-sas-n" id="' + p + '-sas-n">' + opts.number + "</div>" +
        "<p>" + sasCopy(opts.name) + "</p>" +
        '<div class="ph-sas-in">Type your peer\'s number</div>' +
        '<div class="ph-sas-row"><span class="ph-sas-copy">' + ic("copy", 13) + 'Copy</span><span class="ph-sas-btn" id="' + p + '-sas-btn">They match — continue</span></div></div></div>' +
        '<div class="ph-call-ctrls"><span>' + ic("mic", 22, "stroke-width:1.6") + "</span><span>" + ic("video", 22, "stroke-width:1.6") + '</span><span class="is-end">' + ic("hangup", 22, "stroke-width:1.6") + "</span></div></div>",
    );
  }

  QG.ui = {
    desktop: desktop,
    chatPage: chatPage,
    chatThread: chatThread,
    vaultPage: vaultPage,
    vaultWorkspace: function (p) {
      return vaultWorkspace(p, vaultAlgoCards());
    },
    fileCard: fileCard,
    callWindow: callWindow,
    phoneDashboard: phoneDashboard,
    phoneCall: phoneCall,
    RADII: RADII,
  };
})();
