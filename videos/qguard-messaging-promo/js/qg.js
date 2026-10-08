/* =============================================================================
   QGuard Messaging promo — shared runtime helpers
   Loaded once by index.html and reached from every sub-composition as window.QG.

   Everything here is a pure function of timeline time: no clocks, no unseeded
   randomness, no listeners. Canvases are driven through QG.proxy(), a plain
   object whose `t` setter redraws, so a seek to any frame paints that frame
   even when the runtime suppresses GSAP callbacks.
   ========================================================================== */
(function () {
  "use strict";

  var DPR = Math.max(1, Math.round(window.devicePixelRatio || 1));

  /* --- Master clock ---------------------------------------------------------
     Global seconds. 120 BPM: one beat = 0.5s, one bar = 2s. Every scene starts
     on a bar line. The audio score (tools/make-audio.mjs) reads the same table. */
  var SCENES = [
    { id: "s01-threat", start: 0, dur: 6, mode: "night" },
    { id: "s02-brand", start: 6, dur: 6, mode: "day" },
    { id: "s03-devices", start: 12, dur: 6, mode: "day" },
    { id: "s04-chat", start: 18, dur: 4, mode: "day" },
    { id: "s05-inside", start: 22, dur: 4, mode: "night" },
    { id: "s06-calls", start: 26, dur: 4, mode: "day" },
    { id: "s07-vault", start: 30, dur: 4, mode: "day" },
    { id: "s08-envelope", start: 34, dur: 4, mode: "night" },
    { id: "s09-terminal", start: 38, dur: 4, mode: "night" },
    { id: "s10-suite", start: 42, dur: 8, mode: "day" },
    { id: "s11-principles", start: 50, dur: 4, mode: "mixed" },
    { id: "s12-close", start: 54, dur: 6, mode: "day" },
  ];
  var TOTAL = 60;

  /* --- Day / night schedule -------------------------------------------------
     Global seconds. At `t` the shared ground moves to day (1) or night (0)
     across `d` seconds centred on t; d = 0 is a hard flip on the beat. The
     background world and the overlay both read this one function, so the
     ground, the grain and the chapter rail can never disagree. */
  var SWITCH = [
    { t: 5.86, day: 1, d: 0.3 },
    { t: 22.0, day: 0, d: 0.22 },
    { t: 26.0, day: 1, d: 0.3 },
    { t: 34.0, day: 0, d: 0.22 },
    { t: 42.0, day: 1, d: 0.3 },
    { t: 50.0, day: 0, d: 0 },
    { t: 51.0, day: 1, d: 0 },
    { t: 52.0, day: 0, d: 0 },
    { t: 53.86, day: 1, d: 0.3 },
  ];

  function dayMix(t) {
    var v = 0;
    for (var i = 0; i < SWITCH.length; i++) {
      var s = SWITCH[i];
      if (s.d === 0) {
        if (t >= s.t) v = s.day;
      } else {
        var k = (t - (s.t - s.d / 2)) / s.d;
        k = k < 0 ? 0 : k > 1 ? 1 : k;
        k = k * k * (3 - 2 * k);
        v = v + (s.day - v) * k;
      }
    }
    return v;
  }

  /* --- Deterministic randomness -------------------------------------------- */
  function rng(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Integer hash to [0, 1). Stable for any pair of integers.
  function hash(a, b) {
    var h = (Math.imul(a | 0, 374761393) + Math.imul((b | 0) + 1, 668265263)) >>> 0;
    h = Math.imul(h ^ (h >>> 13), 1274126177) >>> 0;
    return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
  }

  function clamp(v, lo, hi) {
    return v < lo ? lo : v > hi ? hi : v;
  }

  function lerp(a, b, t) {
    return a + (b - a) * t;
  }

  function smooth(t) {
    t = clamp(t, 0, 1);
    return t * t * (3 - 2 * t);
  }

  // 0 before a, 1 after b, eased in between.
  function ramp(t, a, b) {
    return smooth((t - a) / (b - a));
  }

  /* --- Canvas plumbing ------------------------------------------------------ */
  function proxy(draw) {
    var state = { _t: 0 };
    Object.defineProperty(state, "t", {
      get: function () {
        return this._t;
      },
      set: function (v) {
        this._t = v;
        draw(v);
      },
    });
    return state;
  }

  // Sizes the backing store for the output density and returns a context whose
  // units are composition pixels.
  function canvas(el, w, h) {
    el.width = Math.round(w * DPR);
    el.height = Math.round(h * DPR);
    var ctx = el.getContext("2d");
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    return {
      ctx: ctx,
      w: w,
      h: h,
      clear: function () {
        ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
        ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = "source-over";
        ctx.clearRect(0, 0, w, h);
      },
    };
  }

  /* --- Eases ----------------------------------------------------------------
     Critically damped spring as a pure function of progress (see
     hyperframes-animation → gsap-easing-and-stagger.md). No overshoot. */
  function springEase(response) {
    var w = (2 * Math.PI) / (response || 0.5);
    function pos(t) {
      return 1 - Math.exp(-w * t) * (1 + w * t);
    }
    var SCAN = 12 / w;
    var N = 4800;
    var T = SCAN;
    for (var i = N; i >= 0; i--) {
      var t = (i / N) * SCAN;
      if (Math.abs(1 - pos(t)) > 0.001) {
        T = ((i + 1) / N) * SCAN;
        break;
      }
    }
    var xT = pos(T);
    return {
      duration: T,
      ease: function (p) {
        return pos(p * T) + p * (1 - xT);
      },
    };
  }

  /* --- Headline word masks -------------------------------------------------- */
  function wrapWord(text, extraClass) {
    var mask = document.createElement("span");
    mask.className = "qg-wm";
    var word = document.createElement("span");
    word.className = "qg-w" + (extraClass ? " " + extraClass : "");
    word.textContent = text;
    mask.appendChild(word);
    return { mask: mask, word: word };
  }

  // Replaces the text inside `el` with masked words and returns the word
  // elements in reading order. A child element (for example a .qg-grad span)
  // lends its class to each of its words; <br> is kept as a hard line break.
  function split(el) {
    var words = [];
    var out = document.createDocumentFragment();

    function addText(text, extraClass) {
      var parts = text.split(/(\s+)/);
      for (var i = 0; i < parts.length; i++) {
        var part = parts[i];
        if (!part) continue;
        if (/^\s+$/.test(part)) {
          out.appendChild(document.createTextNode(" "));
        } else {
          var w = wrapWord(part, extraClass);
          out.appendChild(w.mask);
          words.push(w.word);
        }
      }
    }

    var nodes = Array.prototype.slice.call(el.childNodes);
    for (var n = 0; n < nodes.length; n++) {
      var node = nodes[n];
      if (node.nodeType === 3) {
        addText(node.nodeValue, "");
      } else if (node.nodeType === 1) {
        if (node.tagName === "BR") {
          out.appendChild(document.createElement("br"));
        } else {
          addText(node.textContent, node.className || "");
        }
      }
    }

    el.textContent = "";
    el.appendChild(out);
    return words;
  }

  // Words rise through their masks.
  function rise(tl, words, at, opts) {
    opts = opts || {};
    tl.fromTo(
      words,
      { yPercent: 135 },
      {
        yPercent: 0,
        duration: opts.duration || 0.8,
        ease: opts.ease || "expo.out",
        stagger: opts.stagger === undefined ? 0.07 : opts.stagger,
      },
      at,
    );
  }

  // Chips, cards and buttons lift off their hard shadow.
  function lift(tl, els, at, opts) {
    opts = opts || {};
    var d = opts.depth === undefined ? 7 : opts.depth;
    var color = opts.color || "rgba(9, 13, 22, 0.88)";
    var extra = opts.extra ? ", " + opts.extra : "";
    var extraFrom = opts.extra ? ", " + opts.extraFrom : "";
    tl.fromTo(
      els,
      { x: d, y: d, opacity: 0, boxShadow: "0px 0px 0px " + color + extraFrom },
      {
        x: 0,
        y: 0,
        opacity: 1,
        boxShadow: d + "px " + d + "px 0px " + color + extra,
        duration: opts.duration || 0.5,
        ease: opts.ease || "power3.out",
        stagger: opts.stagger === undefined ? 0.12 : opts.stagger,
      },
      at,
    );
  }

  /* --- Cipher decode --------------------------------------------------------
     A mono string resolves from cipher glyphs, left to right. Length is
     preserved, so the element never changes width. */
  var GLYPHS = "0123456789ABCDEF#%&+=/<>*";

  function scramble(text, p, bucket, seed) {
    var n = text.length;
    var solid = Math.floor(p * (n + 2));
    var out = "";
    for (var i = 0; i < n; i++) {
      var ch = text.charAt(i);
      if (i < solid || ch === " " || p >= 1) {
        out += ch;
      } else {
        out += GLYPHS.charAt(Math.floor(hash(i + seed * 131, bucket) * GLYPHS.length));
      }
    }
    return out;
  }

  function decode(tl, el, at, opts) {
    opts = opts || {};
    var text = opts.text === undefined ? el.textContent : opts.text;
    var dur = opts.duration || 0.7;
    var seed = opts.seed || 1;
    var state = proxy(function (p) {
      el.textContent = scramble(text, p, Math.floor(p * dur * 24), seed);
    });
    state.t = 0;
    tl.fromTo(state, { t: 0 }, { t: 1, duration: dur, ease: "none" }, at);
    return state;
  }

  /* --- Icons ----------------------------------------------------------------
     Drawn for this piece on a 24-unit grid, 2-unit round strokes. */
  var ICONS = {
    dashboard: '<rect x="3" y="3" width="8" height="9" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="12" width="8" height="9" rx="1.5"/><rect x="3" y="16" width="8" height="5" rx="1.5"/>',
    chat: '<path d="M4 5h16v11H9l-5 4z"/>',
    vault: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.2"/><path d="M12 16.2v1.8"/>',
    key: '<circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8 20 3"/><path d="m16 7 3 3"/><path d="m18.5 4.5 2 2"/>',
    devices: '<rect x="2" y="4" width="14" height="10" rx="1.5"/><path d="M6 18h6"/><path d="M9 14v4"/><rect x="17" y="9" width="5" height="11" rx="1.2"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M21 14v7"/><path d="M14 21h3"/>',
    activity: '<path d="M2 12h4l3-8 4 16 3-8h6"/>',
    gauge: '<path d="M4 18a9 9 0 1 1 16 0"/><path d="m12 13 4-5"/><circle cx="12" cy="14" r="1.2"/>',
    card: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/><path d="M6 15h4"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>',
    bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 21h4"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7"/><path d="M12 17v.2"/>',
    moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M5 5l1.8 1.8M17.2 17.2 19 19M5 19l1.8-1.8M17.2 6.8 19 5"/>',
    logout: '<path d="M10 4H5v16h5"/><path d="M14 8l4 4-4 4"/><path d="M18 12H9"/>',
    paperclip: '<path d="M20 11.5 12 19.5a5 5 0 0 1-7-7l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7L9.8 17a1.6 1.6 0 0 1-2.3-2.3l7.5-7.5"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><path d="M12 18v3"/>',
    send: '<path d="M21 3 3 10.5l7 2.5 2.5 7z"/><path d="m21 3-11 10"/>',
    video: '<rect x="3" y="6" width="13" height="12" rx="2"/><path d="m16 10 5-3v10l-5-3z"/>',
    more: '<circle cx="12" cy="5" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="12" cy="19" r="1.2"/>',
    archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10h14V9"/><path d="M10 13h4"/>',
    eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 6.1A9.5 9.5 0 0 1 22 12a11 11 0 0 1-2.4 3.2"/><path d="M6.4 6.5A11 11 0 0 0 2 12a9.6 9.6 0 0 0 13 4.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    timer: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2"/><path d="M9 2h6"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    chevron: '<path d="m6 9 6 6 6-6"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
    tick: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    terminal: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3"/><path d="M12 15h6"/>',
    filecheck: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4"/><path d="m9 14 2 2 4-4"/>',
    file: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4"/><path d="M9 13h6M9 17h6"/>',
    folder: '<path d="M3 6h6l2 2h10v11H3z"/>',
    unlock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 7.6-1.6"/><circle cx="12" cy="15" r="1.2"/>',
    lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18 14.2a6.5 6.5 0 0 1 3.5 5.8"/>',
    download: '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 20h16"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><path d="M12 7.5v.2"/>',
    phone: '<rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M11 18.5h2"/>',
    monitor: '<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5v.2M7 16.5v.2"/>',
    atom: '<ellipse cx="12" cy="12" rx="10" ry="4.2"/><ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(60 12 12)"/><ellipse cx="12" cy="12" rx="10" ry="4.2" transform="rotate(120 12 12)"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>',
    grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>',
    hangup: '<path d="M3 13c5-5 13-5 18 0l-2.5 3-3.5-1.5v-2.5a9 9 0 0 0-6 0v2.5L5.5 16z"/><path d="M4 4l16 16"/>',
    cloudoff: '<path d="M3 3l18 18"/><path d="M7 18a4.5 4.5 0 0 1-.6-9"/><path d="M9.5 6.2A6 6 0 0 1 18 11a3.5 3.5 0 0 1 1.9 6"/>',
    msgplus: '<path d="M4 5h16v11H9l-5 4z"/><path d="M12 8v5M9.5 10.5h5"/>',
    windows: '<path d="M3 5.5 11 4.3v7.2H3zM13 4l8-1.2v8.7h-8zM3 13h8v7.2L3 19zM13 13h8v8.7L13 20.5z" fill="currentColor" stroke="none"/>',
    arrow: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  };

  function icon(name, size, extraStyle) {
    var s = size || 24;
    return (
      '<span class="qg-ico" style="width:' + s + "px;height:" + s + "px;" + (extraStyle || "") + '">' +
      '<svg viewBox="0 0 24 24">' + (ICONS[name] || "") + "</svg></span>"
    );
  }

  window.QG = {
    DPR: DPR,
    SCENES: SCENES,
    TOTAL: TOTAL,
    dayMix: dayMix,
    rng: rng,
    hash: hash,
    clamp: clamp,
    lerp: lerp,
    smooth: smooth,
    ramp: ramp,
    proxy: proxy,
    canvas: canvas,
    springEase: springEase,
    split: split,
    rise: rise,
    lift: lift,
    scramble: scramble,
    decode: decode,
    icon: icon,
    GLYPHS: GLYPHS,
  };
})();
