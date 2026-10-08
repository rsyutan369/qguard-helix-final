/* =============================================================================
   QGuard Messaging promo — canvas renderers
   Each renderer is a pure function of scene time. Scenes drive them through
   QG.proxy(), so any frame can be painted on its own, in any order.
   ========================================================================== */
(function () {
  "use strict";
  var QG = window.QG;

  function easeInOutCubic(p) {
    p = QG.clamp(p, 0, 1);
    return p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
  }

  /* --- Double helix --------------------------------------------------------
     Two ribbons a half-turn apart. A ribbon is widest where it faces the
     viewer and thinnest edge-on, and the half of each turn that passes behind
     is drawn first and darker, so it reads as depth rather than as two sine
     waves. Rungs carry a pin at each end, as on the Qguard Helix mark.

     o: { x0, x1, cy, amp, k, w, width, power, rungs, rungStep, a, b }
        a / b: { front, back, glow } colours for the two strands            */
  function helix(ctx, o) {
    var STEP = 6;
    var x0 = o.x0;
    var x1 = o.x1;
    if (x1 <= x0) return;
    var power = o.power || 0;
    var width = o.width || 13;
    var strands = [
      { phase: 0, c: o.a },
      { phase: Math.PI, c: o.b },
    ];

    function ribbon(s, wantFront) {
      ctx.fillStyle = wantFront ? s.c.front : s.c.back;
      ctx.globalAlpha = o.alpha === undefined ? 1 : o.alpha;
      var run = null;
      function flush() {
        if (run && run.length > 1) {
          ctx.beginPath();
          ctx.moveTo(run[0].x, run[0].y - run[0].hw);
          for (var i = 1; i < run.length; i++) ctx.lineTo(run[i].x, run[i].y - run[i].hw);
          for (var j = run.length - 1; j >= 0; j--) ctx.lineTo(run[j].x, run[j].y + run[j].hw);
          ctx.closePath();
          ctx.fill();
        }
        run = null;
      }
      for (var x = x0; x <= x1; x += STEP) {
        var th = o.k * x + o.w + s.phase;
        var c = Math.cos(th);
        var pt = { x: x, y: o.cy + o.amp * Math.sin(th), hw: 2.5 + (width + 5 * power) * Math.abs(c) };
        if (c >= 0 === wantFront) {
          if (!run) run = [];
          run.push(pt);
        } else if (run) {
          run.push(pt);
          flush();
        }
      }
      flush();
    }

    var alpha = o.alpha === undefined ? 1 : o.alpha;

    // soft light under the whole braid
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    for (var s = 0; s < 2; s++) {
      ctx.beginPath();
      for (var gx = x0; gx <= x1; gx += 12) {
        var gy = o.cy + o.amp * Math.sin(o.k * gx + o.w + strands[s].phase);
        if (gx === x0) ctx.moveTo(gx, gy);
        else ctx.lineTo(gx, gy);
      }
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = "rgba(" + strands[s].c.glow + "," + (0.14 + 0.16 * power).toFixed(3) + ")";
      ctx.lineWidth = width * 2.6;
      ctx.stroke();
    }

    ribbon(strands[0], false);
    ribbon(strands[1], false);

    if (o.rungs !== false) {
      var step = o.rungStep || 44;
      var first = Math.ceil(x0 / step) * step + step / 2;
      for (var rx = first; rx < x1 - 10; rx += step) {
        var sv = Math.sin(o.k * rx + o.w);
        var y1 = o.cy + o.amp * sv;
        var y2 = o.cy - o.amp * sv;
        if (Math.abs(y1 - y2) < 26) continue;
        var fade = QG.clamp((x1 - rx) / 200, 0, 1) * QG.clamp((rx - x0) / 60, 0, 1);
        ctx.globalAlpha = (0.32 + 0.3 * power) * fade * alpha;
        ctx.strokeStyle = o.rungColor || "rgb(150,180,255)";
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.moveTo(rx, y1);
        ctx.lineTo(rx, y2);
        ctx.stroke();
        ctx.fillStyle = o.pinColor || "rgb(214,228,255)";
        ctx.beginPath();
        ctx.arc(rx, y1, 4.5, 0, 6.2832);
        ctx.arc(rx, y2, 4.5, 0, 6.2832);
        ctx.fill();
      }
    }

    ribbon(strands[0], true);
    ribbon(strands[1], true);
    ctx.globalAlpha = 1;
  }

  var NIGHT_STRANDS = {
    a: { front: "rgb(167,139,250)", back: "rgb(62,48,128)", glow: "167,139,250" },
    b: { front: "rgb(34,211,238)", back: "rgb(14,92,112)", glow: "34,211,238" },
  };

  var DAY_STRANDS = {
    a: { front: "rgb(124,58,237)", back: "rgb(196,181,253)", glow: "124,58,237" },
    b: { front: "rgb(0,168,214)", back: "rgb(165,233,247)", glow: "0,168,214" },
  };

  /* --- Scene 01: the wall ---------------------------------------------------
     60 × 20 cells of cipher glyphs.
       Sweep 1 (cyan)  0.45–2.05s  the harvest: everything is copied.
       Sweep 2 (rose)  2.75–4.00s  Q-Day: runs of glyphs read as plaintext.
       Sweep 3 (helix) 4.45–5.70s  the answer: it is sealed again, for good.
     Returns (t) => { pct, front }: harvest progress 0–100 and the helix front x. */
  function threatWall(cv) {
    var ctx = cv.ctx;
    var COLS = 60;
    var ROWS = 20;
    var CW = 32;
    var CH = 54;
    var G = "0123456789ABCDEF0123456789abcdef+/=";

    // What the archive turns out to contain.
    var WORDS = [
      { text: "CUSTOMER DATA", col: 24, row: 1 },
      { text: "CONTRACTS", col: 45, row: 2 },
      { text: "API KEYS", col: 20, row: 3 },
      { text: "CREDENTIALS", col: 46, row: 5 },
      { text: "SOURCE CODE", col: 45, row: 8 },
      { text: "MEDICAL RECORDS", col: 42, row: 11 },
      { text: "PRIVATE MESSAGES", col: 38, row: 13 },
      { text: "BOARD MINUTES", col: 5, row: 14 },
      { text: "TRADE SECRETS", col: 22, row: 15 },
    ];
    var plain = {};
    WORDS.forEach(function (w) {
      for (var k = 0; k < w.text.length; k++) {
        if (w.text.charAt(k) !== " ") plain[w.col + k + ":" + w.row] = w.text.charAt(k);
      }
    });

    function sweepX(t, from, dur) {
      return QG.lerp(-140, 2060, easeInOutCubic((t - from) / dur));
    }

    function bar(x, rgb) {
      if (x < -130 || x > 2050) return;
      var g = ctx.createLinearGradient(x - 220, 0, x + 6, 0);
      g.addColorStop(0, "rgba(" + rgb + ",0)");
      g.addColorStop(0.85, "rgba(" + rgb + ",0.14)");
      g.addColorStop(1, "rgba(" + rgb + ",0.9)");
      ctx.globalAlpha = 1;
      ctx.fillStyle = g;
      ctx.fillRect(x - 220, 0, 226, 1080);
      ctx.fillStyle = "rgba(255,255,255,0.9)";
      ctx.fillRect(x, 0, 3, 1080);
    }

    return function (t) {
      cv.clear();
      var wallIn = QG.ramp(t, 0.05, 0.9);
      var s1 = sweepX(t, 0.45, 1.6);
      var s2 = t < 2.75 ? -9999 : sweepX(t, 2.75, 1.25);
      var s3 = t < 4.45 ? -9999 : sweepX(t, 4.45, 1.25);
      var copiedFade = 1 - QG.ramp(t, 2.2, 2.9);

      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      for (var r = 0; r < ROWS; r++) {
        for (var c = 0; c < COLS; c++) {
          var x = c * CW + CW / 2;
          var y = r * CH + CH / 2;
          var h = QG.hash(c * 3 + 1, r * 7 + 2);
          var bucket = Math.floor(t * (0.7 + 2.6 * h) + h * 10);
          var ch = G.charAt(Math.floor(QG.hash(c * 17 + r * 131, bucket) * G.length));
          var alpha = (0.15 + 0.2 * QG.hash(c + 5, r + 9)) * wallIn;
          var rgb = "143,166,214";
          var bold = false;

          // sweep 1 — the harvest
          var d1 = s1 - x;
          if (d1 > 0 && t < 2.9) {
            var flare = d1 < 240 ? Math.pow(1 - d1 / 240, 2) : 0;
            alpha += (0.6 * flare + 0.1) * copiedFade;
            if (flare > 0.05) rgb = "34,211,238";
          }

          // sweep 2 — Q-Day
          var p = plain[c + ":" + r];
          var d2 = s2 - x;
          if (d2 > 0) {
            if (p) {
              var k2 = QG.clamp(d2 / 110, 0, 1);
              if (k2 >= 1) ch = p;
              rgb = "255,92,122";
              alpha = 0.35 + 0.65 * k2;
              bold = true;
            } else {
              alpha *= QG.lerp(1, 0.42, QG.clamp(d2 / 320, 0, 1));
            }
          }

          // sweep 3 — sealed again
          var d3 = s3 - x;
          if (d3 > 0) {
            var k3 = QG.clamp(d3 / 150, 0, 1);
            if (p) {
              if (k3 < 1) {
                rgb = "196,150,214";
                alpha = QG.lerp(1, 0.5, k3);
              } else {
                rgb = "124,163,255";
                alpha = 0.5;
                bold = false;
              }
            } else {
              rgb = "124,163,255";
              alpha = QG.lerp(alpha, 0.34 + 0.12 * h, k3);
            }
          }

          if (alpha < 0.02) continue;
          ctx.globalAlpha = Math.min(1, alpha);
          ctx.fillStyle = "rgb(" + rgb + ")";
          ctx.font = (bold ? "700" : "500") + ' 27px "JetBrains Mono", monospace';
          ctx.fillText(ch, x, y);
        }
      }

      if (t < 2.2) bar(s1, "34,211,238");
      if (t >= 2.75 && t < 4.1) bar(s2, "255,92,122");

      if (t >= 4.45) {
        var power = QG.ramp(t, 5.0, 5.9);
        helix(ctx, {
          x0: -30,
          x1: s3,
          cy: 540,
          amp: 150 * QG.ramp(t, 4.45, 5.25),
          k: 0.0098,
          w: t * 2.4,
          power: power,
          a: NIGHT_STRANDS.a,
          b: NIGHT_STRANDS.b,
        });

        // the leading edge
        if (s3 > -200 && s3 < 2100) {
          var g = ctx.createRadialGradient(s3, 540, 0, s3, 540, 360);
          g.addColorStop(0, "rgba(214,238,255,0.6)");
          g.addColorStop(0.4, "rgba(96,165,250,0.22)");
          g.addColorStop(1, "rgba(76,141,255,0)");
          ctx.fillStyle = g;
          ctx.fillRect(s3 - 360, 180, 720, 720);
        }

        // the braid gathers light at its centre just before the bloom
        if (power > 0) {
          var g2 = ctx.createRadialGradient(960, 540, 0, 960, 540, 520);
          g2.addColorStop(0, "rgba(240,248,255," + (0.5 * power).toFixed(3) + ")");
          g2.addColorStop(0.45, "rgba(125,190,255," + (0.2 * power).toFixed(3) + ")");
          g2.addColorStop(1, "rgba(76,141,255,0)");
          ctx.fillStyle = g2;
          ctx.fillRect(440, 20, 1040, 1040);
        }
      }
      ctx.globalAlpha = 1;

      return {
        pct: Math.round(100 * QG.clamp((s1 + 140) / 2200, 0, 1)),
        front: t < 4.45 ? 0 : QG.clamp(s3, 0, 1920),
      };
    };
  }

  QG.draw = {
    helix: helix,
    threatWall: threatWall,
    NIGHT_STRANDS: NIGHT_STRANDS,
    DAY_STRANDS: DAY_STRANDS,
    easeInOutCubic: easeInOutCubic,
  };
})();
