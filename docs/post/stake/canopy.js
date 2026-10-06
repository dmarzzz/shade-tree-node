/* global document, IntersectionObserver, requestAnimationFrame, window */

/* Get access canopy: the same glyph identity as the landing grove, but composed as
   a CANOPY — dense foliage across the whole backdrop, denser toward the crown and
   thinning down, never a thin strip and never a straight trunk line. Content sits
   in clearings. One seat (your leaf) can be placed and lit by the stake flow.
   Reuses the grove's atlas, noise, greens, reduced-motion and off-screen pause. */
(function () {
  'use strict';

  var TAU = Math.PI * 2;
  var RAMP = '·:;+*xeoa%&#@';
  var GREEN_TIERS = 16;
  var GOLD_TIERS = 8;
  var FEATHER = 56;

  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  function hash(ix, iy, seed) {
    var h = (ix * 374761393 + iy * 668265263 + seed * 974634) | 0;
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    h = h ^ (h >>> 16);
    return (h >>> 0) / 4294967295;
  }
  function vnoise(x, y, seed) {
    var ix = Math.floor(x), iy = Math.floor(y);
    var fx = x - ix, fy = y - iy;
    var sx = fx * fx * (3 - 2 * fx), sy = fy * fy * (3 - 2 * fy);
    var a = hash(ix, iy, seed), b = hash(ix + 1, iy, seed);
    var c = hash(ix, iy + 1, seed), d = hash(ix + 1, iy + 1, seed);
    return a + (b - a) * sx + (c - a) * sy + (a - b - c + d) * sx * sy;
  }
  function lerp(a, b, t) { return a + (b - a) * t; }

  /* moss -> leaf -> lichen: the site's greens */
  function greenColor(t) {
    var r, g, b;
    if (t < 0.7) { var u = t / 0.7; r = lerp(22, 116, u); g = lerp(40, 150, u); b = lerp(28, 110, u); }
    else { var v = (t - 0.7) / 0.3; r = lerp(116, 210, v); g = lerp(150, 224, v); b = lerp(110, 196, v); }
    return 'rgb(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ')';
  }
  /* rare sparks in the site's pulse gold */
  function goldColor(t) {
    var r, g, b;
    if (t < 0.7) { var u = t / 0.7; r = lerp(90, 226, u); g = lerp(70, 190, u); b = lerp(30, 103, u); }
    else { var v = (t - 0.7) / 0.3; r = lerp(226, 255, v); g = lerp(190, 228, v); b = lerp(103, 168, v); }
    return 'rgb(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ')';
  }

  function Canopy(section) {
    this.section = section;
    this.canvas = section.querySelector('.glyph-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    if (!this.ctx) return;
    this.seed = 23;
    this.visible = true;
    this.running = false;
    this.last = 0;
    this.t0 = performance.now();
    this.seat = null;       /* your leaf: {col,row,x,y, lit, litAt} */
    this.loop = this.loop.bind(this);
    this.build();
    this.observe();
    if (reduced.matches) this.drawFrame(0, true); else this.start();

    var self = this;
    reduced.addEventListener && reduced.addEventListener('change', function () {
      if (reduced.matches) { self.stop(); self.drawFrame(0, true); } else { self.start(); }
    });
    var rt = null;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () { self.build(); if (reduced.matches) self.drawFrame(0, true); }, 160);
    });
    window.addEventListener('load', function () { self.build(); if (reduced.matches) self.drawFrame(0, true); });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) self.stop(); else if (!reduced.matches && self.visible) self.start();
    });
    /* the stake flow re-parts the canopy when the current panel changes */
    section.addEventListener('canopy:relayout', function () {
      self.build(); if (reduced.matches) self.drawFrame(0, true);
    });
  }

  Canopy.prototype.observe = function () {
    var self = this;
    if (!('IntersectionObserver' in window)) return;
    new IntersectionObserver(function (entries) {
      self.visible = entries[0].isIntersecting;
      if (!self.visible) self.stop(); else if (!reduced.matches) self.start();
    }, { threshold: 0.01 }).observe(this.canvas);
  };

  /* 0 inside a clearing, ramping to 1 beyond the feather */
  Canopy.prototype.clearingFactor = function (x, y) {
    var f = 1;
    for (var i = 0; i < this.clearings.length; i++) {
      var r = this.clearings[i];
      var dx = Math.max(r.left - x, 0, x - r.right);
      var dy = Math.max(r.top - y, 0, y - r.bottom);
      var d = Math.sqrt(dx * dx + dy * dy);
      var t = Math.min(1, d / FEATHER);
      t = t * t * (3 - 2 * t);
      if (t < f) f = t;
    }
    return f;
  };

  Canopy.prototype.build = function () {
    var canvas = this.canvas;
    var srect = this.section.getBoundingClientRect();
    var w = Math.max(1, srect.width), h = Math.max(1, srect.height);
    var dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    this.w = w; this.h = h; this.dpr = dpr;

    this.clearings = [];
    var nodes = this.section.querySelectorAll('[data-clearing]');
    for (var ci = 0; ci < nodes.length; ci++) {
      var r = nodes[ci].getBoundingClientRect();
      if (r.width < 2 || r.height < 2) continue; /* hidden panels contribute nothing */
      this.clearings.push({
        left: r.left - srect.left, right: r.right - srect.left,
        top: r.top - srect.top, bottom: r.bottom - srect.top
      });
    }

    var cell = w < 600 ? 13 : 15;
    this.cell = cell;
    var cols = Math.ceil(w / cell), rows = Math.ceil(h / cell);
    var seed = this.seed;
    var cells = [];

    for (var rr = 0; rr < rows; rr++) {
      for (var cc = 0; cc < cols; cc++) {
        var px = (cc + 0.5) * cell, py = (rr + 0.5) * cell;
        /* foliage in clumps, three octaves, so it reads as leaves not a grid */
        var leaf = 0.52 * vnoise(px / 72, py / 58, seed) +
                   0.30 * vnoise(px / 27, py / 22, seed + 7) +
                   0.18 * vnoise(px / 12, py / 10, seed + 13);
        /* the canopy: dense at the crown (top), thinning downward but always present */
        var vy = py / h;
        var crown = 1 - 0.55 * (vy * vy); /* 1.0 at top -> ~0.45 at the base */
        var value = (leaf - 0.30) / 0.70; /* recenter the clumps */
        if (value <= 0) continue;
        value *= crown;
        if (value <= 0.10) continue; /* gaps between leaf clumps */
        var open = this.clearingFactor(px, py);
        if (open < 0.05) continue;
        var topFade = Math.min(1, py / 36);
        var botFade = Math.min(1, (h - py) / 24);
        cells.push({
          x: cc * cell, y: rr * cell,
          ch: Math.min(RAMP.length - 1, Math.floor(value * (RAMP.length - 1) + 0.5)),
          base: (0.14 + 0.66 * value) * open * topFade * botFade,
          phase: hash(cc, rr, seed + 29),
          rate: 0.20 + 0.55 * hash(cc, rr, seed + 31),
          gold: hash(cc, rr, seed + 37) < 0.035 && value > 0.4,
          nf: 2 + 15 * hash(cc, rr, seed + 23),
          famp: 0, fstart: -10,
          seat: false
        });
      }
    }

    this.cellsArr = cells;
    this.placeSeat();
    this.buildAtlas();
  };

  /* your leaf: a reserved cell high in the crown, lit when admitted */
  Canopy.prototype.placeSeat = function () {
    if (!this.seat) return;
    var cell = this.cell;
    var col = Math.round(this.seat.frac * (this.w / cell));
    var row = Math.round((this.h * 0.14) / cell);
    this.seat.col = col; this.seat.row = row;
    this.seat.x = col * cell; this.seat.y = row * cell;
  };

  Canopy.prototype.buildAtlas = function () {
    var s = Math.ceil(this.cell * this.dpr);
    var chars = RAMP.length;
    var tiers = GREEN_TIERS + GOLD_TIERS;
    var atlas = document.createElement('canvas');
    atlas.width = s * chars;
    atlas.height = s * tiers;
    var g = atlas.getContext('2d');
    g.font = (s * 0.9) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    for (var t = 0; t < tiers; t++) {
      var isGold = t >= GREEN_TIERS;
      var tt = isGold ? (t - GREEN_TIERS) / (GOLD_TIERS - 1) : t / (GREEN_TIERS - 1);
      var col = isGold ? goldColor(tt) : greenColor(tt);
      g.fillStyle = col;
      if (tt > 0.62) { g.shadowColor = col; g.shadowBlur = (tt - 0.62) * 9 * this.dpr; } else { g.shadowBlur = 0; }
      for (var ci = 0; ci < chars; ci++) {
        g.fillText(RAMP[ci], ci * s + s / 2, t * s + s / 2 + s * 0.03);
      }
    }
    this.atlas = atlas; this.as = s;
  };

  Canopy.prototype.drawFrame = function (t, still) {
    var ctx = this.ctx, dpr = this.dpr, s = this.as;
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    var cells = this.cellsArr;
    for (var i = 0; i < cells.length; i++) {
      var cl = cells[i];
      var b = cl.base;
      if (!still) {
        b *= 0.70 + 0.30 * Math.sin(t * cl.rate * TAU * 0.15 + cl.phase * TAU);
        if (t >= cl.nf) {
          cl.fstart = t;
          cl.famp = (Math.sin(cl.phase * 9871 + t) > 0.35 ? 0.6 : -0.4) * (0.4 + 0.6 * cl.phase);
          cl.nf = t + 4 + 18 * hash(i, (t * 7) | 0, 91);
        }
        var ft = t - cl.fstart;
        if (ft >= 0 && ft < 0.7) {
          var env = ft < 0.12 ? ft / 0.12 : 1 - (ft - 0.12) / 0.58;
          b += cl.famp * env * cl.base * 1.4;
        }
      } else { b *= 0.82; }
      if (b <= 0.02) continue;
      if (b > 1) b = 1;
      var tier = cl.gold
        ? GREEN_TIERS + Math.min(GOLD_TIERS - 1, Math.round((0.35 + 0.65 * b) * (GOLD_TIERS - 1)))
        : Math.min(GREEN_TIERS - 1, Math.round(b * (GREEN_TIERS - 1)));
      ctx.drawImage(this.atlas, cl.ch * s, tier * s, s, s,
        Math.round(cl.x * dpr), Math.round(cl.y * dpr), s, s);
    }
    /* your seat */
    if (this.seat && this.seat.x != null) {
      var lit = this.seat.lit;
      var pulse = still ? 1 : 0.8 + 0.2 * Math.sin(t * TAU * 0.5);
      var row = lit
        ? GREEN_TIERS + Math.min(GOLD_TIERS - 1, Math.round(((still ? 0.9 : 0.75 + 0.25 * pulse)) * (GOLD_TIERS - 1)))
        : Math.min(GREEN_TIERS - 1, Math.round((lit ? 0.9 : 0.5) * (GREEN_TIERS - 1)));
      var ch = lit ? RAMP.length - 1 : 8; /* a bright leaf when lit */
      ctx.drawImage(this.atlas, Math.min(RAMP.length - 1, ch) * s, row * s, s, s,
        Math.round(this.seat.x * dpr), Math.round(this.seat.y * dpr), s, s);
    }
  };

  Canopy.prototype.loop = function (now) {
    if (!this.running) return;
    if (now - this.last >= 33) { this.last = now; this.drawFrame((now - this.t0) / 1000, false); }
    requestAnimationFrame(this.loop);
  };
  Canopy.prototype.start = function () { if (this.running || !this.ctx) return; this.running = true; requestAnimationFrame(this.loop); };
  Canopy.prototype.stop = function () { this.running = false; };

  /* API for the stake flow (the events layer): place and light your leaf */
  Canopy.prototype.addSeat = function (frac) { this.seat = { frac: frac == null ? 0.5 : frac, lit: false }; this.placeSeat(); };
  Canopy.prototype.lightSeat = function () { if (this.seat) this.seat.lit = true; };
  Canopy.prototype.clearSeat = function () { this.seat = null; };

  function init() {
    var sections = document.querySelectorAll('.glyph-grove');
    window.ShadeCanopy = null;
    for (var i = 0; i < sections.length; i++) {
      var c = new Canopy(sections[i]);
      if (c.ctx) window.ShadeCanopy = c;
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
