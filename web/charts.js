'use strict';

/* Charts for the overview: time series (lines with a light area), stacked
   columns, sparklines, bar lists and a share bar. Plain SVG and HTML with no
   library, so the admin UI stays a handful of static files under a strict
   CSP. Colours are CSS custom properties (--c-series-*, --c-chart-*) that the
   skins and the light theme define, so a chart follows the theme without
   being redrawn. Every label goes in with textContent. */
const QGCharts = (() => {
  const SVGNS = 'http://www.w3.org/2000/svg';

  function svgEl(tag, attrs, parent) {
    const n = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    if (parent) parent.appendChild(n);
    return n;
  }
  function el(tag, cls, parent, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    if (parent) parent.appendChild(n);
    return n;
  }
  const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

  /* ---- formatting ---- */
  const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
  const whole = new Intl.NumberFormat('en-US');
  function scaled(v, units, base) {
    let i = 0;
    let x = Math.abs(v);
    while (x >= base && i < units.length - 1) { x /= base; i++; }
    const digits = i === 0 || x >= 100 ? 0 : 1;
    const s = x.toFixed(digits).replace(/\.0$/, '');
    return `${v < 0 ? '-' : ''}${s} ${units[i]}`;
  }
  const fmt = {
    bits: (v) => scaled(v, ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'], 1000),
    bytes: (v) => scaled(v, ['B', 'kB', 'MB', 'GB', 'TB', 'PB'], 1000),
    count: (v) => (Math.abs(v) < 1000 ? whole.format(Math.round(v * 10) / 10) : compact.format(v)),
    int: (v) => whole.format(Math.round(v)),
    ms: (v) => (v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1).replace(/\.0$/, '')} s` : `${Math.round(v)} ms`),
    pct: (v) => (v === 0 ? '0%' : v < 0.1 ? '<0.1%' : `${v >= 10 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')}%`),
  };

  // niceScale picks an axis maximum and step (1, 2 or 5 times a power of ten)
  // that give about `ticks` gridlines above zero.
  function niceScale(max, ticks) {
    if (!(max > 0)) return { max: 1, step: 0.25 };
    const raw = max / ticks;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const r = raw / mag;
    const step = (r > 5 ? 10 : r > 2 ? 5 : r > 1 ? 2 : 1) * mag;
    return { max: Math.ceil(max / step - 1e-9) * step, step };
  }

  const pad2 = (n) => String(n).padStart(2, '0');
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const hhmm = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  const dayLabel = (d) => `${DAYS[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]}`;

  // spanLabel names the interval [t, t+step) for a tooltip.
  function spanLabel(t, step) {
    const a = new Date(t * 1000);
    const b = new Date((t + step) * 1000);
    if (step < 60) return `${dayLabel(a)}, ${hhmm(a)}:${pad2(a.getSeconds())} to ${hhmm(b)}:${pad2(b.getSeconds())}`;
    return `${dayLabel(a)}, ${hhmm(a)} to ${hhmm(b)}`;
  }

  // timeTicks returns about six tick times between start and end, on round
  // local-time boundaries.
  function timeTicks(start, end) {
    const steps = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];
    const step = steps.find((s) => s >= (end - start) / 7) || 86400;
    const offset = -new Date(start * 1000).getTimezoneOffset() * 60;
    const out = [];
    for (let t = Math.ceil((start + offset) / step) * step - offset; t <= end; t += step) {
      const d = new Date(t * 1000);
      out.push({ t, label: step >= 86400 ? `${DAYS[d.getDay()]} ${d.getDate()}` : hhmm(d) });
    }
    return out;
  }

  /* ---- tooltip ---- */
  function tooltip(host) {
    const tip = el('div', 'chart__tip', host);
    tip.hidden = true;
    tip.setAttribute('role', 'status');
    return {
      show(title, rows, x, y) {
        tip.replaceChildren();
        el('div', 'chart__tiptitle', tip, title);
        for (const r of rows) {
          const row = el('div', 'chart__tiprow', tip);
          const key = el('span', `chart__key chart__key--${r.shape || 'line'}`, row);
          if (r.color) key.style.setProperty('--key', r.color);
          el('span', 'chart__tipval', row, r.value);
          el('span', 'chart__tiplabel', row, r.label);
        }
        tip.hidden = false;
        const hostW = host.clientWidth;
        const w = tip.offsetWidth;
        const left = x + 14 + w > hostW ? Math.max(4, x - 14 - w) : x + 14;
        tip.style.left = `${left}px`;
        tip.style.top = `${Math.max(4, y)}px`;
      },
      hide() { tip.hidden = true; },
    };
  }

  /* ---- shared frame for time charts ---- */
  class TimeChart {
    constructor(host, opts) {
      this.host = host;
      this.opts = Object.assign({ height: 240, format: String, axisFormat: null, empty: 'No data in this range yet.' }, opts);
      host.classList.add('chart');
      this.plot = el('div', 'chart__plot', host);
      this.plot.tabIndex = 0;
      this.plot.setAttribute('role', 'group');
      this.plot.setAttribute('aria-label', `${this.opts.label || 'Chart'}. Arrow keys step through the points; the Table button lists every value.`);
      this.plot.style.height = `${this.opts.height}px`;
      this.tip = tooltip(host);
      this.idx = null;
      this.data = null;
      this.plot.addEventListener('pointermove', (e) => this.pointAt(e.clientX));
      this.plot.addEventListener('pointerleave', () => this.clearHover());
      this.plot.addEventListener('focus', () => this.setIndex(this.lastIndex()));
      this.plot.addEventListener('blur', () => this.clearHover());
      this.plot.addEventListener('keydown', (e) => this.onKey(e));
      let lastWidth = 0;
      new ResizeObserver(() => {
        if (this.plot.clientWidth !== lastWidth) { lastWidth = this.plot.clientWidth; this.render(); }
      }).observe(this.plot);
    }

    update(data) {
      this.data = data;
      this.render();
      if (this.idx != null) this.setIndex(Math.min(this.idx, this.count() - 1));
    }

    count() { return this.data ? this.data.points : 0; }

    lastIndex() {
      const n = this.count();
      for (let i = n - 1; i >= 0; i--) if (this.hasData(i)) return i;
      return n - 1;
    }

    frame() {
      const w = Math.max(this.plot.clientWidth, 280);
      const h = this.opts.height;
      const m = { l: 64, r: 14, t: 12, b: 26 };
      return { w, h, m, pw: w - m.l - m.r, ph: h - m.t - m.b };
    }

    // axes draws gridlines, value labels and time labels, and returns the
    // value-to-y function.
    axes(g, f, max) {
      const { m, pw, ph } = f;
      const scale = niceScale(max, 4);
      const y = (v) => m.t + ph - (v / scale.max) * ph;
      const label = this.opts.axisFormat || this.opts.format;
      for (let v = 0; v <= scale.max + scale.step / 2; v += scale.step) {
        const yy = Math.round(y(v)) + 0.5;
        svgEl('line', { x1: m.l, x2: m.l + pw, y1: yy, y2: yy, class: v === 0 ? 'chart__base' : 'chart__grid' }, g);
        svgEl('text', { x: m.l - 10, y: yy, class: 'chart__ylabel', 'text-anchor': 'end', 'dominant-baseline': 'middle' }, g)
          .textContent = label(v);
      }
      const d = this.data;
      const end = d.start + d.points * d.step;
      for (const tick of timeTicks(d.start, end)) {
        const x = m.l + ((tick.t - d.start) / (end - d.start)) * pw;
        if (x < m.l + 16 || x > m.l + pw - 16) continue;
        svgEl('line', { x1: Math.round(x) + 0.5, x2: Math.round(x) + 0.5, y1: m.t + ph, y2: m.t + ph + 4, class: 'chart__base' }, g);
        svgEl('text', { x, y: m.t + ph + 18, class: 'chart__xlabel', 'text-anchor': 'middle' }, g).textContent = tick.label;
      }
      return y;
    }

    xOf(i, f) { return f.m.l + ((i + 0.5) / this.count()) * f.pw; }

    pointAt(clientX) {
      if (!this.data) return;
      const f = this.frame();
      const x = clientX - this.plot.getBoundingClientRect().left;
      const i = Math.floor(((x - f.m.l) / f.pw) * this.count());
      this.setIndex(Math.max(0, Math.min(this.count() - 1, i)));
    }

    onKey(e) {
      if (!this.data) return;
      const n = this.count();
      const moves = { ArrowLeft: -1, ArrowRight: 1, PageUp: -10, PageDown: 10 };
      if (e.key in moves) this.setIndex(Math.max(0, Math.min(n - 1, (this.idx ?? this.lastIndex()) + moves[e.key])));
      else if (e.key === 'Home') this.setIndex(0);
      else if (e.key === 'End') this.setIndex(this.lastIndex());
      else if (e.key === 'Escape') this.clearHover();
      else return;
      e.preventDefault();
    }

    clearHover() {
      this.idx = null;
      this.tip.hide();
      if (this.cross) this.cross.replaceChildren();
    }

    render() {
      if (!this.data) return;
      const f = this.frame();
      const svg = svgEl('svg', { width: f.w, height: f.h, viewBox: `0 0 ${f.w} ${f.h}`, class: 'chart__svg', 'aria-hidden': 'true' });
      const back = svgEl('g', {}, svg);
      const grid = svgEl('g', {}, svg);
      const marks = svgEl('g', {}, svg);
      this.cross = svgEl('g', {}, svg);
      const max = Math.max(this.maxValue(), this.opts.minMax || 0);
      this.y = this.axes(grid, f, max);
      this.back = back;
      this.draw(marks, f);
      this.plot.replaceChildren(svg);
      if (!this.anyData()) {
        el('div', 'chart__empty', this.plot, this.opts.empty);
      }
      this.f = f;
    }

    anyData() {
      for (let i = 0; i < this.count(); i++) if (this.hasData(i)) return true;
      return false;
    }
  }

  /* ---- lines with a light area ---- */
  class LineChart extends TimeChart {
    // data: { start, step, points, series: [{ label, color, values, area }], title(i) }
    hasData(i) { return this.data.series.some((s) => isNum(s.values[i])); }

    maxValue() {
      let max = 0;
      for (const s of this.data.series) for (const v of s.values) if (isNum(v) && v > max) max = v;
      return max;
    }

    draw(g, f) {
      const base = f.m.t + f.ph;
      for (const s of this.data.series) {
        let line = '';
        let area = '';
        let run = [];
        const flush = () => {
          if (run.length === 1) {
            const [x, y] = run[0];
            svgEl('circle', { cx: x, cy: y, r: 2, style: `fill:${s.color}` }, g);
          } else if (run.length > 1) {
            line += `M${run.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('L')}`;
            if (s.area) {
              area += `M${run[0][0].toFixed(1)},${base}L${run.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('L')}L${run[run.length - 1][0].toFixed(1)},${base}Z`;
            }
          }
          run = [];
        };
        s.values.forEach((v, i) => {
          if (isNum(v)) run.push([this.xOf(i, f), this.y(v)]);
          else flush();
        });
        flush();
        if (area) svgEl('path', { d: area, style: `fill:${s.color}`, class: 'chart__area' }, g);
        if (line) svgEl('path', { d: line, style: `stroke:${s.color}`, class: 'chart__line' }, g);
      }
    }

    setIndex(i) {
      if (!this.data || i == null || i < 0) return;
      this.idx = i;
      const f = this.f || this.frame();
      const x = this.xOf(i, f);
      this.cross.replaceChildren();
      svgEl('line', { x1: x, x2: x, y1: f.m.t, y2: f.m.t + f.ph, class: 'chart__cross' }, this.cross);
      const rows = [];
      for (const s of this.data.series) {
        const v = s.values[i];
        if (isNum(v)) {
          svgEl('circle', { cx: x, cy: this.y(v), r: 4, style: `fill:${s.color}`, class: 'chart__dot' }, this.cross);
        }
        rows.push({ label: s.label, value: isNum(v) ? this.opts.format(v) : 'no data', color: s.color, shape: 'line' });
      }
      const d = this.data;
      this.tip.show(d.title ? d.title(i) : spanLabel(d.start + i * d.step, d.step), rows, x, f.m.t);
    }
  }

  /* ---- stacked columns ---- */
  class ColumnChart extends TimeChart {
    // data: { start, step, points, series: [{ label, color, values }] (bottom first), rows(i) for the tooltip }
    hasData(i) { return this.data.series.some((s) => isNum(s.values[i])); }

    maxValue() {
      let max = 0;
      for (let i = 0; i < this.count(); i++) {
        let sum = 0;
        for (const s of this.data.series) if (isNum(s.values[i])) sum += s.values[i];
        max = Math.max(max, sum);
      }
      return max;
    }

    draw(g, f) {
      const n = this.count();
      const slot = f.pw / n;
      const bw = Math.max(1, Math.min(24, slot - 2));
      const base = f.m.t + f.ph;
      const r = Math.min(4, bw / 2);
      this.bw = bw;
      for (let i = 0; i < n; i++) {
        const x = f.m.l + i * slot + (slot - bw) / 2;
        let y0 = base;
        const visible = this.data.series.map((s) => s.values[i]).filter((v) => isNum(v) && v > 0).length;
        let drawn = 0;
        for (const s of this.data.series) {
          const v = s.values[i];
          if (!isNum(v) || v <= 0) continue;
          drawn++;
          const top = this.y(v) - (base - y0); // stack on what is below
          let h = y0 - top;
          const gap = drawn > 1 ? 2 : 0;
          h -= gap;
          const yb = y0 - gap;
          if (h < 0.5) { y0 = top; continue; }
          if (drawn === visible && h > r) {
            const yt = yb - h;
            svgEl('path', { d: `M${x},${yb}V${yt + r}Q${x},${yt} ${x + r},${yt}H${x + bw - r}Q${x + bw},${yt} ${x + bw},${yt + r}V${yb}Z`, style: `fill:${s.color}` }, g);
          } else {
            svgEl('rect', { x, y: yb - h, width: bw, height: h, style: `fill:${s.color}` }, g);
          }
          y0 = top;
        }
      }
    }

    setIndex(i) {
      if (!this.data || i == null || i < 0) return;
      this.idx = i;
      const f = this.f || this.frame();
      const slot = f.pw / this.count();
      const x = f.m.l + i * slot;
      this.cross.replaceChildren();
      svgEl('rect', { x: x + (slot - this.bw) / 2 - 3, y: f.m.t, width: this.bw + 6, height: f.ph, class: 'chart__colhover' }, this.back);
      if (this.hoverRect) this.hoverRect.remove();
      this.hoverRect = this.back.lastChild;
      const d = this.data;
      const rows = d.rows ? d.rows(i) : d.series.slice().reverse().map((s) => ({ label: s.label, value: isNum(s.values[i]) ? this.opts.format(s.values[i]) : 'no data', color: s.color, shape: 'box' }));
      this.tip.show(spanLabel(d.start + i * d.step, d.step), rows, x + slot / 2, f.m.t);
    }

    clearHover() {
      super.clearHover();
      if (this.hoverRect) { this.hoverRect.remove(); this.hoverRect = null; }
    }
  }

  /* ---- sparkline ---- */
  // sparkline returns an SVG of values (null for gaps), scaled to its own
  // maximum. Its colour is currentColor.
  function sparkline(values, opts) {
    const o = Object.assign({ width: 120, height: 32, area: true }, opts);
    const svg = svgEl('svg', { viewBox: `0 0 ${o.width} ${o.height}`, preserveAspectRatio: 'none', class: 'spark', 'aria-hidden': 'true' });
    const nums = values.filter(isNum);
    if (!nums.length) return svg;
    const max = Math.max(...nums) || 1;
    const n = values.length;
    const x = (i) => (n === 1 ? o.width / 2 : (i / (n - 1)) * o.width);
    const y = (v) => o.height - 2 - (v / max) * (o.height - 4);
    let line = '';
    let area = '';
    let run = [];
    const flush = () => {
      if (run.length > 1) {
        line += `M${run.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('L')}`;
        area += `M${run[0][0].toFixed(1)},${o.height}L${run.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('L')}L${run[run.length - 1][0].toFixed(1)},${o.height}Z`;
      }
      run = [];
    };
    values.forEach((v, i) => { if (isNum(v)) run.push([x(i), y(v)]); else flush(); });
    flush();
    if (o.area && area) svgEl('path', { d: area, class: 'spark__area' }, svg);
    if (line) svgEl('path', { d: line, class: 'spark__line' }, svg);
    return svg;
  }

  /* ---- bar list ---- */
  // barList renders ranked rows: label, value and a bar scaled to the largest.
  function barList(host, rows, opts) {
    const o = Object.assign({ empty: 'Nothing in this range.', format: fmt.count }, opts);
    host.replaceChildren();
    if (!rows.length) {
      el('div', 'barlist__empty', host, o.empty);
      return;
    }
    const max = Math.max(...rows.map((r) => r.value)) || 1;
    for (const r of rows) {
      const row = el('div', 'barlist__row', host);
      if (r.title) row.title = r.title;
      const head = el('div', 'barlist__head', row);
      const label = el('span', 'barlist__label', head, r.label);
      if (r.mono) label.classList.add('mono');
      if (r.note) el('span', 'barlist__note', head, r.note);
      el('span', 'barlist__value', head, o.format(r.value));
      const track = el('div', 'barlist__track', row);
      const bar = el('div', 'barlist__bar', track);
      bar.style.width = `${Math.max(r.value > 0 ? 1.5 : 0, (r.value / max) * 100)}%`;
    }
  }

  /* ---- share bar ---- */
  // shareBar renders one 100% bar with a legend of labels, shares and counts.
  function shareBar(host, parts, opts) {
    const o = Object.assign({ empty: 'Nothing in this range.', format: fmt.count }, opts);
    host.replaceChildren();
    const total = parts.reduce((a, p) => a + p.value, 0);
    if (!total) {
      el('div', 'barlist__empty', host, o.empty);
      return;
    }
    const bar = el('div', 'sharebar', host);
    for (const p of parts) {
      if (!p.value) continue;
      const seg = el('div', 'sharebar__seg', bar);
      seg.style.flexGrow = String(p.value);
      seg.style.background = p.color;
      seg.title = `${p.label}: ${fmt.pct((p.value / total) * 100)}`;
    }
    const legend = el('div', 'sharebar__legend', host);
    for (const p of parts) {
      const row = el('div', 'sharebar__row', legend);
      const key = el('span', 'chart__key chart__key--box', row);
      key.style.setProperty('--key', p.color);
      el('span', 'sharebar__label', row, p.label);
      el('span', 'sharebar__pct', row, fmt.pct((p.value / total) * 100));
      el('span', 'sharebar__count', row, o.format(p.value));
    }
  }

  /* ---- legend ---- */
  function legend(host, items) {
    host.replaceChildren();
    for (const it of items) {
      const row = el('span', 'legend__item', host);
      const key = el('span', `chart__key chart__key--${it.shape || 'line'}`, row);
      key.style.setProperty('--key', it.color);
      el('span', '', row, it.label);
    }
  }

  /* ---- table view ---- */
  // table renders the chart's data as rows, newest first: the accessible twin
  // of a chart, and the way to read exact values.
  function table(host, head, rows) {
    host.replaceChildren();
    const wrap = el('div', 'charttable', host);
    const t = el('table', 'table table--compact', wrap);
    const tr = el('tr', '', el('thead', '', t));
    head.forEach((h, i) => el('th', i ? 'num' : '', tr, h));
    const body = el('tbody', '', t);
    for (const r of rows) {
      const row = el('tr', '', body);
      r.forEach((c, i) => el('td', i ? 'num mono' : 'mono', row, c));
    }
  }

  return { LineChart, ColumnChart, sparkline, barList, shareBar, legend, table, fmt, spanLabel, niceScale };
})();
