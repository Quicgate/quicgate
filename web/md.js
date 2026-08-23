/* Minimal markdown renderer for the built-in guides. Covers exactly what the
   docs use: headings, paragraphs, bold/italic/inline code, links, fenced code
   blocks, unordered + ordered lists, tables, blockquotes and hr. Everything is
   HTML-escaped first, so the renderer never injects markup from the source. */
'use strict';

function mdEscape(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Inline spans: code first (its content is literal), then bold, italic, links.
function mdInline(s) {
  let out = '';
  const parts = s.split(/(`[^`]*`)/);
  for (const part of parts) {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 1) {
      out += '<code>' + part.slice(1, -1) + '</code>';
      continue;
    }
    let t = part;
    t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    t = t.replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
    t = t.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, text, href) => {
      // Same-directory .md links navigate between guides in-app.
      if (/^[\w-]+\.md$/.test(href)) return `<a href="#" data-guide="${href.slice(0, -3)}">${text}</a>`;
      if (/^https?:\/\//.test(href)) return `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
      return `<a href="${href}">${text}</a>`;
    });
    out += t;
  }
  return out;
}

function renderMarkdown(src) {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  let i = 0;
  let para = [];
  const flushPara = () => {
    if (para.length) {
      html.push('<p>' + mdInline(para.join(' ')) + '</p>');
      para = [];
    }
  };
  while (i < lines.length) {
    const raw = lines[i];
    const line = mdEscape(raw);

    if (raw.startsWith('```')) {
      flushPara();
      const code = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) code.push(mdEscape(lines[i++]));
      i++; // closing fence
      html.push('<pre><code>' + code.join('\n') + '</code></pre>');
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      flushPara();
      const level = h[1].length;
      html.push(`<h${level}>` + mdInline(h[2]) + `</h${level}>`);
      i++;
      continue;
    }
    if (/^(-{3,}|\*{3,})\s*$/.test(raw)) {
      flushPara();
      html.push('<hr>');
      i++;
      continue;
    }
    if (raw.startsWith('|')) {
      flushPara();
      const rows = [];
      while (i < lines.length && lines[i].startsWith('|')) {
        const cells = mdEscape(lines[i]).replace(/^\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
        rows.push(cells);
        i++;
      }
      const sep = rows.length > 1 && rows[1].every((c) => /^:?-+:?$/.test(c) || c === '');
      let t = '<div class="md-tablewrap"><table>';
      rows.forEach((cells, idx) => {
        if (sep && idx === 1) return;
        const tag = sep && idx === 0 ? 'th' : 'td';
        t += '<tr>' + cells.map((c) => `<${tag}>` + mdInline(c) + `</${tag}>`).join('') + '</tr>';
      });
      t += '</table></div>';
      html.push(t);
      continue;
    }
    const li = raw.match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
    if (li) {
      flushPara();
      const ordered = /^\d+\.$/.test(li[2]);
      const tag = ordered ? 'ol' : 'ul';
      const items = [];
      while (i < lines.length) {
        const m = lines[i].match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
        if (!m || /^\d+\.$/.test(m[2]) !== ordered) break;
        let item = m[3];
        i++;
        // Continuation lines indented under the same item.
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !lines[i].match(/^(\s*)([-*]|\d+\.)\s/)) {
          item += ' ' + lines[i].trim();
          i++;
        }
        items.push('<li>' + mdInline(mdEscape(item)) + '</li>');
      }
      html.push(`<${tag}>` + items.join('') + `</${tag}>`);
      continue;
    }
    if (raw.startsWith('>')) {
      flushPara();
      const quote = [];
      while (i < lines.length && lines[i].startsWith('>')) {
        quote.push(mdEscape(lines[i].replace(/^>\s?/, '')));
        i++;
      }
      html.push('<blockquote><p>' + mdInline(quote.join(' ')) + '</p></blockquote>');
      continue;
    }
    if (raw.trim() === '') {
      flushPara();
      i++;
      continue;
    }
    para.push(line);
    i++;
  }
  flushPara();
  return html.join('\n');
}
