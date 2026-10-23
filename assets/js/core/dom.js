// Tiny DOM helpers and a deliberately small Markdown subset for lesson text:
// paragraphs, lists, `code`, **bold**, *emphasis*, [links](url) and ==highlights==.

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs ?? {})) {
    if (value === false || value === null || value === undefined) continue;
    if (key === 'class') el.className = value;
    else if (key === 'html') el.innerHTML = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function inline(source) {
  const codes = [];
  let out = escapeHtml(source).replace(/`([^`]+)`/g, (_, code) => {
    codes.push(`<code>${code}</code>`);
    return `\u0000${codes.length - 1}\u0000`;
  });
  out = out
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\s][^*]*?)\*/g, '$1<em>$2</em>')
    .replace(/==(.+?)==/g, '<mark>$1</mark>')
    .replace(/\[([^\]]+)\]\(((?:https?:\/\/|#\/)[^)\s]+)\)/g, (_, label, href) => {
      const external = href.startsWith('http');
      return `<a href="${href}"${external ? ' rel="noopener noreferrer" target="_blank"' : ''}>${label}</a>`;
    });
  return out.replace(/\u0000(\d+)\u0000/g, (_, i) => codes[Number(i)]);
}

export function md(source) {
  const blocks = String(source ?? '').trim().split(/\n\s*\n/);
  return blocks
    .map((block) => {
      const lines = block.split('\n');
      if (lines.every((line) => /^\s*[-*] /.test(line))) {
        return `<ul>${lines.map((line) => `<li>${inline(line.replace(/^\s*[-*] /, ''))}</li>`).join('')}</ul>`;
      }
      if (lines.every((line) => /^\s*\d+\. /.test(line))) {
        return `<ol>${lines.map((line) => `<li>${inline(line.replace(/^\s*\d+\. /, ''))}</li>`).join('')}</ol>`;
      }
      return `<p>${inline(lines.join(' '))}</p>`;
    })
    .join('');
}

export function mdNode(source, tag = 'div', className = 'prose') {
  return h(tag, { class: className, html: md(source) });
}

export function announce(message) {
  const region = document.getElementById('announcer');
  if (!region) return;
  region.textContent = '';
  requestAnimationFrame(() => {
    region.textContent = message;
  });
}

export async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

export function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
