/* Shared client-side utilities, loaded on every page. */

/**
 * Escapes a string for safe insertion into innerHTML. Every page in this
 * app builds table rows via template literals like `<td>${value}</td>`,
 * and MANY of those values come from log messages, case notes, Sigma
 * rule titles/descriptions, and other places an attacker (or just a
 * weird log message) could put HTML/script content. Without escaping,
 * that content executes in the analyst's browser - a stored XSS.
 *
 * Also safe to use inside HTML attributes (value="...", title="...") -
 * the textContent -> innerHTML trick alone reliably escapes < > & but
 * NOT quote characters (they're not dangerous in plain text content,
 * only in attribute values), so quotes are explicitly handled too.
 *
 * Rule of thumb used throughout this app: wrap ANY value in escapeHtml()
 * before interpolating it into an HTML string, UNLESS it's a value this
 * app generated itself from a fixed, known set of options (e.g. a
 * severity level, a status string) - not something that ever holds a
 * log message, note, title, description, or anything else free-text.
 */
function escapeHtml(value){
  if (value === null || value === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(value);
  return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * For embedding a value inside an inline event handler's JS string literal,
 * e.g. onclick="doThing('${escapeJsAttr(value)}')" - escapeHtml() alone is
 * NOT safe here. The browser HTML-decodes the attribute value BEFORE the
 * JS engine parses it as code, so an HTML-entity-escaped quote (&#39;)
 * gets decoded back into a literal quote by the time JS sees it - which
 * re-opens the exact string-breakout this is trying to prevent. This
 * needs the single quote backslash-escaped (survives HTML decoding as a
 * literal two-character sequence, correctly escaping the JS string), and
 * the double quote HTML-entity-escaped (needed since the outer attribute
 * itself is double-quoted).
 */
function escapeJsAttr(value){
  if (value === null || value === undefined) return '';
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Shared timestamp formatter - identical logic was duplicated on every
 * page; centralizing it here also means any future fix only needs to
 * happen once. */
function fmtTime(iso){
  if (!iso) return '-';
  const d = new Date(iso + 'Z');
  return d.toLocaleString([], {month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'});
}
