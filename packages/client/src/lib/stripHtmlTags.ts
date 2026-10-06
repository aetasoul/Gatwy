/** Removes `<...>` spans the same way `s.replace(/<[^>]+>/g, '')` does, without a regex. */
export function stripHtmlTags(html: string): string {
  let out = '';
  let i = 0;
  while (i < html.length) {
    if (html[i] === '<') {
      const end = html.indexOf('>', i + 1);
      if (end > i + 1) {
        i = end + 1;
        continue;
      }
    }
    out += html[i++];
  }
  return out;
}
