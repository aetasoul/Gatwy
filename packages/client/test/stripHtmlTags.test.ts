import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { stripHtmlTags } from '../src/lib/stripHtmlTags.js';

// split/join removes the same matches as the previous replace() call.
const reference = (s: string) => s.split(/<[^>]+>/g).join('');

describe('stripHtmlTags', () => {
  it('removes tags and keeps text', () => {
    assert.equal(stripHtmlTags('<b>bold</b> and <i>italic</i>'), 'bold and italic');
    assert.equal(stripHtmlTags('<p class="x">a\nb</p>'), 'a\nb');
  });

  it('leaves an unclosed or empty angle bracket as text', () => {
    assert.equal(stripHtmlTags('1 < 2'), '1 < 2');
    assert.equal(stripHtmlTags('a <> b'), 'a <> b');
    assert.equal(stripHtmlTags('x <y'), 'x <y');
  });

  it('does not reassemble a script tag from nested fragments', () => {
    for (const input of ['<scr<script>ipt>alert(1)', '<<script>script>', '<scr<!-- -->ipt>', 'a<<b>script>c']) {
      assert.doesNotMatch(stripHtmlTags(input), /<script/i, input);
    }
  });

  it('matches the previous regex on every string over a small alphabet', () => {
    const alphabet = ['<', '>', 'a', ' ', '/', '\n', '&'];
    let checked = 0;
    const walk = (prefix: string, depth: number) => {
      assert.equal(stripHtmlTags(prefix), reference(prefix), JSON.stringify(prefix));
      checked++;
      if (depth === 0) return;
      for (const ch of alphabet) walk(prefix + ch, depth - 1);
    };
    walk('', 7);
    assert.ok(checked > 100000);
  });
});
