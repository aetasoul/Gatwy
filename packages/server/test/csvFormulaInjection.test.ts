import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { neutralizeCsvFormula, rowsToCsv } from '../src/services/csv.js';

describe('rowsToCsv (database export)', () => {
  it('neutralises formula-looking strings in the header and in the cells', () => {
    const csv = rowsToCsv(['id', '=evil'], [[1, '=1+1'], [2, '@SUM(A1)'], [3, '-cmd']]);
    assert.equal(csv, ["id,'=evil", "1,'=1+1", "2,'@SUM(A1)", "3,'-cmd"].join('\n'));
  });

  it('keeps numbers, booleans, nulls and dates as data', () => {
    const d = new Date('2026-10-07T10:00:00.000Z');
    const csv = rowsToCsv(['n', 'b', 'x', 'd'], [[-5, true, null, d]]);
    assert.equal(csv, 'n,b,x,d\n-5,true,,2026-10-07T10:00:00.000Z');
  });

  it('keeps negative numeric strings from DECIMAL/numeric columns intact', () => {
    assert.equal(rowsToCsv(['amount'], [['-12.50'], ['+5']]), 'amount\n-12.50\n+5');
  });

  it('still quotes commas, quotes and newlines, after neutralising', () => {
    const csv = rowsToCsv(['v'], [['=a,"b"'], ['line1\nline2']]);
    assert.equal(csv, 'v\n"\'=a,""b"""\n"line1\nline2"');
  });
});

describe('neutralizeCsvFormula', () => {
  for (const lead of ['=', '+', '-', '@', '\t', '\r']) {
    it(`prefixes a cell starting with ${JSON.stringify(lead)}`, () => {
      const cell = `${lead}HYPERLINK("http://evil.example","x")`;
      assert.equal(neutralizeCsvFormula(cell), `'${cell}`);
    });
  }

  it('leaves ordinary text untouched', () => {
    for (const cell of ['', 'report.txt', '/home/user/=file', 'a=b', 'x-y', '{"size":1}']) {
      assert.equal(neutralizeCsvFormula(cell), cell);
    }
  });

  it('only looks at the first character', () => {
    assert.equal(neutralizeCsvFormula(' =1+1'), ' =1+1');
  });

  it('leaves plain numeric strings alone (pg numeric/int8, mysql DECIMAL arrive as strings)', () => {
    for (const cell of ['-12.50', '+5', '-5', '-.5', '+1e5', '-3.', '-9007199254740993']) {
      assert.equal(neutralizeCsvFormula(cell), cell);
    }
  });

  it('still prefixes numeric-looking text that is a formula', () => {
    for (const cell of ['-1+1', '+5-2', '-12.50,3', '-5\t', '-', '+', '=5', '-1e', '--5']) {
      assert.equal(neutralizeCsvFormula(cell), `'${cell}`);
    }
  });
});
