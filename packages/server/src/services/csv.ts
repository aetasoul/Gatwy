/**
 * Neutralise spreadsheet formula injection (CSV injection) in a text cell.
 *
 * Excel, LibreOffice and Google Sheets evaluate a cell that starts with `=`, `+`, `-`, `@`,
 * tab or carriage return as a formula, even inside a quoted CSV field. Values such as a remote
 * file name or a database column are attacker-controlled, so prefix them with a single quote,
 * which spreadsheets treat as "this is text". Apply it to strings only: a numeric `-5` is data.
 */
export function neutralizeCsvFormula(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  let s = v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (typeof v === 'string') s = neutralizeCsvFormula(s);
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Build a CSV document from a header row and data rows (database query results). */
export function rowsToCsv(columns: string[], rows: unknown[][]): string {
  return [columns.map(csvCell).join(','), ...rows.map((r) => r.map(csvCell).join(','))].join('\n');
}
