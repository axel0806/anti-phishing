const FORMULA_START = /^[=+\-@\t\r]/;
const NEEDS_QUOTES = /[",\n\r]/;

function cell(v: unknown): string {
  if (v === null || v === undefined) return "";
  let s = v instanceof Date ? v.toISOString() : Array.isArray(v) ? v.join(" ") : String(v);
  // Spreadsheet apps run cells that start with = + - @ as formulas, and sender addresses and flag evidence are attacker-controlled.
  if (typeof v === "string" && FORMULA_START.test(s)) s = "'" + s;
  return NEEDS_QUOTES.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

/** RFC 4180 CSV with formula neutralisation. Columns default to the first row's keys. */
export function toCsv(rows: Record<string, unknown>[], columns?: string[]): string {
  const cols = columns ?? Object.keys(rows[0] ?? {});
  const lines = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))];
  return lines.join("\n") + (rows.length ? "" : "\n");
}
