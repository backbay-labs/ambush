import * as React from "react";

export type TableToggleProps = {
  rows: Record<string, string | number>[];
  caption: string;
  label: string;
};

/**
 * The table behind every chart.
 *
 * Mandatory, not a progressive enhancement. A chart is a lossy rendering — it
 * truncates ids, rounds numbers, and drops nodes above a cap — so the table is
 * the only place the underlying values are complete. It is also the only way
 * this figure is readable by a screen reader or copyable into a report.
 *
 * Columns are the union of every row's keys in first-seen order, so a row
 * missing a field renders an empty cell rather than shifting every cell after
 * it into the wrong column.
 */
export function TableToggle({
  rows,
  caption,
  label,
}: TableToggleProps): React.ReactElement {
  const columns = React.useMemo(() => {
    const seen: string[] = [];
    for (const row of rows) {
      for (const key of Object.keys(row)) {
        if (!seen.includes(key)) seen.push(key);
      }
    }
    return seen;
  }, [rows]);

  return (
    <details className="mt-2">
      <summary className="cursor-pointer text-xs text-muted-foreground">
        {label}
      </summary>
      <div className="mt-1 overflow-x-auto">
        <table data-testid="perch-viz-table" className="text-xs">
          <caption className="text-left text-xs text-muted-foreground">
            {caption}
          </caption>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column} className="pr-3 text-left font-normal">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              // Rows have no stable id of their own; the caller's order IS the
              // identity here, and the table never reorders.
              // biome-ignore lint/suspicious/noArrayIndexKey: row order is the identity
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column} className="pr-3">
                    {row[column] ?? ""}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
