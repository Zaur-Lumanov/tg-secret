import { keyVisualizationBytes } from "tg-secret-core";

/** The key visualization of official clients, drawn in the terminal (24-bit colors). */
const COLORS: [number, number, number][] = [
  [0xff, 0xff, 0xff],
  [0xd5, 0xe6, 0xf3],
  [0x2d, 0x57, 0x75],
  [0x2f, 0x99, 0xc9],
];

export function renderIdenticon(key: Buffer): string[] {
  const data = keyVisualizationBytes(key);
  const rows: string[] = [];
  let bit = 0;
  for (let y = 0; y < 12; y++) {
    let row = "";
    for (let x = 0; x < 12; x++) {
      const v = (data[bit >> 3] >> (bit % 8)) & 0x3;
      bit += 2;
      const [r, g, b] = COLORS[v];
      row += `\x1b[48;2;${r};${g};${b}m  `;
    }
    rows.push(row + "\x1b[0m");
  }
  return rows;
}

export function renderKeyHex(key: Buffer): string[] {
  const hex = keyVisualizationBytes(key).toString("hex");
  const groups = hex.match(/.{8}/g) ?? [];
  const rows: string[] = [];
  for (let i = 0; i < groups.length; i += 3) rows.push(groups.slice(i, i + 3).join(" "));
  return rows;
}
