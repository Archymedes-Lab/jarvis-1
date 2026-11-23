// The /procs grid: where each process stands, as a pure function of the table.
// No DOM and no WebGL, so tests/test_procs_page.py runs it in Node.
//
//   domain   one district per operating system, side by side along x
//            (Windows first, then the Linux guest).
//   block    inside a district, one block per family: the processes that
//            share a parent program. Families smaller than MIN_FAMILY share
//            one "other" block, so a host with many singletons stays compact.
//            A family key that starts with '#' (missing watched processes)
//            always keeps its own block, first in its district.
//   cell     inside a block, processes fill rows in start order (created,
//            then id), so a new process takes the next free cell and nothing
//            else moves unless its block needs another column or row.
//
// Blocks are packed by a skyline: each takes the lowest free spot, leftmost
// first, in a district of fixed width (a multiple of four).
//
// Guarantees (tested): deterministic for any input order, one item per cell,
// blocks never overlap, every cell lies inside its block and district, and a
// district's side grows like the square root of its item count.

export const MIN_FAMILY = 3;
export const BLOCK_GAP = 1;      // empty cells between blocks
export const DOMAIN_GAP = 4;     // empty cells between districts
export const OTHER = '';         // the family key for small families

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const byStart = (a, b) => (a.order - b.order) || cmp(a.id, b.id);

// Block placement order: pinned ('#') blocks first, then taller blocks first
// (so the skyline packs tightly and rarely changes), then by key; "other" last.
function blockOrder(a, b) {
  const pa = a.key.startsWith('#'), pb = b.key.startsWith('#');
  if (pa !== pb) return pa ? -1 : 1;
  const oa = a.key === OTHER, ob = b.key === OTHER;
  if (oa !== ob) return oa ? 1 : -1;
  return (b.rows - a.rows) || (b.cols - a.cols) || cmp(a.key, b.key);
}

// items: [{ id, h, family, order }]. Returns
//   cells:   Map id -> { h, col, row, block }   (absolute grid coordinates)
//   blocks:  [{ h, key, col, row, cols, rows, n }]
//   domains: { h: { col, row, cols, rows, n } } for hosts with items
export function gridLayout(items, { hosts = ['win', 'lin'], minFamily = MIN_FAMILY } = {}) {
  const cells = new Map();
  const blocks = [];
  const domains = {};
  let originCol = 0;
  for (const h of hosts) {
    const mine = items.filter((it) => it.h === h);
    if (!mine.length) continue;
    // families, with the small ones folded into "other"
    const fam = new Map();
    for (const it of mine) {
      const k = String(it.family ?? OTHER);
      if (!fam.has(k)) fam.set(k, []);
      fam.get(k).push(it);
    }
    const groups = new Map();
    for (const [k, list] of fam) {
      const key = k.startsWith('#') || list.length >= minFamily ? k : OTHER;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(...list);
    }
    const own = [];
    for (const [key, list] of groups) {
      list.sort(byStart);
      const cols = Math.ceil(Math.sqrt(list.length));
      own.push({ h, key, list, cols, rows: Math.ceil(list.length / cols), n: list.length });
    }
    own.sort(blockOrder);
    // district width: near square, rounded up to a multiple of four so that
    // small changes in the table do not change it
    let area = 0, widest = 0;
    for (const b of own) { area += (b.cols + BLOCK_GAP) * (b.rows + BLOCK_GAP); widest = Math.max(widest, b.cols); }
    const width = Math.max(widest, Math.ceil(Math.sqrt(area) * 1.08 / 4) * 4);
    // skyline packing: each block takes the lowest free spot (then the leftmost)
    const sky = new Array(width).fill(0);
    let usedCols = 0, usedRows = 0;
    for (const b of own) {
      let bestX = 0, bestZ = Infinity;
      for (let x = 0; x + b.cols <= width; x++) {
        let z = 0;
        for (let i = x; i < x + b.cols; i++) z = Math.max(z, sky[i]);
        if (z < bestZ) { bestZ = z; bestX = x; }
      }
      b.col = originCol + bestX; b.row = bestZ;
      for (let i = bestX; i < Math.min(width, bestX + b.cols + BLOCK_GAP); i++) sky[i] = bestZ + b.rows + BLOCK_GAP;
      b.list.forEach((it, i) => {
        cells.set(it.id, { h, col: b.col + (i % b.cols), row: b.row + Math.floor(i / b.cols), block: blocks.length });
      });
      usedCols = Math.max(usedCols, bestX + b.cols);
      usedRows = Math.max(usedRows, bestZ + b.rows);
      blocks.push({ h, key: b.key, col: b.col, row: b.row, cols: b.cols, rows: b.rows, n: b.n });
    }
    domains[h] = { col: originCol, row: 0, cols: usedCols, rows: usedRows, n: mine.length };
    originCol += usedCols + DOMAIN_GAP;
  }
  return { cells, blocks, domains };
}

// The family of a process: its parent's name (lower case, a trailing pid
// folded), or '(no parent)' when the parent has exited or its pid was reused.
export function familyOf(parent) {
  if (!parent) return '(no parent)';
  return String(parent.name || '?').trim().toLowerCase().replace(/\(\d+\)$/, '(#)');
}

// Height of a cube in cells for a CPU share (percent of the whole machine):
// square root, so a 1% load is visible and order is kept. FLOOR_H is idle.
export const FLOOR_H = 0.18, MAX_H = 7.5;
export function cpuHeight(cpu) {
  const c = Math.max(0, Math.min(100, +cpu || 0));
  return FLOOR_H + (MAX_H - FLOOR_H) * Math.sqrt(c / 100);
}

// Footprint (side, in cells) for resident memory in KB: log scale between
// 0.34 (a few KB) and 0.92 (16 GB and above).
export function memSide(kb) {
  const k = Math.max(1, +kb || 1);
  const t = Math.min(1, Math.log2(k) / 24);
  return 0.34 + 0.58 * t;
}
