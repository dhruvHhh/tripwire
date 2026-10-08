// Generates the extension icons in icons/ from logo.png.
//
//   node tools/make-icons.js
//   node tools/make-icons.js --preview preview.png   (also writes a contact sheet)
//
// A development tool: nothing here ships with the extension, and it needs
// nothing but Node (it reads and writes PNG files itself).
//
// A plain downscale of the logo makes poor small icons, for two reasons this
// script works around:
//   - The chain links are white with a hairline outline. Shrunk, the outline
//     vanishes and the links disappear on a light toolbar. Each size redraws
//     the outline at a width that survives.
//   - At 16 and 32 px the warning triangle and its "!" are too small to read.
//     Those sizes enlarge the triangle, drop the spark marks, and place the
//     "!" on whole pixels. They favour legibility over matching the logo.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const ROOT = path.join(__dirname, '..');
const SOURCE = path.join(ROOT, 'logo.png');
const OUTPUT_DIR = path.join(ROOT, 'icons');

// Each output pixel is worked out from SUPERSAMPLE x SUPERSAMPLE samples.
const SUPERSAMPLE = 8;

const COLORS = {
  link: [255, 255, 255],
  outline: [112, 117, 122],
  warning: [234, 53, 48],
};

// size:      width and height of the PNG.
// box:       the artwork is fitted inside a centered box this big; the rest
//            is transparent padding.
// outline:   width of the outline drawn around the links, in output pixels.
// linkColor: colour of the links, if not the logo's white.
// grow:      how much the links are thickened, in output pixels.
// triangle:  how much the warning triangle is enlarged about its centre.
// gap:       transparent margin kept around the triangle, in output pixels.
// sparks:    whether the small spark marks are drawn.
// snapMark:  draw the "!" on whole pixels instead of sampling it.
// harden:    steepen edge anti-aliasing for a crisper look.
const RECIPES = [
  // At 16 px a white band with an outline on each side turns to mush, so the
  // links are one solid grey that shows on light and dark toolbars alike.
  { size: 16, box: 16, outline: 0, linkColor: [134, 139, 144], grow: 0.4, triangle: 1.75, gap: 1, sparks: false, snapMark: true, harden: true },
  { size: 32, box: 32, outline: 1, triangle: 1.5, gap: 1, sparks: false, snapMark: true, harden: true },
  { size: 48, box: 46, outline: 1, triangle: 1, gap: 0, sparks: true, snapMark: false, harden: false },
  // Chrome Web Store: 128x128 with the artwork in the middle 96x96.
  { size: 128, box: 96, outline: 1.5, triangle: 1, gap: 0, sparks: true, snapMark: false, harden: false },
];

// --- PNG reading and writing --------------------------------------------------

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// Returns { width, height, data } with data as RGBA bytes.
function readPng(file) {
  const buffer = fs.readFileSync(file);
  if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error(`${file} is not a PNG`);

  let header = null;
  const idat = [];
  for (let offset = 8; offset < buffer.length; ) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('latin1', offset + 4, offset + 8);
    const body = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      header = {
        width: body.readUInt32BE(0),
        height: body.readUInt32BE(4),
        bitDepth: body[8],
        colorType: body[9],
        interlace: body[12],
      };
    } else if (type === 'IDAT') {
      idat.push(body);
    }
    offset += 12 + length;
  }

  const channels = { 2: 3, 6: 4 }[header.colorType];
  if (header.bitDepth !== 8 || !channels || header.interlace !== 0) {
    throw new Error('logo.png must be an 8-bit, non-interlaced RGB or RGBA PNG');
  }

  const { width, height } = header;
  const stride = width * channels;
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const pixels = Buffer.alloc(stride * height);

  // Undo the per-row filters.
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const rowIn = y * (stride + 1) + 1;
    const rowOut = y * stride;
    for (let i = 0; i < stride; i++) {
      const left = i >= channels ? pixels[rowOut + i - channels] : 0;
      const up = y > 0 ? pixels[rowOut - stride + i] : 0;
      const upLeft = y > 0 && i >= channels ? pixels[rowOut - stride + i - channels] : 0;
      let predicted = 0;
      if (filter === 1) predicted = left;
      else if (filter === 2) predicted = up;
      else if (filter === 3) predicted = (left + up) >> 1;
      else if (filter === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        predicted = pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
      }
      pixels[rowOut + i] = (raw[rowIn + i] + predicted) & 0xff;
    }
  }

  if (channels === 4) return { width, height, data: pixels };
  const data = Buffer.alloc(width * height * 4, 255);
  for (let i = 0; i < width * height; i++) pixels.copy(data, i * 4, i * 3, i * 3 + 3);
  return { width, height, data };
}

function writePng(file, { width, height, data }) {
  const chunk = (type, body) => {
    const out = Buffer.alloc(12 + body.length);
    out.writeUInt32BE(body.length, 0);
    out.write(type, 4, 'latin1');
    body.copy(out, 8);
    out.writeUInt32BE(crc32(out.subarray(4, 8 + body.length)), 8 + body.length);
    return out;
  };

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height); // Filter byte 0 on every row.
  for (let y = 0; y < height; y++) data.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);

  fs.writeFileSync(
    file,
    Buffer.concat([
      PNG_SIGNATURE,
      chunk('IHDR', header),
      chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
      chunk('IEND', Buffer.alloc(0)),
    ]),
  );
}

// --- Taking the logo apart ----------------------------------------------------

// Anything fainter than this is leftover haze from background removal.
const MIN_ALPHA = 16;

// A summed-area table: the average of any rectangle of `values` in O(1).
function createAverager(values, width, height) {
  const sums = new Float64Array((width + 1) * (height + 1));
  for (let y = 0; y < height; y++) {
    let row = 0;
    for (let x = 0; x < width; x++) {
      row += values[y * width + x];
      sums[(y + 1) * (width + 1) + x + 1] = sums[y * (width + 1) + x + 1] + row;
    }
  }
  // Average over [x0, x1) x [y0, y1), in whole source pixels, clipped to the image.
  return (x0, y0, x1, y1) => {
    const area = (x1 - x0) * (y1 - y0);
    x0 = Math.max(0, Math.min(width, x0));
    x1 = Math.max(0, Math.min(width, x1));
    y0 = Math.max(0, Math.min(height, y0));
    y1 = Math.max(0, Math.min(height, y1));
    if (x1 <= x0 || y1 <= y0) return 0;
    const w = width + 1;
    return (sums[y1 * w + x1] - sums[y0 * w + x1] - sums[y1 * w + x0] + sums[y0 * w + x0]) / area;
  };
}

// Labels 4-connected groups of non-zero cells. Returns { labels, groups }
// with one { id, count, left, top, right, bottom } per group.
function findGroups(mask, width, height) {
  const labels = new Int32Array(width * height);
  const groups = [];
  const stack = [];
  for (let start = 0; start < mask.length; start++) {
    if (!mask[start] || labels[start]) continue;
    const group = { id: groups.length + 1, count: 0, left: width, top: height, right: 0, bottom: 0 };
    groups.push(group);
    labels[start] = group.id;
    stack.push(start);
    while (stack.length > 0) {
      const index = stack.pop();
      const x = index % width;
      const y = (index - x) / width;
      group.count++;
      group.left = Math.min(group.left, x);
      group.right = Math.max(group.right, x + 1);
      group.top = Math.min(group.top, y);
      group.bottom = Math.max(group.bottom, y + 1);
      for (const next of [index - 1, index + 1, index - width, index + width]) {
        if (next < 0 || next >= mask.length || labels[next] || !mask[next]) continue;
        if (Math.abs((next % width) - x) > 1) continue; // Wrapped around a row end.
        labels[next] = group.id;
        stack.push(next);
      }
    }
  }
  return { labels, groups };
}

// Splits the logo into its parts: the white links, the red triangle (with the
// "!" both cut out and filled in), and the red spark marks.
function analyseLogo(logo) {
  const { width, height, data } = logo;
  const count = width * height;
  const links = new Float32Array(count);
  const red = new Float32Array(count);

  for (let i = 0; i < count; i++) {
    const alpha = data[i * 4 + 3];
    if (alpha < MIN_ALPHA) continue;
    const isRed = data[i * 4] - data[i * 4 + 1] > 80;
    (isRed ? red : links)[i] = alpha / 255;
  }

  // The triangle is the biggest red shape; the rest are sparks.
  const { labels, groups } = findGroups(red, width, height);
  const triangleGroup = groups.reduce((a, b) => (b.count > a.count ? b : a));
  const triangle = new Float32Array(count);
  const sparks = new Float32Array(count);
  for (let i = 0; i < count; i++) {
    if (labels[i] === triangleGroup.id) triangle[i] = red[i];
    else if (labels[i]) sparks[i] = red[i];
  }

  // The "!" is whatever inside the triangle can't be reached from outside it.
  const { left, top, right, bottom } = triangleGroup;
  const boxWidth = right - left + 2;
  const boxHeight = bottom - top + 2;
  const open = new Uint8Array(boxWidth * boxHeight);
  for (let y = 0; y < boxHeight; y++) {
    for (let x = 0; x < boxWidth; x++) {
      const sx = left - 1 + x;
      const sy = top - 1 + y;
      open[y * boxWidth + x] = triangle[sy * width + sx] < 0.5 ? 1 : 0;
    }
  }
  const openGroups = findGroups(open, boxWidth, boxHeight);
  const outsideId = openGroups.labels[0];
  const markParts = openGroups.groups
    .filter((group) => group.id !== outsideId && group.count > 20)
    .map((group) => ({
      left: group.left + left - 1,
      right: group.right + left - 1,
      top: group.top + top - 1,
      bottom: group.bottom + top - 1,
    }))
    .sort((a, b) => a.top - b.top);
  if (markParts.length !== 2) throw new Error('Expected the triangle to contain a two-part "!"');

  const filled = Float32Array.from(triangle);
  for (let y = 0; y < boxHeight; y++) {
    for (let x = 0; x < boxWidth; x++) {
      const id = openGroups.labels[y * boxWidth + x];
      if (id && id !== outsideId) filled[(top - 1 + y) * width + left - 1 + x] = 1;
    }
  }

  // Bounds of everything, and of everything except the sparks.
  const boundsOf = (...masks) => {
    const b = { left: width, top: height, right: 0, bottom: 0 };
    for (let i = 0; i < count; i++) {
      if (!masks.some((mask) => mask[i] >= 0.25)) continue;
      const x = i % width;
      const y = (i - x) / width;
      b.left = Math.min(b.left, x);
      b.right = Math.max(b.right, x + 1);
      b.top = Math.min(b.top, y);
      b.bottom = Math.max(b.bottom, y + 1);
    }
    return b;
  };

  return {
    width,
    height,
    sample: {
      links: createAverager(links, width, height),
      triangle: createAverager(triangle, width, height),
      filledTriangle: createAverager(filled, width, height),
      sparks: createAverager(sparks, width, height),
    },
    bounds: { all: boundsOf(links, triangle, sparks), withoutSparks: boundsOf(links, triangle) },
    triangle: { left, top, right, bottom, cx: (left + right) / 2, cy: (top + bottom) / 2 },
    mark: { stem: markParts[0], dot: markParts[1] },
  };
}

// --- Drawing one icon ---------------------------------------------------------

// Squared distance from every cell to the nearest set cell (Felzenszwalb and
// Huttenlocher's two-pass transform).
function squaredDistances(isSet, size) {
  const INF = 1e12;
  const grid = new Float64Array(size * size);
  for (let i = 0; i < grid.length; i++) grid[i] = isSet[i] ? 0 : INF;

  const line = new Float64Array(size);
  const result = new Float64Array(size);
  const hull = new Int32Array(size);
  const breaks = new Float64Array(size + 1);

  const transformLine = () => {
    let k = 0;
    hull[0] = 0;
    breaks[0] = -INF;
    breaks[1] = INF;
    for (let q = 1; q < size; q++) {
      let s;
      do {
        const p = hull[k];
        s = (line[q] + q * q - (line[p] + p * p)) / (2 * q - 2 * p);
      } while (s <= breaks[k] && --k >= 0);
      k++;
      hull[k] = q;
      breaks[k] = s;
      breaks[k + 1] = INF;
    }
    k = 0;
    for (let q = 0; q < size; q++) {
      while (breaks[k + 1] < q) k++;
      const p = hull[k];
      result[q] = (q - p) * (q - p) + line[p];
    }
  };

  for (let x = 0; x < size; x++) {
    for (let y = 0; y < size; y++) line[y] = grid[y * size + x];
    transformLine();
    for (let y = 0; y < size; y++) grid[y * size + x] = result[y];
  }
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) line[x] = grid[y * size + x];
    transformLine();
    for (let x = 0; x < size; x++) grid[y * size + x] = result[x];
  }
  return grid;
}

const EMPTY = 0;
const OUTLINE = 1;
const LINK = 2;
const WARNING = 3;

function drawIcon(parts, recipe) {
  const { size, box } = recipe;
  const fine = size * SUPERSAMPLE; // Side of the supersampled canvas.

  // The artwork (without sparks, if they aren't drawn) fills the box.
  const bounds = recipe.sparks ? parts.bounds.all : parts.bounds.withoutSparks;
  const span = Math.max(bounds.right - bounds.left, bounds.bottom - bounds.top);
  // Leave room inside the box for what is added around the links.
  const inner = box - 2 * (recipe.outline + (recipe.grow || 0));
  const scale = span / (inner * SUPERSAMPLE); // Source pixels per fine pixel.
  const originX = (bounds.left + bounds.right) / 2 - (fine / 2) * scale;
  const originY = (bounds.top + bounds.bottom) / 2 - (fine / 2) * scale;

  // The red parts can be drawn larger than life, about the triangle's centre.
  const { cx, cy } = parts.triangle;
  const redScale = scale / recipe.triangle;
  const unit = scale * SUPERSAMPLE; // Source pixels per output pixel.
  // A shift of the red parts, in output pixels, set below.
  let nudgeX = 0;
  let nudgeY = 0;
  const redX = (sx) => cx + (sx - nudgeX * unit - cx) / recipe.triangle;
  const redY = (sy) => cy + (sy - nudgeY * unit - cy) / recipe.triangle;
  // And back: where a point of the red artwork lands, in output pixels.
  const toOutputX = (sx) => (cx + (sx - cx) * recipe.triangle - originX) / unit + nudgeX;
  const toOutputY = (sy) => (cy + (sy - cy) * recipe.triangle - originY) / unit + nudgeY;

  // Small icons: move the red parts by up to half a pixel so the triangle's
  // base and the "!" sit exactly on output pixels instead of straddling them.
  if (recipe.snapMark) {
    const { stem } = parts.mark;
    const markWidth = Math.max(1, Math.round(toOutputX(stem.right) - toOutputX(stem.left)));
    const stemLeft = (toOutputX(stem.left) + toOutputX(stem.right)) / 2 - markWidth / 2;
    const base = toOutputY(parts.triangle.bottom);
    nudgeX = Math.round(stemLeft) - stemLeft;
    nudgeY = Math.round(base) - base;
  }

  const sampleAt = (sampler, x, y, step) =>
    sampler(Math.floor(x), Math.floor(y), Math.max(Math.floor(x) + 1, Math.ceil(x + step)), Math.max(Math.floor(y) + 1, Math.ceil(y + step)));

  const isLink = new Uint8Array(fine * fine);
  const isWarning = new Uint8Array(fine * fine);
  const triangleSampler = recipe.snapMark ? parts.sample.filledTriangle : parts.sample.triangle;
  for (let v = 0; v < fine; v++) {
    for (let u = 0; u < fine; u++) {
      const sx = originX + u * scale;
      const sy = originY + v * scale;
      const index = v * fine + u;
      isLink[index] = sampleAt(parts.sample.links, sx, sy, scale) >= 0.5 ? 1 : 0;

      const rx = redX(sx);
      const ry = redY(sy);
      let warning = sampleAt(triangleSampler, rx, ry, redScale);
      if (recipe.sparks) warning = Math.max(warning, sampleAt(parts.sample.sparks, rx, ry, redScale));
      isWarning[index] = warning >= 0.5 ? 1 : 0;
    }
  }

  // The "!" placed on whole output pixels, as a cut-out like the logo's.
  if (recipe.snapMark) {
    const { stem, dot } = parts.mark;
    const markWidth = Math.max(1, Math.round(toOutputX(stem.right) - toOutputX(stem.left)));
    const x0 = Math.round((toOutputX(stem.left) + toOutputX(stem.right)) / 2 - markWidth / 2);
    const top = Math.round(toOutputY(stem.top));
    const bottom = Math.max(top + 4, Math.round(toOutputY(dot.bottom)));
    const dotHeight = Math.max(1, Math.round(toOutputY(dot.bottom) - toOutputY(dot.top)));
    const gapHeight = Math.max(1, Math.round(toOutputY(dot.top) - toOutputY(stem.bottom)));
    const stemBottom = Math.max(top + 2, bottom - dotHeight - gapHeight);
    const cut = (yFrom, yTo) => {
      for (let v = yFrom * SUPERSAMPLE; v < yTo * SUPERSAMPLE; v++) {
        for (let u = x0 * SUPERSAMPLE; u < (x0 + markWidth) * SUPERSAMPLE; u++) {
          if (u >= 0 && v >= 0 && u < fine && v < fine) isWarning[v * fine + u] = 0;
        }
      }
    };
    cut(top, stemBottom);
    cut(bottom - dotHeight, bottom);
  }

  const fromLink = squaredDistances(isLink, fine);
  const fromWarning = squaredDistances(isWarning, fine);
  const grow = recipe.grow || 0;
  const growReach = (grow * SUPERSAMPLE) ** 2;
  const outlineReach = ((grow + recipe.outline) * SUPERSAMPLE) ** 2;
  const layerColors = [null, COLORS.outline, recipe.linkColor || COLORS.link, COLORS.warning];
  const gapReach = (recipe.gap * SUPERSAMPLE) ** 2;

  // One layer per fine pixel, then each output pixel averages its samples.
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let covered = 0;
      for (let v = y * SUPERSAMPLE; v < (y + 1) * SUPERSAMPLE; v++) {
        for (let u = x * SUPERSAMPLE; u < (x + 1) * SUPERSAMPLE; u++) {
          const index = v * fine + u;
          let layer = EMPTY;
          if (isWarning[index]) layer = WARNING;
          else if (recipe.gap > 0 && fromWarning[index] <= gapReach) layer = EMPTY;
          else if (isLink[index] || (grow > 0 && fromLink[index] <= growReach)) layer = LINK;
          else if (recipe.outline > 0 && fromLink[index] <= outlineReach) layer = OUTLINE;
          if (layer === EMPTY) continue;
          const color = layerColors[layer];
          r += color[0];
          g += color[1];
          b += color[2];
          covered++;
        }
      }
      if (covered === 0) continue;

      let alpha = covered / (SUPERSAMPLE * SUPERSAMPLE);
      // Push edge pixels towards fully on or fully off.
      if (recipe.harden) alpha = Math.max(0, Math.min(1, (alpha - 0.5) * 1.6 + 0.5));
      const offset = (y * size + x) * 4;
      out[offset] = Math.round(r / covered);
      out[offset + 1] = Math.round(g / covered);
      out[offset + 2] = Math.round(b / covered);
      out[offset + 3] = Math.round(alpha * 255);
    }
  }
  return { width: size, height: size, data: out };
}

// --- Contact sheet ------------------------------------------------------------

// Every icon at actual size and enlarged, on light and dark backgrounds.
function drawPreview(icons) {
  const BACKGROUNDS = [[255, 255, 255], [241, 243, 244], [53, 54, 58], [32, 33, 36]];
  const ENLARGED = 160; // Roughly how big each enlarged copy is drawn.
  const PAD = 12;
  const zoomOf = (icon) => Math.max(1, Math.floor(ENLARGED / icon.width));
  const rowHeights = icons.map((icon) => icon.height * zoomOf(icon) + PAD * 2);
  const columnWidth = Math.max(...icons.map((icon) => icon.width * (1 + zoomOf(icon)))) + PAD * 3;
  const width = columnWidth * BACKGROUNDS.length;
  const height = rowHeights.reduce((a, b) => a + b, 0);
  const data = Buffer.alloc(width * height * 4, 255);

  const blend = (x, y, [r, g, b, a]) => {
    if (x < 0 || y < 0 || x >= width || y >= height) return;
    const offset = (y * width + x) * 4;
    const alpha = a / 255;
    data[offset] = Math.round(r * alpha + data[offset] * (1 - alpha));
    data[offset + 1] = Math.round(g * alpha + data[offset + 1] * (1 - alpha));
    data[offset + 2] = Math.round(b * alpha + data[offset + 2] * (1 - alpha));
  };

  let rowTop = 0;
  icons.forEach((icon, row) => {
    const ZOOM = zoomOf(icon);
    BACKGROUNDS.forEach((background, column) => {
      const left = column * columnWidth;
      for (let y = rowTop; y < rowTop + rowHeights[row]; y++) {
        for (let x = left; x < left + columnWidth; x++) blend(x, y, [...background, 255]);
      }
      for (let y = 0; y < icon.height; y++) {
        for (let x = 0; x < icon.width; x++) {
          const pixel = icon.data.subarray((y * icon.width + x) * 4, (y * icon.width + x) * 4 + 4);
          blend(left + PAD + x, rowTop + PAD + y, pixel);
          for (let dy = 0; dy < ZOOM; dy++) {
            for (let dx = 0; dx < ZOOM; dx++) {
              blend(left + PAD * 2 + icon.width + x * ZOOM + dx, rowTop + PAD + y * ZOOM + dy, pixel);
            }
          }
        }
      }
    });
    rowTop += rowHeights[row];
  });
  return { width, height, data };
}

// --- Main -----------------------------------------------------------------------

function main() {
  const parts = analyseLogo(readPng(SOURCE));
  const icons = RECIPES.map((recipe) => drawIcon(parts, recipe));

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  icons.forEach((icon, index) => {
    const file = path.join(OUTPUT_DIR, `icon${RECIPES[index].size}.png`);
    writePng(file, icon);
    console.log(`${path.relative(ROOT, file)}  ${icon.width}x${icon.height}  ${fs.statSync(file).size} bytes`);
  });

  const previewFlag = process.argv.indexOf('--preview');
  if (previewFlag !== -1) {
    const file = path.resolve(process.argv[previewFlag + 1] || 'icon-preview.png');
    writePng(file, drawPreview(icons));
    console.log(`preview: ${file}`);
  }
}

main();
