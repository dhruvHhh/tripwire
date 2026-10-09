// Builds the release zip: dist/tripwire-<version>.zip, the file attached to a
// GitHub release.
//
//   node tools/package.js
//
// The zip holds only what the extension loads at runtime: manifest.json,
// icons/ and src/. Tests, the demo, tools, documentation,
// logo.png and the test blocklist (test/fixtures/blocklist.txt) stay out.
//
// Before writing anything it checks that every file the extension refers to
// is in the package, and that the package has nothing nobody refers to.
// After writing, it reads the zip back and checks every file in it.
//
// A development tool, like make-icons.js: it needs nothing but Node, and
// writes the zip format itself.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const ROOT = path.join(__dirname, '..');
const OUTPUT_DIR = path.join(ROOT, 'dist');

// The only top-level entries that go in.
const INCLUDE = ['manifest.json', 'icons', 'src'];

// Never packaged, wherever they turn up under those.
const EXCLUDE = [
  /(^|\/)\./, // Dotfiles and dot-folders.
  /(^|\/)(Thumbs\.db|desktop\.ini)$/i,
  /\.test\.js$/,
  /\.(md|map|log|zip|pem)$/i,
];

// Files the extension may ask for that are deliberately not packaged. The
// test blocklist is loaded only by development installs, and a missing file
// is expected there (see src/background/lists.js).
const OPTIONAL_REFERENCES = ['test/fixtures/blocklist.txt'];

// Paths that must never be in the package.
const FORBIDDEN = [/^test\//, /^demo\//, /^tools\//, /^docs\//, /^dist\//, /^logo\.png$/, /blocklist\.txt$/, /\.md$/i];

// --- Choosing the files ----------------------------------------------------------

const toPosix = (file) => file.split(path.sep).join('/');

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

// Every file that goes in the package, as sorted paths relative to `root`.
function listFiles(root = ROOT) {
  const files = [];
  for (const name of INCLUDE) {
    const full = path.join(root, name);
    if (!fs.existsSync(full)) continue;
    const found = fs.statSync(full).isDirectory() ? walk(full) : [full];
    files.push(...found.map((file) => toPosix(path.relative(root, file))));
  }
  return files.filter((file) => !EXCLUDE.some((pattern) => pattern.test(file))).sort();
}

// --- What the extension refers to --------------------------------------------------

// Paths named in the manifest.
function manifestReferences(manifest) {
  const refs = new Set();
  const add = (value) => {
    if (typeof value === 'string' && value) refs.add(value.replace(/^\//, ''));
  };
  for (const icon of Object.values(manifest.icons || {})) add(icon);
  const action = manifest.action || {};
  add(action.default_popup);
  if (typeof action.default_icon === 'string') add(action.default_icon);
  for (const icon of Object.values(typeof action.default_icon === 'object' ? action.default_icon : {})) add(icon);
  add(manifest.background && manifest.background.service_worker);
  add(manifest.options_ui && manifest.options_ui.page);
  add(manifest.options_page);
  for (const script of manifest.content_scripts || []) {
    for (const file of [...(script.js || []), ...(script.css || [])]) add(file);
  }
  for (const group of manifest.web_accessible_resources || []) {
    for (const file of group.resources || []) add(file);
  }
  return refs;
}

const isLocal = (url) => !/^(?:[a-z][a-z0-9+.-]*:|#|\/\/)/i.test(url);
const resolveFrom = (file, ref) => path.posix.normalize(path.posix.join(path.posix.dirname(file), ref.split(/[?#]/)[0]));

// Paths named inside one packaged file: src/href in a page, importScripts()
// in the service worker, and extension-root paths written as strings in
// scripts (such as the welcome page's address).
function fileReferences(file, text) {
  const refs = new Set();
  if (file.endsWith('.html')) {
    for (const [, url] of text.matchAll(/\s(?:src|href)="([^"]+)"/g)) {
      if (isLocal(url)) refs.add(resolveFrom(file, url));
    }
  }
  if (file.endsWith('.js')) {
    for (const [, list] of text.matchAll(/importScripts\(([^)]*)\)/g)) {
      for (const [, url] of list.matchAll(/'([^']+)'/g)) refs.add(resolveFrom(file, url));
    }
    for (const [, url] of text.matchAll(/'((?:src|icons|test)\/[\w./-]+\.(?:html|js|css|png|txt|json))'/g)) {
      refs.add(url);
    }
  }
  return refs;
}

/**
 * Checks the package's files against what refers to them.
 * @returns {{ missing: string[], unreferenced: string[], optionalMissing: string[] }}
 *   missing: referred to but not packaged; unreferenced: packaged but never
 *   referred to; optionalMissing: the expected, deliberate omissions.
 */
function checkReferences(root = ROOT, files = listFiles(root)) {
  const packaged = new Set(files);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  const referenced = manifestReferences(manifest);
  for (const file of files) {
    if (!/\.(html|js)$/.test(file)) continue;
    for (const ref of fileReferences(file, fs.readFileSync(path.join(root, file), 'utf8'))) referenced.add(ref);
  }

  const missing = [...referenced].filter((ref) => !packaged.has(ref) && !OPTIONAL_REFERENCES.includes(ref)).sort();
  const optionalMissing = [...referenced].filter((ref) => !packaged.has(ref) && OPTIONAL_REFERENCES.includes(ref)).sort();
  const unreferenced = files.filter((file) => file !== 'manifest.json' && !referenced.has(file));
  return { missing, unreferenced, optionalMissing };
}

// --- The zip format ----------------------------------------------------------------

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// Every entry gets the same date (1 January 2026, 00:00), so the same files
// always make a byte-identical zip.
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

/**
 * Makes a zip archive.
 * @param {{ name: string, data: Buffer }[]} entries
 * @returns {Buffer}
 */
function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    const deflated = zlib.deflateRawSync(data, { level: 9 });
    // Store the file as it is when compressing it would not help.
    const method = deflated.length < data.length ? 8 : 0;
    const body = method === 8 ? deflated : data;
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // Version needed to extract: 2.0.
    local.writeUInt16LE(0x0800, 6); // Flags: names are UTF-8.
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBytes, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // Made by: 2.0.
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);

    offset += local.length + nameBytes.length + body.length;
  }

  const centralSize = centrals.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

/**
 * Reads a zip archive made by zip() (or any plain one: stored or deflated
 * entries, no encryption, no zip64), checking each entry's CRC.
 * @returns {{ name: string, data: Buffer }[]}
 */
function unzip(archive) {
  const endAt = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (endAt < 0) throw new Error('not a zip file');
  const count = archive.readUInt16LE(endAt + 10);
  let at = archive.readUInt32LE(endAt + 16);

  const entries = [];
  for (let i = 0; i < count; i++) {
    if (archive.readUInt32LE(at) !== 0x02014b50) throw new Error('bad central directory');
    const method = archive.readUInt16LE(at + 10);
    const crc = archive.readUInt32LE(at + 16);
    const compressedSize = archive.readUInt32LE(at + 20);
    const nameLength = archive.readUInt16LE(at + 28);
    const extraLength = archive.readUInt16LE(at + 30);
    const commentLength = archive.readUInt16LE(at + 32);
    const localAt = archive.readUInt32LE(at + 42);
    const name = archive.toString('utf8', at + 46, at + 46 + nameLength);

    const dataAt = localAt + 30 + archive.readUInt16LE(localAt + 26) + archive.readUInt16LE(localAt + 28);
    const body = archive.subarray(dataAt, dataAt + compressedSize);
    const data = method === 8 ? zlib.inflateRawSync(body) : Buffer.from(body);
    if (crc32(data) !== crc) throw new Error(`CRC mismatch in ${name}`);
    entries.push({ name, data });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

// --- Building ------------------------------------------------------------------------

function fail(message) {
  console.error(`\n${message}`);
  process.exit(1);
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const files = listFiles(ROOT);

  const forbidden = files.filter((file) => FORBIDDEN.some((pattern) => pattern.test(file)));
  if (forbidden.length > 0) fail(`These must not be packaged:\n  ${forbidden.join('\n  ')}`);

  const { missing, unreferenced, optionalMissing } = checkReferences(ROOT, files);
  if (missing.length > 0) fail(`Referred to by the extension, but not in the package:\n  ${missing.join('\n  ')}`);
  if (unreferenced.length > 0) fail(`In the package, but nothing refers to them:\n  ${unreferenced.join('\n  ')}`);

  const entries = files.map((name) => ({ name, data: fs.readFileSync(path.join(ROOT, name)) }));
  const archive = zip(entries);
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const output = path.join(OUTPUT_DIR, `tripwire-${manifest.version}.zip`);
  fs.writeFileSync(output, archive);

  // Read it back from disk and compare every file.
  const readBack = unzip(fs.readFileSync(output));
  const same =
    readBack.length === entries.length &&
    readBack.every((entry, i) => entry.name === entries[i].name && entry.data.equals(entries[i].data));
  if (!same) fail('The zip that was written does not match the files.');

  console.log(`Tripwire ${manifest.version}: ${entries.length} files\n`);
  for (const { name, data } of entries) console.log(`  ${String(data.length).padStart(7)}  ${name}`);
  const unpacked = entries.reduce((sum, entry) => sum + entry.data.length, 0);
  console.log(`\n${path.relative(ROOT, output)}: ${(archive.length / 1024).toFixed(1)} KB (${(unpacked / 1024).toFixed(1)} KB unpacked)`);
  console.log('Checked: read back and identical; every file the manifest and pages refer to is present;');
  console.log('nothing unreferenced; no tests, demo, tools, docs, logo.png or test list.');
  if (optionalMissing.length > 0) console.log(`Left out on purpose (development installs only): ${optionalMissing.join(', ')}`);
}

if (require.main === module) main();

module.exports = { INCLUDE, OPTIONAL_REFERENCES, FORBIDDEN, listFiles, checkReferences, zip, unzip, crc32 };
