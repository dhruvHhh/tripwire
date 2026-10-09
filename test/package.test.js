// Run with: node --test
//
// The release zip (tools/package.js): what goes in, what stays out, and
// whether the zip it writes reads back intact.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { listFiles, checkReferences, zip, unzip, crc32, FORBIDDEN, OPTIONAL_REFERENCES } = require('../tools/package.js');
const blocklist = require('../src/lib/blocklist.js');

const ROOT = path.join(__dirname, '..');
const files = listFiles(ROOT);

test('the package holds the manifest, the icons and src/, and nothing else', () => {
  assert.ok(files.includes('manifest.json'));
  assert.ok(files.includes('src/content/early.js'));
  assert.ok(files.includes('src/popup/popup.html'));
  assert.ok(files.includes('src/options/options.html'));
  assert.ok(files.includes('src/welcome/welcome.html'));
  for (const size of [16, 32, 48, 128]) assert.ok(files.includes(`icons/icon${size}.png`));
  for (const file of files) {
    assert.match(file, /^(manifest\.json|icons\/|src\/)/, file);
  }
});

test('the package leaves out tests, demo, tools, docs, the logo and the test list', () => {
  for (const file of files) {
    for (const pattern of FORBIDDEN) assert.doesNotMatch(file, pattern, file);
  }
  assert.ok(!files.includes(blocklist.CONFIG.fixture.path), 'the test list is not packaged');
  assert.ok(!files.some((file) => file.endsWith('.md')));
  assert.ok(!files.includes('logo.png'));
});

test('everything the extension refers to is packaged, and everything packaged is referred to', () => {
  const { missing, unreferenced, optionalMissing } = checkReferences(ROOT, files);
  assert.deepEqual(missing, []);
  assert.deepEqual(unreferenced, []);
  // The one deliberate gap: the test list, loaded only by development installs.
  assert.deepEqual(optionalMissing, OPTIONAL_REFERENCES);
  assert.deepEqual(OPTIONAL_REFERENCES, [blocklist.CONFIG.fixture.path]);
});

test('the reference check notices a missing file', () => {
  const { missing, unreferenced } = checkReferences(ROOT, files.filter((file) => file !== 'src/content/early.js'));
  assert.deepEqual(missing, ['src/content/early.js']);
  assert.deepEqual(unreferenced, []);
});

test('crc32: the standard check value', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
  assert.equal(crc32(Buffer.alloc(0)), 0);
});

test('zip and unzip: the real files go in and come out unchanged', () => {
  const entries = files.map((name) => ({ name, data: fs.readFileSync(path.join(ROOT, name)) }));
  const archive = zip(entries);
  const back = unzip(archive);
  assert.deepEqual(back.map((entry) => entry.name), files);
  back.forEach((entry, i) => assert.ok(entry.data.equals(entries[i].data), entry.name));
  assert.ok(archive.length < entries.reduce((sum, entry) => sum + entry.data.length, 0), 'compressed');
});

test('zip: the same files always make the same bytes', () => {
  const entries = [
    { name: 'a.txt', data: Buffer.from('hello hello hello hello') },
    { name: 'dir/b.bin', data: Buffer.from([0, 1, 2, 3]) },
  ];
  assert.ok(zip(entries).equals(zip(entries)));
});

test('unzip: a damaged archive is refused', () => {
  const archive = zip([{ name: 'a.txt', data: Buffer.from('some text that compresses, some text that compresses') }]);
  assert.throws(() => unzip(Buffer.from('not a zip')), /not a zip/);
  const damaged = Buffer.from(archive);
  damaged[40] ^= 0xff; // Inside the compressed data.
  assert.throws(() => unzip(damaged));
});
