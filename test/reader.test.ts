import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ccc } from '@ckb-ccc/core'
import { adler32, decodeCkbfsData, readSegment, joinVerified, joinSegments, typeIdOf, CkbfsError, isCkbfsV3, ckbfsV3Scripts, CKBFS_V3, CKBFS_V3_BY_TYPE } from '../src/index.ts'

const enc = new TextEncoder()
const hex = (b: Uint8Array) => ccc.hexFrom(b) as `0x${string}`
const ZERO32 = new Uint8Array(32)

/** A CKBFS v3 head witness: magic, version, backlink, next index, then content. */
function head(content: Uint8Array, opts: { next?: number; back?: { txHash: Uint8Array; index: number; checksum: number } } = {}) {
  const b = new Uint8Array(50 + content.length)
  b.set(enc.encode('CKBFS'), 0)
  b[5] = 3
  b.set(opts.back?.txHash ?? ZERO32, 6)
  const dv = new DataView(b.buffer)
  dv.setUint32(38, opts.back?.index ?? 0, true)
  dv.setUint32(42, opts.back?.checksum ?? 0, true)
  dv.setUint32(46, opts.next ?? 0, true)
  b.set(content, 50)
  return hex(b)
}

/** A continuation witness: next index, then content. */
function cont(content: Uint8Array, next = 0) {
  const b = new Uint8Array(4 + content.length)
  new DataView(b.buffer).setUint32(0, next, true)
  b.set(content, 4)
  return hex(b)
}

/** CKBFSData v3, as a cell would carry it. */
function cellData(meta: { index: number; checksum: number; contentType: string; filename: string }) {
  const ct = enc.encode(meta.contentType)
  const fn = enc.encode(meta.filename)
  const fields = [
    new Uint8Array(4),
    new Uint8Array(4),
    new Uint8Array(4 + ct.length),
    new Uint8Array(4 + fn.length),
  ]
  new DataView(fields[0].buffer).setUint32(0, meta.index, true)
  new DataView(fields[1].buffer).setUint32(0, meta.checksum, true)
  new DataView(fields[2].buffer).setUint32(0, ct.length, true)
  fields[2].set(ct, 4)
  new DataView(fields[3].buffer).setUint32(0, fn.length, true)
  fields[3].set(fn, 4)

  const header = 4 + 4 * fields.length
  const total = header + fields.reduce((n, f) => n + f.length, 0)
  const out = new Uint8Array(total)
  const dv = new DataView(out.buffer)
  dv.setUint32(0, total, true)
  let off = header
  fields.forEach((f, i) => {
    dv.setUint32(4 + i * 4, off, true)
    out.set(f, off)
    off += f.length
  })
  return hex(out)
}

test('adler32 matches the values the format is defined against', () => {
  assert.equal(adler32(new Uint8Array(0)), 1)
  assert.equal(adler32(enc.encode('a')), 0x00620062)
  assert.equal(adler32(enc.encode('abc')), 0x024d0127)
})

test('the cell data round-trips', () => {
  const meta = { index: 3, checksum: 12345, contentType: 'text/html', filename: 'index.html' }
  assert.deepEqual(decodeCkbfsData(cellData(meta)), meta)
  assert.throws(() => decodeCkbfsData('0x00'), CkbfsError)
})

test('a segment is read across every witness in its chain', () => {
  // Content split over three witnesses: head at 0 points to 2, which points to 5.
  const w: `0x${string}`[] = []
  w[0] = head(enc.encode('hello '), { next: 2 })
  w[1] = '0x'
  w[2] = cont(enc.encode('on chain'), 5)
  w[3] = '0x'
  w[4] = '0x'
  w[5] = cont(enc.encode('!'))
  const seg = readSegment(w, 0)
  assert.equal(new TextDecoder().decode(seg.bytes), 'hello on chain!')
  assert.equal(seg.back, null)
})

test('a witness chain that loops is refused rather than followed', () => {
  const w: `0x${string}`[] = []
  w[0] = head(enc.encode('a'), { next: 1 })
  w[1] = cont(enc.encode('b'), 1) // points at itself
  assert.throws(() => readSegment(w, 0), /loops/)
})

test('something that is not a CKBFS head is refused', () => {
  assert.throws(() => readSegment([hex(new Uint8Array(60))], 0), /not a CKBFS v3 head/)
})

test('a whole file with no appends verifies against the cell', () => {
  const content = enc.encode('a page')
  const seg = { bytes: content, back: null }
  assert.deepEqual(joinVerified([seg], adler32(content)), content)
  // And a cell claiming a different checksum is refused.
  assert.throws(() => joinVerified([seg], adler32(content) + 1), /does not match the cell/)
})

test('an append history verifies at every prefix, not only at the end', () => {
  const one = enc.encode('first ')
  const two = enc.encode('second')
  const whole = new Uint8Array([...one, ...two])
  // The newer segment backlinks to the older and declares what came before it.
  const segs = [
    { bytes: one, back: null },
    { bytes: two, back: { txHash: '0x' + '11'.repeat(32), index: 0, checksum: adler32(one) } },
  ]
  assert.deepEqual(joinVerified(segs, adler32(whole)), whole)
})

test('a spliced history is caught even when the total still adds up', () => {
  // The control, and the reason this package exists. An attacker replaces the first
  // publication with different bytes and adjusts the second so the FINAL checksum still
  // matches. Checking only the end accepts it; checking the prefix does not.
  const real = enc.encode('pay alice')
  const fake = enc.encode('pay evil!') // same length, so the totals can be made to line up
  const tail = enc.encode(' now')
  const whole = new Uint8Array([...fake, ...tail])

  const spliced = [
    { bytes: fake, back: null },
    // the backlink still declares the checksum of the ORIGINAL first segment
    { bytes: tail, back: { txHash: '0x' + '22'.repeat(32), index: 0, checksum: adler32(real) } },
  ]
  assert.throws(() => joinVerified(spliced, adler32(whole)), /declares a checksum the earlier content does not produce/)

  // And the control on the control: the same shape, honest, passes.
  const honest = [
    { bytes: real, back: null },
    { bytes: tail, back: { txHash: '0x' + '22'.repeat(32), index: 0, checksum: adler32(real) } },
  ]
  assert.ok(joinVerified(honest, adler32(new Uint8Array([...real, ...tail]))))
})

test('only the type-id form of a ckbfs:// URI is followable', () => {
  const id = 'a'.repeat(64)
  assert.equal(typeIdOf(`ckbfs://${id}`), `0x${id}`)
  assert.equal(typeIdOf(`  ckbfs://${id.toUpperCase()}  `), `0x${id}`)
  // An outpoint URI is valid CKBFS and cannot be followed across an append, so it is
  // refused here rather than resolved into something that goes stale.
  assert.equal(typeIdOf(`ckbfs://0x${id}`), `0x${id}`)
  assert.equal(typeIdOf(`ckbfs://${'b'.repeat(64)}i0`), null)
  assert.equal(typeIdOf('https://example.com'), null)
})

test('joinSegments returns the bytes without checking them, and says so by its name', () => {
  // Offered for a caller that has already verified, or is verifying differently. It is
  // separate from joinVerified precisely so that not checking has to be chosen.
  const segs = [{ bytes: enc.encode('x'), back: null }]
  assert.deepEqual(joinSegments(segs), enc.encode('x'))
})

test('a file cell may refer to the CKBFS v3 script by data hash or by type, on its own network only', () => {
  const testnet = { addressPrefix: 'ckt' } as never, mainnet = { addressPrefix: 'ckb' } as never
  assert.equal(isCkbfsV3(testnet, CKBFS_V3), true)
  assert.equal(isCkbfsV3(testnet, CKBFS_V3_BY_TYPE.testnet), true)
  assert.equal(isCkbfsV3(mainnet, CKBFS_V3_BY_TYPE.mainnet), true)
  // the controls: the other network's type id, the right hash with the wrong hash type, nothing
  assert.equal(isCkbfsV3(testnet, CKBFS_V3_BY_TYPE.mainnet), false)
  assert.equal(isCkbfsV3(mainnet, CKBFS_V3_BY_TYPE.testnet), false)
  assert.equal(isCkbfsV3(testnet, { codeHash: CKBFS_V3.codeHash, hashType: 'type' }), false)
  assert.equal(isCkbfsV3(testnet, null), false)
  assert.deepEqual(ckbfsV3Scripts(mainnet).map((s) => s.hashType), ['data1', 'type'])
})
