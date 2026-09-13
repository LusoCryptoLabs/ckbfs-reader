import { ccc } from '@ckb-ccc/core'

/**
 * Read a CKBFS v3 file off Nervos CKB, and check it.
 *
 * CKBFS stores a file in the witnesses of the transactions that published it, with a cell
 * holding the metadata and a checksum. This reads one back and verifies it. The checking is
 * the point: the reference library's read path reassembles content and calls none of its own
 * verification helpers, so what it hands you has not been checked against the chain.
 *
 * Two things are verified here, and the second is the one that matters:
 *
 *  - the adler32 of the whole content equals the checksum in the cell;
 *  - **every prefix** of an append history equals the checksum its backlink declares.
 *
 * A file can be appended to, which spends its cell into a new transaction whose head witness
 * points back at the previous publication and states the checksum of everything before it.
 * Checking only the final sum accepts a history that has been truncated or spliced, as long
 * as the total still lands; checking each prefix does not.
 *
 * Nothing here writes. To publish a file, use `@ckbfs/api`.
 */

/** CKBFS v3, pinned by data hash so a future deployment cannot change what a file means. */
export const CKBFS_V3 = {
  codeHash: '0xb5d13ffe0547c78021c01fe24dce2e959a1ed8edbca3cb93dd2e9f57fb56d695' as const,
  hashType: 'data1' as const,
}

const dec = new TextDecoder()
const ZERO32 = '0x' + '00'.repeat(32)
/** Bounded: each hop is an RPC, and a broken chain must not loop forever. */
const MAX_APPENDS = 512

export interface CkbfsMeta {
  /** The witness index the content starts at. */
  index: number
  /** adler32 of the whole content, as the cell states it. */
  checksum: number
  contentType: string
  filename: string
}

export interface CkbfsFile extends CkbfsMeta {
  content: Uint8Array
  /** How many times it was appended to after first publication. */
  appends: number
}

export class CkbfsError extends Error {}

/** `CKBFSData` v3: a molecule table of index u32, checksum u32, contentType Bytes, filename Bytes. */
export function decodeCkbfsData(data: ccc.BytesLike): CkbfsMeta {
  const b = ccc.bytesFrom(data)
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
  const u32 = (o: number) => dv.getUint32(o, true)
  if (b.length < 20 || (u32(4) - 4) / 4 !== 4) throw new CkbfsError('not a CKBFS v3 cell')
  const off = [u32(4), u32(8), u32(12), u32(16)]
  const bytesAt = (o: number) => b.subarray(o + 4, o + 4 + u32(o))
  return {
    index: u32(off[0]),
    checksum: u32(off[1]),
    contentType: dec.decode(bytesAt(off[2])),
    filename: dec.decode(bytesAt(off[3])),
  }
}

/** adler32, which is what CKBFS checksums with. */
export function adler32(b: Uint8Array): number {
  let a = 1
  let s = 0
  for (let i = 0; i < b.length; i++) {
    a = (a + b[i]) % 65521
    s = (s + a) % 65521
  }
  return ((s << 16) | a) >>> 0
}

const u32At = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(o, true)

export interface Segment {
  bytes: Uint8Array
  /** Where the previous publication is, and what it claimed its content summed to. */
  back: { txHash: string; index: number; checksum: number } | null
}

/**
 * One publication's bytes: the witness chain inside a single transaction.
 *
 * The head witness is `CKBFS`, `0x03`, a 32-byte previous tx hash, a u32 previous witness
 * index, a u32 previous checksum, a u32 next-witness index, then the first chunk. Every
 * witness after it is a u32 next index and a chunk, and 0 as the next index ends the chain.
 */
export function readSegment(witnesses: readonly ccc.Hex[], index: number, txHash = '(tx)'): Segment {
  const chunks: Uint8Array[] = []
  const seen = new Set<number>()
  let i = index
  let head = true
  let back: Segment['back'] = null
  for (;;) {
    if (witnesses[i] === undefined) throw new CkbfsError(`witness ${i} missing in ${txHash}`)
    if (seen.has(i)) throw new CkbfsError(`witness chain in ${txHash} loops at ${i}`)
    seen.add(i)
    const b = ccc.bytesFrom(witnesses[i])
    let next: number
    if (head) {
      if (b.length < 50 || dec.decode(b.subarray(0, 5)) !== 'CKBFS' || b[5] !== 3)
        throw new CkbfsError(`witness ${i} of ${txHash} is not a CKBFS v3 head`)
      const prev = '0x' + Array.from(b.subarray(6, 38), (x) => x.toString(16).padStart(2, '0')).join('')
      back = prev === ZERO32 ? null : { txHash: prev, index: u32At(b, 38), checksum: u32At(b, 42) }
      next = u32At(b, 46)
      chunks.push(b.subarray(50))
      head = false
    } else {
      if (b.length < 4) throw new CkbfsError(`witness ${i} of ${txHash} is too short for a CKBFS continuation`)
      next = u32At(b, 0)
      chunks.push(b.subarray(4))
    }
    if (!next) break
    i = next
  }
  const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
  let at = 0
  for (const c of chunks) {
    bytes.set(c, at)
    at += c.length
  }
  return { bytes, back }
}

/**
 * Join an append history, oldest first, checking nothing.
 *
 * Separate from `joinVerified` so that not checking is something a caller has to choose
 * rather than something they get by default. If you are not sure which you want, you want
 * the other one.
 */
export function joinSegments(segments: readonly Segment[]): Uint8Array {
  const content = new Uint8Array(segments.reduce((n, s) => n + s.bytes.length, 0))
  let off = 0
  for (const s of segments) {
    content.set(s.bytes, off)
    off += s.bytes.length
  }
  return content
}

/**
 * Join an append history, oldest first, and refuse one that does not add up.
 *
 * `segments` must be ordered oldest to newest. Each one carries the backlink of the
 * publication that produced it, so `segments[i + 1].back.checksum` is a claim about
 * everything up to and including `segments[i]`, and that is what gets checked.
 */
export function joinVerified(segments: readonly Segment[], finalChecksum: number): Uint8Array {
  const content = joinSegments(segments)
  let run = 0
  for (let i = 0; i < segments.length; i++) {
    run += segments[i].bytes.length
    const declared = segments[i + 1]?.back?.checksum
    if (declared !== undefined && adler32(content.subarray(0, run)) !== declared)
      throw new CkbfsError(`the backlink after segment ${i + 1} declares a checksum the earlier content does not produce`)
  }
  if (adler32(content) !== finalChecksum) throw new CkbfsError('content checksum does not match the cell')
  return content
}

/** The live cell carrying this type id, or null. Two is refused rather than guessed at. */
export async function cellForTypeId(
  client: ccc.Client,
  typeId: ccc.Hex,
): Promise<{ outPoint: ccc.OutPoint; outputData: ccc.Hex } | null> {
  const script = ccc.Script.from({ codeHash: CKBFS_V3.codeHash, hashType: CKBFS_V3.hashType, args: typeId })
  let found: { outPoint: ccc.OutPoint; outputData: ccc.Hex } | null = null
  let n = 0
  for await (const cell of client.findCells({ script, scriptType: 'type', scriptSearchMode: 'exact' }, 'asc', 2)) {
    found = { outPoint: cell.outPoint, outputData: cell.outputData as ccc.Hex }
    if (++n > 1) throw new CkbfsError(`two live cells carry the type id ${typeId}`)
  }
  return found
}

/** The type id inside a `ckbfs://` URI, or null. Only the type-id form is followable. */
export function typeIdOf(uri: string): ccc.Hex | null {
  const m = /^ckbfs:\/\/([0-9a-fA-F]{64})$/.exec(uri.trim())
  return m ? (`0x${m[1].toLowerCase()}` as ccc.Hex) : null
}

/** The whole of a file a CKBFS cell holds, verified. Throws rather than return doubtful bytes. */
export async function readFile(
  client: ccc.Client,
  cell: { outPoint: ccc.OutPointLike; outputData: ccc.BytesLike },
): Promise<CkbfsFile> {
  const meta = decodeCkbfsData(cell.outputData)
  const txHash = String(ccc.OutPoint.from(cell.outPoint).txHash)
  const first = await client.getTransaction(txHash)
  if (!first?.transaction) throw new CkbfsError(`transaction ${txHash} not found`)

  const segments: Segment[] = []
  let at = { txHash, index: meta.index, tx: first.transaction }
  const visited = new Set<string>()
  for (let hop = 0; ; hop++) {
    if (hop > MAX_APPENDS) throw new CkbfsError(`append history of ${txHash} is longer than ${MAX_APPENDS}`)
    const key = `${at.txHash}:${at.index}`
    if (visited.has(key)) throw new CkbfsError(`append history of ${txHash} loops`)
    visited.add(key)
    const seg = readSegment(at.tx.witnesses as ccc.Hex[], at.index, at.txHash)
    segments.unshift(seg)
    if (!seg.back) break
    const prev = await client.getTransaction(seg.back.txHash)
    if (!prev?.transaction) throw new CkbfsError(`backlinked transaction ${seg.back.txHash} not found`)
    at = { txHash: seg.back.txHash, index: seg.back.index, tx: prev.transaction }
  }

  return { ...meta, content: joinVerified(segments, meta.checksum), appends: segments.length - 1 }
}

/** The file a `ckbfs://<type id>` URI names, verified, or null when no live cell carries it. */
export async function readUri(client: ccc.Client, uri: string): Promise<CkbfsFile | null> {
  const typeId = typeIdOf(uri)
  if (!typeId) throw new CkbfsError(`not a ckbfs:// type id URI: ${uri}`)
  const cell = await cellForTypeId(client, typeId)
  return cell ? readFile(client, cell) : null
}
