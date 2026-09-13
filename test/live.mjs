// Read a real file off Pudge with this package and nothing else.
//
//   node test/live.mjs ckbfs://<type id>          (Pudge, the CKB testnet)
//
// Not part of `npm test`: it needs the network, and a test that needs the network is a
// test that goes red for reasons that are not about the code. It is here because the
// synthetic tests prove the checking and only this proves the reading.
//
// No default URI on purpose. Pass a file you published yourself, or one you found: a
// canned type id would send everyone to read the same stranger's bytes, and it would rot
// the day that cell is spent.
import { ccc } from '@ckb-ccc/core'
import { readUri } from '../src/index.ts'

const uri = process.argv[2]
if (!uri) {
  console.error('usage: node test/live.mjs ckbfs://<64 hex type id>')
  process.exit(2)
}
const client = new ccc.ClientPublicTestnet()

const t0 = Date.now()
const file = await readUri(client, uri)
if (!file) {
  console.error(`no live cell carries ${uri}`)
  process.exit(1)
}
console.log(`${uri}`)
console.log(`  ${file.filename}  ${file.contentType}`)
console.log(`  ${file.content.length} bytes, ${file.appends} append(s), verified in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
console.log(`  first line: ${new TextDecoder().decode(file.content.subarray(0, 60)).split('\n')[0]}`)
process.exit(0)
