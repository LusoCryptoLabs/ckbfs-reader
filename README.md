# ckbfs-reader

Read a [CKBFS](https://talk.nervos.org/t/ckbfs-protocol-a-standard-for-witnesses-based-content-storage-system/8342) v3 file off Nervos CKB, and check it against the chain.

CKBFS keeps a file in the witnesses of the transactions that published it, with a cell
holding the metadata and a checksum. This reads one back. It does not publish: to write a
file, use [`@ckbfs/api`](https://www.npmjs.com/package/@ckbfs/api), the reference library.

```bash
npm i ckbfs-reader @ckb-ccc/core
```

```ts
import { ccc } from '@ckb-ccc/core'
import { readUri } from 'ckbfs-reader'

const client = new ccc.ClientPublicTestnet()
const file = await readUri(client, 'ckbfs://4bf0cbdb…')

file.filename     // 'index.html'
file.contentType  // 'text/html'
file.content      // Uint8Array, checked against the chain or you got an exception
file.appends      // how many times it was appended to after first publication
```

## Why this exists

**The verification.** Reading a file and checking a file are not the same thing, and the
difference only shows up when somebody has a reason to lie to you. At the time of writing,
the reference library's read path reassembles content and calls none of its own
verification helpers: `verifyChecksum`, `verifyV3WitnessChain` and `verifyWitnessChecksum`
are exported, and the only calls to them are from each other. Bytes you read with it have
not been checked. That may well be deliberate, leaving verification to the caller is a
reasonable thing for a library to do, but it is not stated, and a caller who does not know
to verify will not.

Two things are checked here:

- the adler32 of the whole content equals the checksum the cell holds;
- **every prefix** of an append history equals the checksum its backlink declares.

The second is the one that earns its keep. A file is appended to by spending its cell into
a new transaction whose head witness points back at the previous publication and states the
checksum of everything before it. Verifying only the final sum accepts a history that has
been truncated or spliced, as long as the total still lands on the right number, and adler32
is easy to land on a chosen number. Verifying each prefix does not accept that. There is a
test for exactly this case, with a control beside it.

## What it does not do

- **It does not publish.** No signing, no keys, no transactions.
- **It does not fetch a URI form it cannot follow.** `ckbfs://<txhash>i<index>` is valid
  CKBFS and names one outpoint, which goes stale the moment the file is appended to.
  `typeIdOf` returns null for it rather than resolving something that will rot.
- **It does not promise the bytes are still retrievable.** The content lives in transaction
  witnesses, which are history rather than current state. A full node keeps them; a pruned
  one may not. The cell and its checksum are state and are permanent while the cell is.
- **It does not judge the content.** What comes back is bytes somebody else wrote. If you
  are going to serve them to a browser, sandbox them.
- **It does not close the client for you.** `@ckb-ccc/core` keeps its sockets open, so a
  short script that reads one file and stops will sit there afterwards instead of exiting.
  That is the client, not this package: call `process.exit(0)` when you are done, or close
  the client yourself. Worth knowing because it looks exactly like a hang on your first try.

## API

| | |
|---|---|
| `readUri(client, 'ckbfs://…')` | the file a type id names, verified, or `null` if no live cell carries it |
| `readFile(client, cell)` | the same, when you already have the cell |
| `cellForTypeId(client, typeId)` | the one live cell with that type id; two is an error, not a guess |
| `decodeCkbfsData(data)` | `CKBFSData` v3: index, checksum, contentType, filename |
| `readSegment(witnesses, index)` | one publication's bytes, following the witness chain |
| `joinVerified(segments, checksum)` | join an append history and refuse one that does not add up |
| `joinSegments(segments)` | join it without checking, which you have to ask for by name |
| `adler32(bytes)` | what CKBFS checksums with |
| `typeIdOf(uri)` | the type id in a `ckbfs://` URI, or null |

Everything throws `CkbfsError` rather than returning doubtful bytes.

## Tests

```bash
npm test                       # no network: the format, the chains, the splice
node test/live.mjs ckbfs://<type id>    # reads that real file off Pudge
```

The live one is deliberately not part of `npm test`. A test that needs the network is a
test that goes red for reasons that have nothing to do with the code, and then gets ignored.

## Provenance

Written at [LusoCryptoLabs](https://lusocryptolabs.com), independently of `@ckbfs/api`,
for a gateway that serves files stored on CKB to ordinary browsers. That is the job that
makes verification non-optional: the bytes belong to somebody else, the reader hands them
to a stranger, and a gateway that cannot say whether what it served is what the chain holds
has nothing to offer over a plain web host. It is the reader that runs in production there,
not a demonstration written to be published.

Notes on what was measured while building it, including two ceilings on publishing that are
not documented anywhere else, are at
[lusocryptolabs.com/notes.html](https://lusocryptolabs.com/notes.html).

MIT.
