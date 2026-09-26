# Library Book Lending Tracker: how it works

## The target goal

Paper lending logs can be edited after the fact: a lost book can be quietly
marked as returned, or a borrower can dispute what the log says. A lending tracker in C where every borrow and return is recorded as a block in a blockchain, so that:

- a record cannot be changed without the change being detected (SHA-256
  hashes linking each block to the one before it)
- a record can be traced to someone who was allowed to create it
  (ECDSA digital signatures)
- only books and members that really exist can appear in a record
  (registries loaded from `books.txt` and `members.txt`)
- the chain survives restarts (file-based persistence)

This document goes through how each of those is implemented, the design
decisions behind them, and what the system does and does not protect
against.

## Module overview

The code is split by responsibility so each file can be read on its own:

| File | Responsibility |
|---|---|
| `registry.c/h` | `Book`, `Member` and `Registry` structs; loading and validating `books.txt` and `members.txt`; lookup by ID |
| `crypto.c/h` | thin wrappers over OpenSSL: SHA-256 to hex, key pair generation, reading and writing PEM key files, ECDSA sign and verify, hex encoding |
| `blockchain.c/h` | `Block` and `Blockchain` structs; building, signing and hashing blocks; appending to and loading `chain.txt`; chain validation; deriving loan state |
| `main.c` | the CLI: startup sequence, login and logout, borrow, return, overdue, view, validate and the tamper demo |
| `utils.c/h` | small string helpers shared by the two file parsers |

The dependency direction is one way: `main.c` uses everything,
`blockchain.c` uses `crypto.c` and the `Book`/`Member` structs, and
`crypto.c` and `registry.c` know nothing about blocks. The crypto code
could be swapped for another library without touching the chain logic.

## Startup sequence

```
load books.txt and members.txt   -> exit with an error if either is missing or empty
load or create the librarian keys
load chain.txt                   -> exit if a line cannot be parsed
create the genesis block         -> only if chain.txt had no blocks
validate the whole chain         -> warn and block writes if it fails
show the menu
```

Registries are loaded first because nothing else is meaningful without
them. The chain is validated before the menu appears so a tampered
`chain.txt` is reported immediately, not only when someone thinks to run
option 6.

## Registries

`books.txt` and `members.txt` are read line by line into fixed arrays
inside a `Registry` struct (`MAX_BOOKS` and `MAX_MEMBERS` are 200). The structs match the ones required.

Each line goes through `parse_record()`, which accepts it only if:

- it splits into exactly three comma-separated fields
- no field is empty after trimming spaces
- it does not contain `|`, which is the separator used in `chain.txt`
  (a title containing `|` would otherwise corrupt the chain file)

Each field is then copied with `copy_field()`, which refuses values that
do not fit the struct's array instead of silently truncating them. A
truncated ID could otherwise collide with another ID.

Bad lines and duplicate IDs are skipped with a warning that includes the
line number, so one typo does not stop the whole library. If a file is
missing, or ends up with zero valid records, the program prints an error
and exits:

```
ERROR: cannot open books.txt (No such file or directory)
ERROR: members.txt is empty or has no valid member records
```

`find_book()` and `find_member()` are linear searches. With a few hundred
records at most this is instant, and it keeps the code simple.

## Block structure

```c
typedef struct {
    int index;
    time_t timestamp;
    char book_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[ACTION_SIZE];                    /* 10 */
    char previous_hash[HASH_HEX_SIZE];           /* 65 */
    unsigned char signature[MAX_SIGNATURE_SIZE]; /* 72 */
    unsigned int signature_len;
    char hash[HASH_HEX_SIZE];                    /* 65 */
} Block;
```

The fields follow the required block layout, with two small notes:

- **`signature_len` was added.** An ECDSA signature is DER encoded, a
  format whose length depends on the values of the two numbers inside it.
  On `secp256k1` it is at most 72 bytes (which is why the
  array is 72) and in practice varies between 70 and 72. Without storing the length,
  verification would not know how many of the 72 bytes are the signature.
  In a sample `chain.txt`, signatures start with `3044`, `3045` and
  `3046`; the second byte is the length of what follows, so these are 70,
  71 and 72 bytes long.
- **`Member_name` is written as `member_name`** to match the naming of the
  other fields.

The book title and member name are copied into the block at the time of
the transaction, as required. This means the chain is a self-contained
historical record: if a member later changes their name in
`members.txt`, old blocks still show the name that was valid at the time,
and their signatures still verify.

The genesis block has index 0, action `GENESIS`, empty book and member
fields, and a `previous_hash` of 64 zeros. It is signed like every other
block, so validation does not need a special case for it apart from the
expected `previous_hash`.

The chain itself is a fixed array of `MAX_BLOCKS` (1000) blocks plus a
count, following the array-based chain from class. The `LibrarySystem`
struct that holds it is declared `static` so its roughly 400 KB live in
the data segment instead of on the stack.

## Hashing and signing

### What gets signed

`build_signing_payload()` joins the block's fields with `|`:

```
index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash
```

The separator matters. If the fields were simply concatenated, the pair
`"AB" + "C"` and the pair `"A" + "BC"` would produce the same bytes, so two
different blocks would have the same hash and the same valid signature.
With a separator that cannot appear inside a field (the registry loader
rejects `|`), each payload maps back to exactly one block.

`previous_hash` is part of the signed data, so a signature is bound to
the block's position in the chain. A valid signed block cannot be cut
out and pasted into a different place.

### Order: sign, then hash

`seal_block()` does two things in order:

1. Sign the payload with the private key (ECDSA over SHA-256).
2. Compute the block hash as SHA-256 of `payload|signature_hex`.

Because the hash includes the signature, changing or stripping the
signature changes the hash, which breaks the link from the next block.
The order is: create the block, sign it, then compute its hash.

### Why ECDSA on secp256k1

Signatures use ECDSA with a 72-byte signature field. 72 bytes is
the maximum DER signature size for 256-bit curves, and `secp256k1` is the
curve used by Bitcoin and Ethereum for transaction signatures, so it is
the natural choice for a blockchain project. OpenSSL 3's
`EVP_EC_gen("secp256k1")` generates the key, and `EVP_DigestSign` /
`EVP_DigestVerify` hash the payload with SHA-256 and sign or verify it in
one call.

## Authentication and access control

There is one role that can write to the chain: the librarian. The
librarian is authenticated by proving they can decrypt the private key.

- On first run, `create_librarian_keys()` generates the key pair and asks
  for a passphrase (minimum 8 characters, entered twice). The private key
  is written with `PEM_write_PrivateKey()` using AES-256-CBC, so the file
  on disk is useless without the passphrase. The file is created with
  `open(..., 0600)` so only the owner can read it, and `keys/` is created
  with `0700`.
- The public key is written unencrypted. Anyone can use it to verify
  signatures, which is what makes the chain publicly checkable.
- `require_login()` runs before any action that adds a block. It prompts
  for the passphrase with terminal echo turned off, tries to decrypt the
  private key, and allows 3 attempts. After decrypting, it checks with
  `EVP_PKEY_eq()` that the private key matches the public key, so a
  swapped key file is caught before it can sign anything.
- Passphrase buffers are wiped with `OPENSSL_cleanse()` right after use,
  so the passphrase does not linger in memory.
- Option 8 logs out by freeing the private key, so it is no longer in
  memory at all.

The resulting access control is:

| Action | Needs |
|---|---|
| View registries, view records, validate, tamper demo | public key only |
| Borrow, return, mark overdue, create genesis | private key (passphrase) |

This reflects how a real blockchain works: anyone can read and verify,
only key holders can write.

## Lending rules

A book's current state is never stored as a field that can be edited. It
is derived from the chain by `find_open_loan()`, which walks backwards
from the newest block to the latest block for that book:

- latest is `BORROWED` or `OVERDUE`: the book is on loan, and that block
  says to whom
- latest is `RETURNED`, or there is no block for the book: it is available

The three actions use this:

**Borrow** (option 2). Look up both IDs; if either is unknown, print
`ERROR: Book or Member not found` and stop. If the book already has an
open loan, refuse and name the current borrower. Otherwise create a
`BORROWED` block.

**Return** (option 3). Look up both IDs. If the book has no open loan
(never borrowed, or already returned), print an error. If it is on loan
to a different member, refuse; this stops someone recording a return on
another member's behalf. Otherwise create a `RETURNED` block.

**Mark overdue** (option 4). Only the book ID is asked for; the member
is taken from the open loan. The action is refused if the book is not on
loan, is already marked overdue, or its loan period has not passed yet
(14 days after the `BORROWED` block's timestamp). The period can be
shortened for a demo with `-DLOAN_PERIOD_SECONDS=60`. An overdue book can
still be returned normally.

None of the three ever modifies an existing block. A return does not
"close" the borrow block; it adds a new one. The full history of every
book is always on the chain.

## Persistence

The chain is stored in `chain.txt`, one block per line, fields separated
by `|`, the signature as hex:

```
index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signature_hex|hash
```

Design choices:

- **Plain text instead of `fwrite` of the struct.** A binary dump would
  depend on struct padding and `time_t` size, so it would not be portable
  between compilers or machines. Text also means tampering can be shown
  in the video with a normal text editor.
- **Append only.** `append_block()` opens the file in `"a"` mode and adds
  one line. Existing lines are never rewritten, which mirrors how a
  blockchain grows.
- **Write before commit.** The new block is written to disk first and
  only added to the in-memory array if the write and `fclose()` both
  succeed. A failed write therefore never leaves the program showing a
  record that was not saved.
- **Strict loading.** `load_chain()` parses every field and refuses to
  start if a line is malformed (wrong field count, non-numeric index,
  invalid hex signature, a field too long for its array), reporting the
  line number. It does not try to repair the file: a chain that cannot
  be parsed cannot be trusted.

The keys are persisted in `keys/` as PEM files, the standard format that
the `openssl` command line tool can also read:

```
openssl pkey -in keys/librarian_private.pem -noout -text   # asks for the passphrase
openssl pkey -pubin -in keys/librarian_public.pem -noout -text
```

## Chain validation

`validate_chain()` checks four things on every block:

| Check | Catches |
|---|---|
| `index` equals the position in the array | blocks deleted, inserted or reordered |
| stored `hash` equals a freshly computed hash | any edit to any field of that block |
| `previous_hash` equals the previous block's `hash` (64 zeros for block 0) | a block replaced or removed, a broken link |
| signature verifies with the librarian's public key | edits followed by rehashing, blocks forged without the key |

The first three are the two checks asked for plus an index
check; the fourth is what makes the chain resist a determined attacker,
as the next section shows.

The printed report shows the result of each check per block, the stored
and recomputed hashes when they differ, and names the first tampered
block. The same function runs silently at startup and before every write.

## Tamper detection, analysed

Option 7 runs a two-step attack on a copy of the chain in memory
(`chain.txt` is not modified):

**Step 1: naive edit.** The chosen block's action is flipped, for
example `BORROWED` to `RETURNED` (the "quietly mark a lost book as
returned" scenario). Validation shows:

```
Block 1    index OK    hash FAIL  link OK    signature FAIL  <-- TAMPERED
           stored hash     d50ce94449cfc54caf370eed7d9caa4e36090f2ceef69e7d4e72aef70635aedf
           recomputed hash 044a316544f6d139b66314d4e808070a94366a64c5c67bda01d51eae2780be40
Block 2    index OK    hash OK    link OK    signature OK
```

The stored hash no longer matches the data. Changing one field changed
the entire hash (the avalanche property of SHA-256).

**Step 2: the attacker rehashes.** A smarter attacker recomputes the hash
of the edited block and every block after it, updating each
`previous_hash` so the links line up. This is cheap: SHA-256 takes
microseconds, and there is no proof of work in this project. Validation
now shows:

```
Block 1    index OK    hash OK    link OK    signature FAIL  <-- TAMPERED
Block 2    index OK    hash OK    link OK    signature FAIL  <-- TAMPERED
Block 3    index OK    hash OK    link OK    signature FAIL  <-- TAMPERED
```

Every hash and link is consistent again, so the hash and link checks
would both pass. Only the signatures catch it: block 1's signed
data changed, and blocks 2 and 3 now have a different `previous_hash`
from the one that was signed. Making them valid again would need the
librarian's private key.

This is the key takeaway of the project: **hash linking alone makes
tampering visible only if someone kept the original hashes. Signatures
make it detectable from the chain alone.**

A manual edit of `chain.txt` behaves like step 1, and is caught at
startup:

```
WARNING: chain.txt failed validation. Use option 6 for details. New records are blocked.
```

Blocking writes on an invalid chain matters: appending a new block to a
tampered chain would link a legitimate record to forged history.

## Error handling

The strategy is: validate every input at the boundary where it enters
the program, report exactly what is wrong, and never leave the chain or
its file in a half-written state.

| Situation | Behaviour |
|---|---|
| `books.txt` or `members.txt` missing | error with the OS reason, exit |
| registry file empty or no valid lines | error, exit |
| malformed, too long or duplicate registry line | warning with line number, line skipped |
| unknown book or member ID | `ERROR: Book or Member not found`, nothing recorded |
| borrowing a book already on loan | error naming the current borrower |
| returning a book not on loan, or by the wrong member | error, nothing recorded |
| marking overdue too early | error showing the due date |
| wrong passphrase | 3 attempts, then the action is cancelled |
| private key does not match public key | error, login refused |
| `chain.txt` line cannot be parsed | error with line number, exit |
| chain fails validation | warning at startup, all writes refused |
| writing `chain.txt` fails | error, block not added to memory |
| chain full (1000 blocks) | error, nothing recorded |
| input longer than the buffer | rest of the line discarded, so it cannot spill into the next prompt |
| end of input (Ctrl+D) | clean exit |

All OpenSSL calls have their return values checked, and every key and
context is freed. The program was also run under AddressSanitizer and
UndefinedBehaviorSanitizer through a full session with no reports.

## Limitations

Being honest about what this design does not cover:

- **The public key is the trust anchor.** Someone with write access to
  the folder could generate their own key pair, replace
  `librarian_public.pem`, and re-sign a forged chain. Real systems solve
  this by publishing the public key (or its fingerprint) somewhere the
  attacker cannot change, or by having many independent nodes hold the
  chain.
- **Single node, no consensus.** There is one copy of the chain. Deleting
  the last few lines of `chain.txt` produces a shorter chain that is still
  valid. A distributed blockchain prevents this because other nodes still
  hold the longer chain.
- **One signer.** All blocks are signed by the librarian. Having the
  borrower also sign would prove the member agreed to the record, which
  would settle the "borrower disputes the log" case.
