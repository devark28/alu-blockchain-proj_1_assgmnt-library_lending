# Blockchain-Based Library Book Lending Tracker

A command-line library lending tracker written in C where every borrow,
return and overdue event is stored as a block in a hash-linked chain.
Each block is signed with the librarian's ECDSA key (curve `secp256k1`,
the same curve Bitcoin and Ethereum use) and hashed with SHA-256, so any
edit to a past record is detected the next time the chain is validated.

The project lives in [q1_library_lending/](q1_library_lending/). A
detailed walkthrough of how the code meets each requirement, and why it
was designed the way it was, is in
[q1_library_lending/README.md](q1_library_lending/README.md).

## Features

| Requirement | How it is met |
|---|---|
| Blockchain data structure | `Block` and `Blockchain` structs in `blockchain.h`, genesis block at index 0 with a `previous_hash` of 64 zeros |
| Book and member registries | `books.txt` and `members.txt` loaded into arrays of `Book` and `Member` at startup, with errors for missing, empty or malformed files |
| SHA-256 linking | every block stores the SHA-256 hash of the previous block, and its own hash covers all its fields including the signature |
| Digital signatures | every block is signed with ECDSA over SHA-256 using the librarian's private key |
| Authentication and access control | the private key is stored encrypted (AES-256) under a passphrase; viewing and validating are open, adding blocks requires login |
| Chain validation | checks index, hash, `previous_hash` link and signature of every block and reports the first tampered block |
| CLI | borrow, return, mark overdue, view records, view registries, validate, tamper demo, log out |
| Tamper detection | a built-in demo, plus detection of manual edits to `chain.txt` on startup |
| Persistence | the chain is saved to `chain.txt` (one block per line), keys to `keys/` |

## Requirements

- Linux (tested on Ubuntu 24.04)
- `gcc` (tested with 13.3)
- OpenSSL 3.0 or newer, with development headers (`libssl-dev`)

On Ubuntu or Debian:

```
sudo apt install build-essential libssl-dev
```

OpenSSL 3.0 is required because the code uses `EVP_EC_gen()` and
`EVP_PKEY_eq()`, which do not exist in 1.1.

## Build

From inside `q1_library_lending/`:

```
gcc -Wall -Wextra -o library_tracker main.c registry.c blockchain.c crypto.c utils.c -lcrypto
```

`-lcrypto` links OpenSSL's libcrypto, which provides SHA-256, ECDSA and
the PEM key file functions. No build system is used.

## Run

```
./library_tracker
```

Run it from inside `q1_library_lending/`, because `books.txt`,
`members.txt`, `chain.txt` and `keys/` are opened with relative paths.

**First run.** There are no keys yet, so the program generates a
`secp256k1` key pair and asks for a librarian passphrase (at least 8
characters, typed twice, not echoed). It saves:

- `keys/librarian_private.pem`, encrypted with AES-256 under the
  passphrase, file permissions `0600`
- `keys/librarian_public.pem`, used to verify signatures

It then signs and writes the genesis block to `chain.txt`.

**Later runs.** The public key and the chain are loaded and the chain is
validated silently. If validation fails a warning is printed and new
records are blocked. Borrowing, returning and marking overdue ask for the
passphrase once per session; option 8 logs out.

### Menu

```
===== Library Lending Tracker =====
Books 6 | Members 5 | Blocks 4 | Librarian logged in
  1. View registries
  2. Borrow a book
  3. Return a book
  4. Mark a book overdue
  5. View lending records
  6. Validate chain
  7. Tamper detection demo
  8. Log out
  0. Exit
```

### Demonstrating OVERDUE

The loan period is 14 days, so in a short demo no loan can become
overdue. It can be shortened at compile time without editing the code:

```
gcc -Wall -Wextra -DLOAN_PERIOD_SECONDS=60 -o library_tracker main.c registry.c blockchain.c crypto.c utils.c -lcrypto
```

### Starting over

```
rm -rf chain.txt keys/
```

Deleting only `keys/` while keeping `chain.txt` makes every existing
signature fail validation, because the new public key did not sign them.
That is the expected behaviour.

## File layout

```
q1_library_lending/
  main.c          CLI menu, login and logout, borrow, return, overdue, tamper demo
  blockchain.c/h  Block and Blockchain structs, signing, hashing, validation, chain.txt I/O
  crypto.c/h      SHA-256, ECDSA key generation, key files, sign and verify, hex helpers
  registry.c/h    Book and Member structs, loading and lookup of books.txt and members.txt
  utils.c/h       line splitting, bounded field copy, whitespace trimming
  books.txt       book registry: book_id,title,author
  members.txt     member registry: member_id,full_name,course_code
  chain.txt       created at runtime, the blockchain (not committed)
  keys/           created at runtime, librarian key pair (not committed)
```

## Data formats

`books.txt` and `members.txt` use one record per line, comma separated:

```
BK001,Things Fall Apart,Chinua Achebe
ALU001,John Doe,BLK101
```

`chain.txt` stores one block per line, `|` separated:

```
index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signature_hex|hash
```

For example:

```
1|1790212984|BK001|Things Fall Apart|ALU001|John Doe|BORROWED|635d3800...a87f|3046022100b6aa...90b9|d50ce944...aedf
```

The format is plain text on purpose, so tampering can be demonstrated by
opening the file in any editor.

## Tamper detection

Two ways to see it:

1. **Menu option 7** edits a copy of the chain in memory (flipping a
   block's action between BORROWED and RETURNED) and validates it twice:
   once as-is, where the block's hash no longer matches, and once after
   recomputing every hash after the edit, where hashes and links pass but
   the signature still fails. `chain.txt` is not touched.
2. **Edit `chain.txt` by hand**, for example change `John Doe` to
   `Mallory` on one line, then start the program. It warns that the chain
   failed validation, option 5 shows that block's signature as INVALID,
   option 6 names the tampered block, and new records are refused until
   the file is restored.

## Screenshots

Screenshots are in [images/](images/):

| File | Shows |
|---|---|
| `images/01_first_run.png` | key generation and genesis block |
| `images/02_registries.png` | loaded books and members with loan status |
| `images/03_borrow.png` | a successful borrow and its block hash |
| `images/04_invalid_ids.png` | `ERROR: Book or Member not found` for bad IDs |
| `images/05_return.png` | a return, and the errors for returning a book that is not on loan |
| `images/06_records.png` | lending records with signature validity |
| `images/07_validate.png` | a valid chain |
| `images/08_tamper_demo.png` | option 7, both steps |
| `images/09_file_tamper.png` | startup warning after editing `chain.txt` |
| `images/10_missing_registry.png` | error when `books.txt` is missing or empty |
