# Backup and vault format notes

This document describes what `avb` reads and writes, so a future recovery does
not depend on this particular implementation. It is a compatibility note, not
a formal specification. The authoritative implementation is AliasVault's
AGPL-licensed Rust/TypeScript source.

All binary values in JSON are standard base64 unless a field says otherwise.
All AES-GCM payloads use a 12-byte IV and a 16-byte tag, stored as:

```
IV (12 bytes) | ciphertext | tag (16 bytes)
```

The associated data (AAD) is empty unless listed below.

## 1. `.avex` encrypted export

An `.avex` file is:

```
<UTF-8 JSON header>
\n-----BEGIN ENCRYPTED DATA-----\n
<IV | ciphertext | tag>
```

The delimiter is exactly 32 bytes:

```
\n-----BEGIN ENCRYPTED DATA-----\n
```

### Header

```json
{
  "format": "avex",
  "version": "1.0.0",
  "kdf": {
    "type": "Argon2Id",
    "salt": "base64-of-random-32-bytes",
    "params": {
      "DegreeOfParallelism": 1,
      "MemorySize": 262144,
      "Iterations": 3
    }
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "encryptedDataOffset": 1234
  },
  "metadata": {
    "exportedAt": "2026-11-12T12:34:56.789Z",
    "appVersion": "aliasvault-backup/0.1.0"
  }
}
```

- `encryptedDataOffset` is the byte offset from the start of the file to the
  first ciphertext byte, i.e. header length plus delimiter length.
- The Argon2id salt is not decoded for the KDF. The **UTF-8 bytes of the base64
  string** are the salt, matching AliasVault's exporter.
- The password is the UTF-8 bytes of the user-entered password.
- Key: 32-byte Argon2id output (`version=19`, type `ID`) using the header
  parameters.
- Encryption: AES-256-GCM with that key and empty AAD.
- Plaintext: the bytes of an `.avux` ZIP archive.

`avb` enforces minimum KDF costs of 19456 KiB, 2 iterations, and parallelism 1
before deriving a key.

## 2. `.avux` unencrypted ZIP

The ZIP contains one required file and optional attachment/logo files:

```
manifest.json
attachments/<item-id>_<attachment-id>_<filename>
logos/<source>_<logo-id>.png
```

`manifest.json` has version `"1.0.0"` and these top-level arrays:

```json
{
  "version": "1.0.0",
  "exportedAt": "2026-11-12T12:34:56.789Z",
  "items": [],
  "folders": [],
  "tags": [],
  "itemTags": [],
  "fieldDefinitions": [],
  "logos": []
}
```

### Item

```json
{
  "id": "guid",
  "name": "Example login",
  "itemType": "Login",
  "createdAt": "2026-01-01T00:00:00.000Z",
  "updatedAt": "2026-01-01T00:00:00.000Z",
  "folderId": null,
  "logoId": null,
  "archivedAt": null,
  "fieldValues": [],
  "fieldHistories": [],
  "attachments": [],
  "totpCodes": [],
  "passkeys": []
}
```

`itemType` is one of `Login`, `Alias`, `CreditCard`, or `Note` in the official
client. Passwords are plaintext in `fieldValues[].value`; system field keys
include `login.username`, `login.password`, `login.url`, and `login.notes`.
Custom values use `fieldDefinitionId`.

### Field value and history

```json
{
  "id": "guid",
  "fieldKey": "login.username",
  "fieldDefinitionId": null,
  "value": "alice@example.com",
  "weight": 0
}
```

```json
{
  "id": "guid",
  "fieldKey": "login.password",
  "fieldDefinitionId": null,
  "valueSnapshot": "old-password",
  "changedAt": "2026-01-01T00:00:00.000Z"
}
```

Multi-value fields can share `fieldKey` and `fieldDefinitionId`; their `id` is
the identity. `weight` is an integer sort order.

### Folder, tag, and item-tag

```json
{ "id": "guid", "name": "Work", "parentFolderId": null, "weight": 0,
  "createdAt": "...", "updatedAt": "..." }
```

```json
{ "id": "guid", "name": "Important", "color": "#ff0000",
  "displayOrder": 0, "createdAt": "...", "updatedAt": "..." }
```

```json
{ "id": "guid", "itemId": "guid", "tagId": "guid" }
```

The official importer treats `itemTags` links as many-to-many. `avb` exports
the existing links; it does not preserve the original link row id, because the
`.avux` schema only needs a unique association id.

### Custom field definition

```json
{
  "id": "guid",
  "fieldType": "text",
  "label": "PIN",
  "isMultiValue": false,
  "isHidden": true,
  "enableHistory": false,
  "weight": 0,
  "applicableToTypes": null
}
```

`applicableToTypes` is a JSON-array string or null.

### Attachment

```json
{
  "id": "guid",
  "filename": "note.txt",
  "relativePath": "attachments/<item-id>_<attachment-id>_note.txt"
}
```

The file bytes at `relativePath` must exist for a valid export. `.avux` files
are plaintext; the outer `.avex` layer is what encrypts them.

### TOTP code

```json
{
  "id": "guid",
  "name": "Example",
  "secretKey": "BASE32SECRET",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30
}
```

### Passkey

Byte fields are base64 strings; `null` means absent.

```json
{
  "id": "guid",
  "credentialId": "base64",
  "rpId": "example.com",
  "userHandle": "base64",
  "publicKey": "...",
  "privateKey": "...",
  "prfKey": "base64",
  "displayName": "Laptop",
  "additionalData": "base64"
}
```

### Logo

```json
{
  "id": "guid",
  "kind": "favicon",
  "source": "example.com",
  "name": null,
  "mimeType": "image/png",
  "fetchedAt": "2026-01-01T00:00:00.000Z",
  "relativePath": "logos/example.com_<logo-id>.png"
}
```

Built-in logos may have no corresponding file. Custom and fetched logos should
have one.

## 3. Account key chain

The server's unlock-method response (`v2/UnlockMethod/password`, or the older
`v2/VaultKey/password`) contains:

```json
{
  "type": "password",
  "algorithm": "aes256-gcm",
  "salt": "hex",
  "encryptionType": "Argon2Id",
  "encryptionSettings": "{\"MemorySize\":262144,\"Iterations\":3,\"DegreeOfParallelism\":1}",
  "encryptedAccountKey": "base64",
  "encryptedVek": "base64",
  "encryptedAccountPrivateKey": "base64",
  "encryptedSigningPrivateKey": "base64",
  "accountPublicKey": "{...RSA JWK...}",
  "signingPublicKey": "base64"
}
```

Derivation:

1. `unlockKey = Argon2id(UTF8(password), UTF8(salt), MemorySize, Iterations,
   DegreeOfParallelism)`. As with `.avex`, `salt` is the **hex text** from the
   server; its UTF-8 characters are hashed, not the bytes obtained by decoding
   the hex.
2. `KEK = HKDF-SHA256(ikm=unlockKey, salt=empty, info=b"AliasVault KEK v1")`.
3. `accountKey = AES-GCM-decrypt(encryptedAccountKey, KEK,
   AAD=b"aliasvault/v1/account-key")`. The plaintext is a 32-byte base64 key.
4. `personalVEK = AES-GCM-decrypt(encryptedVek, accountKey,
   AAD=b"aliasvault/v1/vek")`.
5. `accountPrivateKey = AES-GCM-decrypt-text(encryptedAccountPrivateKey,
   accountKey, AAD=b"aliasvault/v1/account-private-key")`.
6. `signingPrivateSeed = AES-GCM-decrypt(encryptedSigningPrivateKey,
   accountKey, AAD=b"aliasvault/v1/account-signing-private-key")`; the Ed25519
   public key is derived from the 32-byte seed.

For SRP:

- `Argon2Id`: `srpPasswordHash = uppercase-hex(unlockKey)`.
- `Argon2IdHkdf`: `srpPasswordHash = uppercase-hex(HKDF-SHA256(unlockKey,
  info=b"AliasVault SRP v1"))`.

`salt` is hex here, not base64. The SRP private value is
`x = SHA256(hexDecode(salt) | SHA256(lower(identity) | ":" | srpPasswordHash))`.

## 4. Vault snapshot frame

`GET /v2/Vault` returns a binary frame:

```
4-byte big-endian header length N
N bytes of UTF-8 JSON header
concatenated ciphertext parts
```

Each part in the header's `manifests`, `buckets`, or `blobs` array has `offset`
and `size` fields relative to the start of the body (after the header). The
actual bytes at that range are the encrypted part. `avb` attaches them as
`_data` internally.

A manifest header entry includes:

```json
{
  "manifestId": "guid",
  "ciphertextHash": "hex-sha256",
  "revision": 12,
  "blobReferences": [
    {"hash": "hex", "category": "attachment", "sizeBytes": 123}
  ],
  "keyType": "grant-key",
  "encryptedVek": "base64",
  "algorithm": "rsa-oaep-sha256",
  "accountPublicKey": "{...RSA JWK...}",
  "grantSignature": "base64",
  "grantSignerUserId": "guid",
  "keyVersion": 1
}
```

The personal manifest's VEK does not travel in this response for an
account-key entry; it comes from the password key chain.

Buckets have `manifestId`, `category`, `ciphertextHash`, `revision`, and data.

### Manifest payload

1. If `ciphertextHash` is present, check
   `SHA256(ciphertext).lower() == ciphertextHash.lower()`.
2. Decrypt with the manifest VEK:
   `AAD = b"aliasvault/v1/manifest/" + lower(manifestId)`.
3. The plaintext is a gzip stream. Decompress with a size limit.
4. The decompressed JSON envelope is:

```json
{
  "schemaVersion": 1,
  "contentHash": "hex-sha256",
  "payload": {
    "manifestId": "guid",
    "manifestSalt": "hex",
    "canonicalizedAt": "...",
    "tables": {
      "Items": [],
      "Folders": [],
      "Tags": [],
      "FieldValues": [],
      "FieldHistories": [],
      "FieldDefinitions": [],
      "Attachments": [],
      "TotpCodes": [],
      "Passkeys": [],
      "Logos": [],
      "ItemTags": []
    }
  }
}
```

5. Verify `contentHash` against the canonical JSON of `payload`. Keys are
   sorted recursively, arrays keep order, compact separators, and no trailing
   newline. The hash is SHA-256 over UTF-8.
6. The payload's declared `manifestId` must match the frame's manifest id.

The Rust codec represents inline bytes as `{"__b64": "<base64>"}` and extracted
blob columns as `{"__blobRef": "<hash>", "__blobKind": "attachment|logo"}`.
Rows have a nullable `IsDeleted` flag; the `.avux` exporter omits deleted rows.

### Bucket payload

Buckets carry tables that are kept out of the manifest (AliasVault currently
uses the `settings` and `stats` categories). They use the same envelope and
checks, with:

```
AAD = b"aliasvault/v1/bucket/" + lower(manifestId) + "/" + category
```

The payload must declare the same `manifestId` and `category`.

### Blob

A blob frame's `blobs` entries contain `hash`, `category`,
`encryptedBlobKey`, and the ciphertext.

1. `blobKey = AES-GCM-decrypt(encryptedBlobKey, VEK,
   AAD=b"aliasvault/v1/blob-key/" + lower(manifestId) + "/" + lower(hash))`.
2. `plaintext = AES-GCM-decrypt(ciphertext, blobKey,
   AAD=b"aliasvault/v1/blob/" + lower(manifestId) + "/" + lower(hash))`.
3. Verify the address:
   `HMAC-SHA256(key=hexDecode(payload.manifestSalt), message=plaintext).hexdigest()
   == lower(hash)`.

The manifest salt comes from the decrypted manifest payload. A missing or
mismatched blob makes the snapshot incomplete.

## 5. Shared manifests

For a non-personal manifest with `keyType = "grant-key"` and
`algorithm = "rsa-oaep-sha256"`, the VEK is encrypted to the account RSA key:

```
VEK = RSA-OAEP-SHA256-decrypt(
  encryptedVek,
  accountPrivateKey,
  label=b"aliasvault/v1/grant/" + lower(manifestId)
)
```

The grant signature is Ed25519 over a length-prefixed message:

```
label = "aliasvault/v1/sig/grant"
fields = [lower(manifestId), str(keyVersion), signerUserId,
          recipientPublicKey, algorithm, encryptedVek]
message = for each field: uint32-big-endian length | UTF-8 bytes
```

The signature must verify with the account's signing public key. `avb` refuses
an unsigned or invalid grant rather than trusting a shared manifest.

## 6. Raw `.avbak` snapshot

A raw snapshot is a ZIP with:

```
meta.json
unlock-method.json
vault.frame
blobs/<manifest-id>.frame
RECOVERY.txt
```

`meta.json`:

```json
{
  "format": "aliasvault-raw-backup",
  "version": 1,
  "createdAt": "2026-11-12T12:34:56.789Z",
  "toolVersion": "0.1.0",
  "apiUrl": "https://app.aliasvault.com/api",
  "username": "you@example.com",
  "storageFormat": "manifest",
  "personalManifestId": "guid",
  "manifestIds": ["guid"],
  "blobFrames": ["manifest-id"]
}
```

`unlock-method.json` is the password unlock-method object exactly as served, or
`null`. `vault.frame` is the exact `GET /v2/Vault` response. Each
`blobs/<manifest-id>.frame` is a valid binary frame containing that manifest's
encrypted blobs; if the server needed multiple download batches, the frames are
recombined with the same ciphertext bytes and new offsets.

The raw snapshot deliberately preserves the encrypted key hierarchy and the
server's ciphertexts. Converting it offline needs the master password; it is
not a plaintext export.

## 7. Compatibility and change policy

- This tool reads `.avex` version `1.0.0`, `.avux` version `1.0.0`, and raw
  snapshot version `1`.
- It rejects unknown payload schema versions instead of guessing.
- It verifies ciphertext hashes, content hashes, blob addresses, and grant
  signatures before using data.
- ZIP entry paths with `..`, absolute paths, or empty components are rejected
  during `.avex` verification and extraction.
