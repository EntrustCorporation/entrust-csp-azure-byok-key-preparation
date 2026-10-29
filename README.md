# Entrust CSP Azure BYOK Key Preparation

This utility prepares a wrapped key exported from an Azure Local Keyset for use with an Azure Key Vault or Managed HSM. It supports two workflows:

- **HSM-protected upload:** package the wrapped key as an Azure BYOK JSON blob.
- **Non-HSM upload:** unwrap an asymmetric private key and write it as a PEM file.

The utility creates the artifact for the selected workflow; it does not connect to Azure or upload keys.

## Requirements

- Python 3
- The Python package listed in `requirements.txt` (`cryptography`)

Install the dependency from the repository directory:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run the script with the path to the wrapped key file. The option names use underscores.

### HSM-protected key

For a key intended for upload to a Managed HSM or Premium Key Vault, provide the key ID (`kid`) and the `--hsm` flag:

```bash
python3 azure_byok_prepare_key.py \
  --hsm \
  --wrapped_key ./wrapped-key.bin \
  --keyid "https://example.vault.azure.net/keys/example/key-version"
```

This writes a `.byok` JSON file beside the input. The blob contains schema version `1.0.0`, the supplied `kid`, the `CKM_RSA_AES_KEY_WRAP` encryption identifier, and the wrapped key encoded with URL-safe Base64.

### Non-HSM key

For a non-HSM upload, provide the PEM wrapping private key with `--wrapping_key`:

```bash
python3 azure_byok_prepare_key.py \
  --wrapped_key ./wrapped-key.bin \
  --wrapping_key ./wrapping-private-key.pem
```

The script decrypts the wrapped wrapping key using RSA-OAEP with SHA-1, unwraps the target key with AES key unwrap with padding, and writes the result as an unencrypted PEM private-key file beside the input. This workflow supports asymmetric keys only. The wrapping private key must be an unencrypted PEM key that can be loaded by `cryptography`.

## Output and key handling

The output extension is `.byok` for HSM mode and `.pem` for non-HSM mode. The output name is derived from the supplied wrapped-key path by truncating it at its first period and appending the extension. Use an input path without periods (other than any extension you intend to be discarded) to avoid unexpected output names.

Non-HSM mode writes the recovered private key without encryption. Protect the wrapping private key, wrapped key, and generated PEM file accordingly, and securely remove temporary copies when they are no longer needed.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).