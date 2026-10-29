#
# Copyright 2026 Entrust Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding

def create_byok_blob(keyid: str, wrapped_key_file: str) -> None:
    with open(wrapped_key_file, "rb") as f:
        wrapped_key = f.read()
    urlsafe_b64_wrappedkey = base64.urlsafe_b64encode(wrapped_key).decode('utf-8')
    json_blob = {
            "schema_version": "1.0.0",
            "header": {
                "kid": keyid,
                "alg": "dir",
                "enc": 'CKM_RSA_AES_KEY_WRAP'
            },
            "ciphertext": urlsafe_b64_wrappedkey,
            "generator": "Entrust KeyControl"
    }
    byok_blob = json.dumps(json_blob).encode('utf-8')
    byok_filename = wrapped_key_file.split(".")[0]
    byok_filename = byok_filename + ".byok"
    with open(byok_filename, "wb") as outfile:
        outfile.write(byok_blob)

    print(f"BYOK blob created: {byok_filename}")

def unwrap_key(wrapped_key_path: str, wrapping_privkey_path: str) -> None:
    with open(wrapping_privkey_path) as fp:
        wrapping_privkey = fp.read()
    with open(wrapped_key_path, "rb") as fp:
        wrapped_key = fp.read()

    private_key = serialization.load_pem_private_key(wrapping_privkey.encode(), password=None)
    key_len = private_key.key_size // 8
    wrapped_wrapping_key = wrapped_key[:key_len]
    wrapped_target_key = wrapped_key[key_len:]
    unwrapped_wrapping_key = private_key.decrypt(wrapped_wrapping_key, OAEP(mgf=MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None))
    unwrapped_key = aes_key_unwrap_with_padding(unwrapped_wrapping_key, wrapped_target_key, backend=None)

    try:
        target_key = serialization.load_der_private_key(unwrapped_key, password=None)
        target_key_bytes = target_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    except:
        print("Failed to load unwrapped key as a private key. This interface is only supported for asymmetric keys.")
        return

    byok_filename = wrapped_key_path.split(".")[0]
    byok_filename = byok_filename + ".pem"
    with open(byok_filename, "wb") as outfile:
        outfile.write(target_key_bytes)

    print(f"BYOK key file created: {byok_filename}")

if __name__ == "__main__":
    parser =  argparse.ArgumentParser(description='Prepare a wrapped key exported from an Azure Local Keyset for upload to a Keyvault')
    parser.add_argument('--hsm', help='Prepare key for upload as an hsm protected key in Managed HSM or Premium Keyvault', action='store_true')
    parser.add_argument('--wrapped_key', help='File containing the wrapped key', required=True)
    parser.add_argument('--keyid', help='Key ID (kid) for the BYOK blob. Required if using the --hsm option', required=False)
    parser.add_argument('--wrapping_key', help='File containing the wrapping private key. Required if not using the --hsm option', required=False)

    args = parser.parse_args()
    wrapped_key_path = args.wrapped_key
    if args.hsm:
        if not args.keyid:
            raise ValueError("Key ID (kid) is required for HSM upload")
        kek_id = args.keyid
        create_byok_blob(kek_id, wrapped_key_path)
    else:
        if not args.wrapping_key:
            raise ValueError("Wrapping private key is required for non-HSM upload")
        wrapping_privkey_path = args.wrapping_key
        unwrap_key(wrapped_key_path, wrapping_privkey_path)
