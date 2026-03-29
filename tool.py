import os
import json
import hashlib
import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_manifest(directory):
    manifest = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file == "metadata.json":
                continue
            path = os.path.join(root, file)
            manifest[path] = hash_file(path)

    with open("metadata.json", "w") as f:
        json.dump(manifest, f, indent=4)

    print("Manifest created!")

def check_integrity():
    with open("metadata.json", "r") as f:
        manifest = json.load(f)

    modified = False

    for path, old_hash in manifest.items():
        if not os.path.exists(path):
            print(f"Missing file: {path}")
            modified = True
            continue

        new_hash = hash_file(path)
        if new_hash != old_hash:
            print(f"Modified file: {path}")
            modified = True

    if not modified:
        print("All files are intact!")

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated!")

def sign_manifest():
    with open("metadata.json", "rb") as f:
        data = hashlib.sha256(f.read()).digest()  # ✅ FIXED

    with open("private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)

    print("Manifest signed!")

def verify_signature():
    with open("metadata.json", "rb") as f:
        data = hashlib.sha256(f.read()).digest()

    with open("signature.sig", "rb") as f:
        signature = f.read()

    with open("public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature VALID!")
    except Exception:
        print("Signature INVALID!")

parser = argparse.ArgumentParser()

parser.add_argument("--hash")
parser.add_argument("--manifest")
parser.add_argument("--check", action="store_true")
parser.add_argument("--genkeys", action="store_true")
parser.add_argument("--sign", action="store_true")
parser.add_argument("--verify", action="store_true")

args = parser.parse_args()

if args.hash:
    print(hash_file(args.hash))
elif args.manifest:
    generate_manifest(args.manifest)
elif args.check:
    check_integrity()
elif args.genkeys:
    generate_keys()
elif args.sign:
    sign_manifest()
elif args.verify:
    verify_signature()
else:
    print("Use --help")