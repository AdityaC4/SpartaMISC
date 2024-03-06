import os
from Crypto.PublicKey import ECC
from Crypto.Util.number import long_to_bytes
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256
from pathlib import Path
import binascii 
import re

ECC_PRIVSIZE = 32

def main():
    header_dir = Path("inc/")
    header_path = header_dir / "ectf_keys.h" 

    # Get component ID
    component_id = -1

    ectf_params_path = header_dir / "ectf_params.h"
    regex = re.compile(r"#define COMPONENT_ID\s*(.*)\s")
    with open(ectf_params_path, "r") as f:
        data = f.read()

        # debugging
        print("HEADER CONTENTS")
        print(data)

        match = re.search(r'#define\s+COMPONENT_ID\s+(\d+)', data)
        if match:
            component_id = int(match.group(1), 0)
        else:
            raise Exception("Could not parse component id from header!");

    print(f"EXTRACTED COMPONENT ID {component_id}")

    deployment_dir = Path("../deployment")

    # Read in host private key
    f = open(deployment_dir / "host_private_key.pem")
    data = f.read()
    host_private_key = ECC.import_key(data)
    f.close()

    comp_private_key = ECC.generate(curve='ed25519')
    comp_public_key = comp_private_key.public_key()

    comp_public_key_bytes = comp_public_key.export_key(format='raw') # Export 32 byte Ed25519 public key

    # Component ID
    dev_id = component_id

    dev_id_bytes = dev_id.to_bytes(4, 'little')

    cert_data = ( comp_public_key_bytes + dev_id_bytes ) # 32 + 4 = 36 bytes

    # Generate signature
    h = SHA256.new(cert_data)
    signer = eddsa.new(host_private_key, 'rfc8032')
    signature = signer.sign(h.digest())

    # Get host public key in DER format
    host_public_key_der = host_private_key.public_key().export_key(format='DER')

    # Get component private key in DER format
    comp_private_key_der = comp_private_key.export_key(format='DER')

    # Get component public key in DER format
    comp_public_key_der = comp_public_key.export_key(format='DER')

    print("HELLO FROM BUILD.PY")
    print(f"HOST PUBLIC KEY DER of length {len(host_public_key_der)}:")
    print(host_public_key_der)
    print(f"COMP PUBLIC KEY DER of length {len(comp_public_key_der)} :")
    print(comp_public_key_der)
    print(f"CERTIFICATE DATA OF LENGTH {len(cert_data)}")
    print(cert_data)
    print(f"CERTIFICATE HASH OF LENGTH {len(h.digest())}")
    print(h.hexdigest())
    print(f"SIGNATURE OF CERTIFICATE of length {len(signature)}:")
    print(binascii.hexlify(bytearray(signature)))

    to_bytearray = lambda d: ','.join(hex(b) for b in d)

    with open(header_path, "w") as fp:
        fp.write("#ifndef __DEV_KEYS__\n")
        fp.write("#define __DEV_KEYS__\n")
        fp.write(f"#define COMP_PRIVKEY_DER {{ {to_bytearray(comp_private_key_der)} }}  \n")
        fp.write(f"#define HOST_PUBKEY_DER {{ {to_bytearray(host_public_key_der)} }} \n")
        fp.write(f"#define COMP_CERT_SIGNATURE {{ {to_bytearray(signature)} }} \n")
        fp.write("#endif\n")


if __name__ == "__main__":
    main()
