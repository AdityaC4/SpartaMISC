import os
from Crypto.PublicKey import ECC
from Crypto.Util.number import long_to_bytes
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from pathlib import Path
import binascii 

ECC_PRIVSIZE = 32

def main():
	header_dir = Path("inc/")
	header_path = header_dir / "ectf_keys.h" 

	deployment_dir = Path("../deployment")

	# Read in host private key
	f = open(deployment_dir / "host_private_key.pem")
	data = f.read()
	host_private_key = ECC.import_key(data)
	f.close()

	ap_private_key = ECC.generate(curve='secp256r1')
	ap_public_key = ap_private_key.public_key()

	ap_public_key_bytes = long_to_bytes(ap_public_key._point.x, ECC_PRIVSIZE) + long_to_bytes(ap_public_key._point.y, ECC_PRIVSIZE)

	# identifier for AP
	dev_id = 0xffffffff

	dev_id_bytes = dev_id.to_bytes(4, 'little')

	cert_data = ( ap_public_key_bytes + dev_id_bytes )

	# Generate signature
	h = SHA256.new(cert_data)
	signer = DSS.new(host_private_key, 'fips-186-3', 'der')
	signature = signer.sign(h)

	# Get host public key in DER format
	host_public_key_der = host_private_key.public_key().export_key(format='DER')

	# Get ap private key in DER format
	ap_private_key_der = ap_private_key.export_key(format='DER')

	# Get ap public key in DER format
	ap_public_key_der = ap_public_key.export_key(format='DER')

	print("HELLO FROM BUILD.PY")
	print(f"HOST PUBLIC KEY DER of length {len(host_public_key_der)}:")
	print(host_public_key_der)
	print(f"AP PUBLIC KEY DER of length {len(ap_public_key_der)} :")
	print(ap_public_key_der)
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
		fp.write(f"#define AP_PRIVKEY_DER {{ {to_bytearray(ap_private_key_der)} }}  \n")
		fp.write(f"#define HOST_PUBKEY_DER {{ {to_bytearray(host_public_key_der)} }} \n")
		fp.write(f"#define CERT_SIGNATURE {{ {to_bytearray(signature)} }} \n")
		fp.write("#endif\n")


if __name__ == "__main__":
	main()
