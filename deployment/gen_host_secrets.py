import os
from Crypto.PublicKey import ECC

def main():
	print("Generating host key...")

	key = ECC.generate(curve='secp256r1')

	filename = "host_private_key.pem"

	with open(filename, "wt") as f:
		data = key.export_key(format='PEM')
		f.write(data)

	print("Stored host key in deployment folder")


if __name__ == "__main__":
	main()