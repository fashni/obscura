import argparse
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm


def encrypt(key, item):
  assert os.path.exists(item)
  try:
    f = Fernet(key)
  except ValueError as e:
    print("Invalid key")
    return
  with open(item, "rb") as fh:
    contents = fh.read()
  try:
    f.decrypt(bytes(item.name.encode()))
    f.decrypt(contents)
  except InvalidToken:
    return {
      "filename": f.encrypt(bytes(item.name.encode())).decode(),
      "content": f.encrypt(contents),
    }

def decrypt(key, item):
  assert os.path.exists(item)
  with open(item, "rb") as fh:
    contents = fh.read()
  try:
    f = Fernet(key)
    return {
      "filename": f.decrypt(bytes(item.name.encode())).decode(),
      "content": f.decrypt(contents),
    }
  except ValueError:
    print("Invalid key")
  except InvalidToken:
    print("Invalid password")

def write_file(item, res):
  with open(item.path.replace(item.name, res["filename"]), "wb") as f:
    f.write(res["content"])

def get_key(password):
  salt = b'!S\x04\xfd7Q\xd8\xefAD%\xde\xae\xe4\x97\x05'
  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
  return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("directory", type=str)
  parser.add_argument("-p", "--password", dest="password", type=str, required=True)
  parser.add_argument("-e", "--encrypt", action="store_true", help=argparse.SUPPRESS)
  return parser.parse_args()

def main():
  args = parse_args()
  key = get_key(args.password)
  files = sorted([f for f in os.scandir(args.directory) if f.is_file()], key=lambda x: x.stat().st_size)

  cmd = encrypt if args.encrypt else decrypt
  ops = "encrypting" if args.encrypt else "decrypting"

  res = cmd(key, files[0])
  if res is None:
    return

  pbar = tqdm(files)
  for item in pbar:
    pbar.set_description(f"{ops} {item.name[:20]+(item.name[20:] and '...')}")
    res = cmd(key, item)
    if res is not None:
      write_file(item, res)
      os.remove(item)


if __name__=="__main__":
  main()
