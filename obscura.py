import argparse
import base64
import os
import uuid
from functools import partial

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt(key, item):
  assert os.path.exists(item)
  try:
    f = Fernet(key)
  except ValueError:
    print("Invalid key")
    return
  with open(item, "rb") as fh:
    contents = fh.read()
  try:
    f.decrypt(bytes(item.name.encode()))
    f.decrypt(contents)
  except InvalidToken:
    return {
      "uuid": str(uuid.uuid4()),
      "filename": f.encrypt(bytes(item.name.encode())),
      "content": f.encrypt(contents),
    }


def decrypt(key, item):
  assert os.path.exists(item)
  with open(item, "rb") as fh:
    contents = fh.read()
  with open(item.path + "-filename", "rb") as fh:
    filename = fh.read()
  try:
    f = Fernet(key)
    return {
      "filename": f.decrypt(filename).decode(),
      "content": f.decrypt(contents),
    }
  except ValueError:
    print("Invalid key")
  except InvalidToken:
    print("Invalid password")


def write_file(is_encrypt, item, res):
  if is_encrypt:
    with open(item.path.replace(item.name, res["uuid"]), "wb") as f:
      f.write(res["content"])
    with open(item.path.replace(item.name, res["uuid"] + "-filename"), "wb") as f:
      f.write(res["filename"])
  else:
    with open(item.path.replace(item.name, res["filename"]), "wb") as f:
      f.write(res["content"])


def get_key(password):
  salt = b"!S\x04\xfd7Q\xd8\xefAD%\xde\xae\xe4\x97\x05"
  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
  return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_files(is_encrypt, directory):
  if is_encrypt:
    files = sorted(
      [f for f in os.scandir(directory)],
      key=lambda x: [not x.is_file(), x.stat().st_size],
    )
  else:
    dirs = [f for f in os.scandir(directory) if f.is_dir()]
    files = [
      f
      for f in os.scandir(directory)
      if f.is_file() and not f.name.endswith("-filename")
    ]
    files = [f for f in files if os.path.exists(f.path + "-filename")] + dirs
    files.sort(key=lambda x: [not x.is_file(), x.stat().st_size])
  return files


def obscura(command, directory, depth=0, max_depth=100):
  cmd, prompt, is_encrypt = command
  print(f"scanning {directory}")
  files = get_files(is_encrypt, directory)

  if len(files) > 0 and files[0].is_file():
    res = cmd(files[0])
    if res is None:
      return

  for item in files:
    if item.is_dir():
      if depth < max_depth:
        obscura(command, item.path, depth + 1, max_depth)
      continue
    print(f"{prompt} {item.name}")
    res = cmd(item)
    if res is not None:
      write_file(is_encrypt, item, res)
      os.remove(item)
      if not is_encrypt:
        os.remove(item.path + "-filename")


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("directory", type=str)
  parser.add_argument("-p", "--password", dest="password", type=str, required=True)
  parser.add_argument("-d", "--max-depth", dest="max_depth", type=int, default=100)
  parser.add_argument("-e", "--encrypt", action="store_true")
  return parser.parse_args()


def main():
  args = parse_args()
  key = get_key(args.password)
  cmd = (
    (partial(encrypt, key), "encrypting", True)
    if args.encrypt
    else (partial(decrypt, key), "decrypting", False)
  )
  obscura(cmd, args.directory, 0, args.max_depth)


if __name__ == "__main__":
  main()
