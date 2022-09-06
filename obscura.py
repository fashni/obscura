import argparse
import base64
import uuid
from functools import partial
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt(key, item):
  assert item.exists()

  try:
    f = Fernet(key)
  except ValueError:
    print("Invalid key")
    return
  with item.open("rb") as fh:
    contents = fh.read()
  try:
    f.decrypt(item.name.encode())
    f.decrypt(contents)
  except InvalidToken:
    return {
      "uuid": str(uuid.uuid4()),
      "filename": f.encrypt(item.name.encode()),
      "content": f.encrypt(contents),
    }


def decrypt(key, item):
  assert item.exists()
  assert item.suffix == ".encrypted"
  assert item.with_suffix(".filename").exists()

  with item.open("rb") as fh:
    contents = fh.read()
  with item.with_suffix(".filename").open("rb") as fh:
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


def write_file(item, res, is_encrypt):
  if is_encrypt:
    with (item.parent / res["uuid"]).with_suffix(".encrypted").open("wb") as fh:
      fh.write(res["content"])
    with (item.parent / res["uuid"]).with_suffix(".filename").open("wb") as fh:
      fh.write(res["filename"])
  else:
    with (item.parent / res["filename"]).open("wb") as fh:
      fh.write(res["content"])


def get_key(password):
  salt = b"!S\x04\xfd7Q\xd8\xefAD%\xde\xae\xe4\x97\x05"
  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
  return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_files(directory, is_encrypt):
  if is_encrypt:
    files = sorted(
      [f for f in directory.iterdir()],
      key=lambda x: [not x.is_file(), x.stat().st_size],
    )
  else:
    dirs = [f for f in directory.iterdir() if f.is_dir()]
    files = [
      f for f in directory.iterdir() if f.is_file() and f.suffix == ".encrypted"
    ]
    files = [f for f in files if f.with_suffix(".filename").exists()] + dirs
    files.sort(key=lambda x: [not x.is_file(), x.stat().st_size])
  return files


def execute(command, item):
  cmd, prompt, is_encrypt = command
  print(f"{prompt} {item.name}")
  res = cmd(item)
  if res is None:
    return
  write_file(item, res, is_encrypt)
  item.unlink()
  if not is_encrypt:
    item.with_suffix(".filename").unlink()


def execute_dir(command, directory, depth=0, max_depth=100):
  cmd, _, is_encrypt = command
  print(f"scanning {directory}")
  files = get_files(directory, is_encrypt)

  if len(files) > 0 and files[0].is_file():
    res = cmd(files[0])
    if res is None:
      return

  for item in files:
    if item.is_file():
      execute(command, item)
      continue
    if depth < max_depth:
      execute_dir(command, item, depth + 1, max_depth)


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("directory", nargs="*", type=str)
  parser.add_argument("-p", "--password", dest="password", type=str, required=True)
  parser.add_argument("-d", "--max-depth", dest="max_depth", type=int, default=100)
  parser.add_argument("-e", "--encrypt", action="store_true")
  return parser.parse_args()


def main(args):
  key = get_key(args.password)
  cmd = (
    (partial(encrypt, key), "encrypting", True)
    if args.encrypt
    else (partial(decrypt, key), "decrypting", False)
  )
  for d in args.directory:
    item = Path(d)
    if not item.exists():
      continue
    if item.is_file():
      execute(cmd, item)
    elif item.is_dir():
      execute_dir(cmd, item, 0, args.max_depth)


if __name__ == "__main__":
  args = parse_args()
  main(args)
