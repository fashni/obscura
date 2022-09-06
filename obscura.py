import argparse
import base64
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Obscura:
  salt = b"!S\x04\xfd7Q\xd8\xefAD%\xde\xae\xe4\x97\x05"
  def __init__(self, password, is_encrypt=False):
    self.is_encrypt = is_encrypt
    self.prompt = "encrypting" if self.is_encrypt else "decrypting"
    self.fernet = Fernet(self.get_key(password, self.salt))

  def encrypt(self, item):
    assert item.exists()

    with item.open("rb") as fh:
      contents = fh.read()
    try:
      self.fernet.decrypt(item.name.encode())
      self.fernet.decrypt(contents)
    except InvalidToken:
      return {
        "uuid": str(uuid.uuid4()),
        "filename": self.fernet.encrypt(item.name.encode()),
        "content": self.fernet.encrypt(contents),
      }

  def decrypt(self, item):
    assert item.exists()
    assert item.suffix == ".encrypted"
    assert item.with_suffix(".filename").exists()

    with item.open("rb") as fh:
      contents = fh.read()
    with item.with_suffix(".filename").open("rb") as fh:
      filename = fh.read()
    try:
      return {
        "filename": self.fernet.decrypt(filename).decode(),
        "content": self.fernet.decrypt(contents),
      }
    except InvalidToken:
      print("Invalid password")

  def write_file(self, item, res):
    if self.is_encrypt:
      with (item.parent / res["uuid"]).with_suffix(".encrypted").open("wb") as fh:
        fh.write(res["content"])
      with (item.parent / res["uuid"]).with_suffix(".filename").open("wb") as fh:
        fh.write(res["filename"])
    else:
      with (item.parent / res["filename"]).open("wb") as fh:
        fh.write(res["content"])

  def get_files(self, directory):
    if self.is_encrypt:
      files = sorted(
        [f for f in directory.iterdir()],
        key=lambda x: [not x.is_file(), x.stat().st_size],
      )
    else:
      dirs = [f for f in directory.iterdir() if f.is_dir()]
      files = [
        f
        for f in directory.iterdir()
        if f.is_file() and f.suffix == ".encrypted"
      ]
      files = [f for f in files if f.with_suffix(".filename").exists()] + dirs
      files.sort(key=lambda x: [not x.is_file(), x.stat().st_size])
    return files

  def execute(self, item):
    print(f"{self.prompt} {item.name}")
    cmd = self.encrypt if self.is_encrypt else self.decrypt
    res = cmd(item)
    if res is None:
      return
    self.write_file(item, res)
    item.unlink()
    if not self.is_encrypt:
      item.with_suffix(".filename").unlink()

  def execute_dir(self, directory, depth=0, max_depth=100):
    print(f"scanning {directory}")
    cmd = self.encrypt if self.is_encrypt else self.decrypt
    files = self.get_files(directory)

    if len(files) > 0 and files[0].is_file():
      res = cmd(files[0])
      if res is None:
        return

    for item in files:
      if item.is_file():
        self.execute(item)
        continue
      if depth < max_depth:
        self.execute_dir(item, depth + 1, max_depth)

  @staticmethod
  def get_key(password, salt):
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("directory", nargs="*", type=str)
  parser.add_argument("-p", "--password", dest="password", type=str, required=True)
  parser.add_argument("-d", "--max-depth", dest="max_depth", type=int, default=100)
  parser.add_argument("-e", "--encrypt", action="store_true")
  return parser.parse_args()


def main(args):
  obscura = Obscura(args.password, args.encrypt)
  for d in args.directory:
    item = Path(d)
    if not item.exists():
      continue
    if item.is_file():
      obscura.execute(item)
    elif item.is_dir():
      obscura.execute_dir(item, 0, args.max_depth)


if __name__ == "__main__":
  args = parse_args()
  main(args)
