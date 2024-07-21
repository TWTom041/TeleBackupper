"""
Upload given path to telegram.
TODO:
Implement an FS
"""
import subprocess
import hashlib
import json
import os
import glob
import asyncio
import io
import pickle

from Crypto import Random  # pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from morefs.dict import DictFS
from telethon import TelegramClient

CONFIG_PATH = "config.json"


def sha256_file(path):
    _bufsize = 1048576
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(_bufsize)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = pad(raw, self.bs)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), self.bs)


class TelegramBackupper:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self.config = json.load(f)
        self.client = TelegramClient(self.config["session_name"], self.config["api_id"], self.config["api_hash"])
        self.client.start(bot_token=self.config["bot_token"])
        self.cipher = AESCipher(self.config["file_encryption_key"])
        self.fs = DictFS()
        self.max_file_size = int(self.config["file_chunk_size"])  # 1GB

    def upload_to_telegram(self, data: bytes, name: str):
        loop = asyncio.get_event_loop()
        data = io.BytesIO(data)
        data.name = name
        print(data.name)
        msg = loop.run_until_complete(self.client.send_file(self.config["send_to_entity_id"], data))
        return msg.id
    
    def download_from_telegram(self, ids: tuple[int, list[int]]):
        loop = asyncio.get_event_loop()
        msg = loop.run_until_complete(self.client.get_messages(self.config["send_to_entity_id"], ids=ids))
        return loop.run_until_complete(msg.download_media(bytes))

    def backup(self):
        for path in glob.iglob(os.path.join(self.config["backup_path"], "**"), recursive=True):
            print("Processing", path)
            if os.path.isfile(path):
                file_hash = sha256_file(path)
                message_ids = []
                with open(path, "rb") as f:
                    _i = 1
                    while True:
                        data = f.read(self.max_file_size)
                        if not data:
                            break
                        message_id = self.upload_to_telegram(data, f"{file_hash}.{_i}")
                        message_ids.append(str(message_id))
                        _i += 1
                with self.fs.open(path, "w") as f:
                    f.write(f"{file_hash}\t{' '.join(message_ids)}")
            elif os.path.isdir(path):
                self.fs.makedirs(path, exist_ok=True)
        os.makedirs(self.config["save_folder"], exist_ok=True)
        with open(os.path.join(self.config["save_folder"], "fs"), "wb") as f:
            print(self.fs.ls("/"))
            pickle.dump(self.fs.store, f)  # TODO: fix this
        with open(os.path.join(self.config["save_folder"], "config.json"), "w") as f:
            json.dump(self.config, f)
    
    def restore(self):
        fs = DictFS()     
        with open("save/fs", "rb") as f:
            fs.store = pickle.load(f)



if __name__ == "__main__":
    backupper = TelegramBackupper(CONFIG_PATH)
    backupper.backup()
