from nacl import secret
from nacl import utils
from base64 import b64encode, b64decode
from nacl.public import PrivateKey as NACLPrivateKey, PublicKey as NACLPublicKey, SealedBox

import json
from rest_framework import serializers
from django.contrib.postgres.fields import JSONField

# helpers
def _encrypt(message, encryptor):
  msg_bytes = str.encode(message)
  encrypted_bytes = encryptor(msg_bytes)
  encrypted_string = b64encode(encrypted_bytes).decode('utf-8')
  return encrypted_string

def _to_string(key):
  return b64encode(key).decode('utf-8')

def _decrypt(encrypted, decryptor):
  encrypted_bytes = b64decode(encrypted.encode())
  msg_bytes = decryptor(encrypted_bytes)
  message = msg_bytes.decode('utf-8')
  return message

def _save(key, fname):
  if not fname.endswith(".pem"):
    raise CryptoException("Not a valid key location.")
  str_text = _to_string(key)
  with open(fname, 'w') as f:
    f.write(str_text)

def _load(fname):
  if not fname.endswith(".pem"):
    raise CryptoException("Not a valid key location.")
  with open(fname, 'r') as f:
    str_text = f.read()
  key = b64decode(str_text.encode())
  return key

def _init(key_text, default):
  if key_text == None:
    return default
  elif key_text.endswith(".pem"):
    return _load(key_text)
  else:
    return b64decode(key_text.encode())

# library
class CryptoException(Exception):
  pass

# symmetric
class SecretKey(object):
  def __init__(self, key_text=None):
    # from scratch
    self.key = _init(key_text, default=utils.random(secret.SecretBox.KEY_SIZE))
  def __str__(self):
    return _to_string(self.key)
  def save(self, fname):
    _save(self.key, fname)
  def encrypt(self, message):
    return _encrypt(message, secret.SecretBox(self.key).encrypt)
  def decrypt(self, encrypted):
    return _decrypt(encrypted, secret.SecretBox(self.key).decrypt)

# public
class PublicKey(object):
  def __init__(self, key_text=None):
    if key_text == None:
      raise CryptoException("Public Key cannot be initialized from scratch.")
    self.key = _init(key_text, default=None)
  def save(self, fname):
    _save(self.key, fname)
  def encrypt(self, message):
    return _encrypt(message, SealedBox(NACLPublicKey(self.key)).encrypt)

class PrivateKey(object):
  def __init__(self, key_text=None):
    self.key =  _init(key_text, default=NACLPrivateKey.generate()._private_key)
  def __str__(self):
    return _to_string(self.key)
  def save(self, fname):
    _save(self.key, fname)
  def encrypt(self, message):
    return _encrypt(message, SealedBox(NACLPrivateKey(self.key).public_key).encrypt)
  def decrypt(self, encrypted):
    return _decrypt(encrypted, SealedBox(NACLPrivateKey(self.key)).decrypt)
  def get_public_key(self):
    return PublicKey(_to_string(NACLPrivateKey(self.key).public_key._public_key))

class EncryptedJSONException(Exception):
  pass

class EncryptedJSON(dict):
  def __init__(self, *args, **kwargs):
    self.update(*args, **kwargs)
    if set(self.keys()) == set(["payload", "secret"]):
      self.locked = True
    else:
      self.locked = False
  def __str__(self):
    if not self.locked:
      return "Unlocked EncryptedDict: {}".format(super().__str__())
    else:
      return "Locked EncryptedDict: {}".format(super().__str__())
  def encrypt(self, public_key):
    if self.locked == True:
      raise EncryptedJSON("Already locked.")
    secret_key = SecretKey()
    payload = dict(self)
    self.clear()
    self.update({
      "payload": secret_key.encrypt(json.dumps(payload)),
      "secret": public_key.encrypt(str(secret_key)),
    })
    self.locked = True
  def decrypt_secret(self, private_key):
    if self.locked == False:
      raise EncryptedJSON("Payload has note been encrypted.")
    return SecretKey(private_key.decrypt(self["secret"]))
  def decrypt_payload(self, secret_key):
    if self.locked == False:
      raise EncryptedJSON("Payload has note been encrypted.")
    return json.loads(secret_key.decrypt(self["payload"]))
  
class EncryptedJSONField(JSONField):
  def to_python(self, value):
    if type(value) == EncryptedJSON:
      return value
    elif type(value) == str:
      return EncryptedJSON(json.loads(value))
    else: 
      return None
  def from_db_value(self, value, expression, connection):
    if value is None:
      return value
    return EncryptedJSON(value)
