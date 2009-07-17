from Crypto.Cipher import AES
import base64
import hashlib
import urllib
import operator
import array
import simplejson as json

message = {
  "guid" : "<%= example_user[:guid] %>"
  "expires" : "<%= example_user[:expires].to_s(:db) %>",
  "display_name" : "<%= example_user[:display_name] %>",
  "email" : "<%= example_user[:email] %>",
  "url" : "<%= example_user[:url] %>",
  "avatar_url" : "<%= example_user[:avatar_url] %>"
}
block_size = 16
mode = AES.MODE_CBC

api_key = "<%= api_key %>"
account_key = '<%= account_key %>'
iv = "OpenSSL for Ruby"

json = json.dumps(message, separators=(',',':'))

salted = api_key+account_key
saltedHash = hashlib.sha1(salted).digest()[:16]

json_bytes = array.array('b', json[0 : len(json)]) 
iv_bytes = array.array('b', iv[0 : len(iv)])

# # xor the iv into the first 16 bytes.
for i in range(0, 16):
	json_bytes[i] = operator.xor(json_bytes[i], iv_bytes[i])

pad = block_size - len(json_bytes.tostring()) % block_size
data = json_bytes.tostring() + pad * chr(pad)
aes = AES.new(saltedHash, mode, iv)
encrypted_bytes = aes.encrypt(data)

param_for_uservoice_sso = urllib.quote(base64.b64encode(encrypted_bytes))
