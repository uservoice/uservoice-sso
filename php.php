&lt;?php
$account_key = "<%= account_key %>";
$api_key = "<%= api_key %>";

$salted = $api_key . $account_key;
$hash = hash('sha1',$salted,true);
$saltedHash = substr($hash,0,16);
$iv = "OpenSSL for Ruby";

$user_data = array(
  "guid" => "<%= example_user[:guid] %>",
  "expires" => "<%= example_user[:expires].to_s(:db) %>",
  "display_name" => "<%= example_user[:display_name] %>",
  "email" => "<%= example_user[:email] %>",
  "url" => "<%= example_user[:url] %>",
  "avatar_url" => "<%= example_user[:avatar_url] %>"
);

$data = json_encode($user_data);

// double XOR first block
for ($i = 0; $i < 16; $i++)
{
 $data[$i] = $data[$i] ^ $iv[$i];
}

$pad = 16 - (strlen($data) % 16);
$data = $data . str_repeat(chr($pad), $pad);
	
$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'','cbc','');
mcrypt_generic_init($cipher, $saltedHash, $iv);
$encryptedData = mcrypt_generic($cipher,$data);
mcrypt_generic_deinit($cipher);

$encryptedData = urlencode(base64_encode($encryptedData));
?&gt;