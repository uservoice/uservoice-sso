<?php
$account_key = "YOUR_ACCOUNT_KEY";
$api_key = "YOUR_API_KEY";

$salted = $api_key . $account_key;
$hash = hash('sha1',$salted,true);
$saltedHash = substr($hash,0,16);
$iv = "OpenSSL for -PHP";

$user_data = array(
  "guid"          => "example_user[:guid]",
  "display_name"  => "example_user[:display_name]",
  "email"         => "example_user[:email]",
  "url"           => "example_user[:url]",
  "avatar_url"    => "example_user[:avatar_url]",
  "expires"       => date("r", strtotime("+30 minutes"))
);

$data = json_encode($user_data);

// double XOR first block
for ($i = 0; $i < 16; $i++)
{
 $data[$i] = $data[$i] ^ $iv[$i];
}

$pad = 16 - (strlen($data) % 16);
$data = $data . str_repeat(chr($pad), $pad);

$encryptedData = openssl_encrypt(
	$data,
	'aes-128-cbc',
	$saltedHash,
	OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,
	$iv
);

$encryptedData = urlencode(base64_encode($encryptedData));
?>
