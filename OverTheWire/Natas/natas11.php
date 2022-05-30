<?php
$cookie = base64_decode(urldecode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D")); 
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in, $key) {
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

// Plaintext ^ Key = Ciphertext
// Plaintext ^ Ciphertext = Key
$plaintext = json_encode($defaultdata);
$ciphertext = $cookie;
echo(xor_encrypt($plaintext, $ciphertext));
echo(" ");
$key = "qw8J";
$actualdata = json_encode(array( "showpassword"=>"yes", "bgcolor"=>"#ffffff"));
$actualcookie = base64_encode(xor_encrypt($actualdata, $key));
echo($actualcookie);
?>