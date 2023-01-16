<?php

include 'config.php';

// clear existing cookie 
foreach($_COOKIE as $key=>$value){
    setCookie($key,"",time()-60);
}

$client_ip = $_SERVER['REMOTE_ADDR'];

// Custom policy with IP condition for signed-url
$policy =
'{'.
    '"Statement":['.
        '{'.
            '"Resource":"'. $video_path . '",'.
            '"Condition":{'.
                '"IpAddress":{"AWS:SourceIp":"' . $client_ip . '/32"},'.
                '"DateLessThan":{"AWS:EpochTime":' . $expires . '}'.
            '}'.
        '}'.
    ']' .
'}';

// Custom policy without IP condition for signed-url
/*
$policy =
'{'.
    '"Statement":['.
        '{'.
            '"Resource":"'. $video_path . '",'.
            '"Condition":{'.
                '"DateLessThan":{"AWS:EpochTime":' . $expires . '}'.
            '}'.
        '}'.
    ']' .
    '}';
*/

function rsa_sha1_sign($policy, $private_key_filename) {
    $signature = "";

    // load the private key
    $fp = fopen($private_key_filename, "r");
    $priv_key = fread($fp, 8192);
    fclose($fp);
    $pkeyid = openssl_get_privatekey($priv_key);

    // compute signature
    openssl_sign($policy, $signature, $pkeyid);

    // free the key from memory
    openssl_free_key($pkeyid);

    return $signature;
}

function url_safe_base64_encode($value) {
    $encoded = base64_encode($value);
    // replace unsafe characters +, = and / with the safe characters -, _ and ~
    return str_replace(
        array('+', '=', '/'),
        array('-', '_', '~'),
        $encoded);
}

function encode_query_params($stream_name) {
    // Adobe Flash Player has trouble with query parameters being passed into it,
    // so replace the bad characters with their URL-encoded forms
    return str_replace(
        array('?', '=', '&'),
        array('%3F', '%3D', '%26'),
        $stream_name);
}

# For signed cookie
function get_signature_in_base64($video_path, $private_key_filename, $key_pair_id, $policy) {
    // the policy contains characters that cannot be part of a URL, so we base64 encode it
    $encoded_policy = url_safe_base64_encode($policy);
    // sign the original policy, not the encoded version
    $signature = rsa_sha1_sign($policy, $private_key_filename);
    // make the signature safe to be included in a URL
    $encoded_signature = url_safe_base64_encode($signature);
    
    // For signed cookie with custom policy, return $encoded_signature
    return $encoded_signature;
}

$policy_in_base64 = url_safe_base64_encode($policy);
$signature_in_base64 = get_signature_in_base64($video_path, $private_key_filename, $key_pair_id, $policy);

// set cookie
setcookie("CloudFront-Expires", "", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Policy", "$policy_in_base64", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Signature", "$signature_in_base64", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Key-Pair-Id", "$key_pair_id", 0, "/", "$cookie_domain", false, true);
?>

<html>
<head>
    <title>CloudFront Signed Cookie - Custom Policy</title>
</head>
<body>
    <h1>Amazon CloudFronti Signed Cookie - Custom Policy</h1>
    <h2>Custom Policy</h2>
    <h3>Cookie for the custom policy, Expires at <?= gmdate('Y-m-d H:i:s T', $expires) ?> only viewable by IP <?= $client_ip ?></h3>
    <div id='custom'>setcookie("CloudFront-Policy", "<?= $policy_in_base64 ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <div id='custom'>setcookie("CloudFront-Signature", "<?= $signature_in_base64 ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <div id='custom'>setcookie("CloudFront-Key-Pair-Id", "<?= $key_pair_id ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <h3>Click here to access with cookie: </h3>
        <div id='custom'><a href='<?= $video_path ?>' target="blank"><?= $video_path ?></a></div>
    
</body>
</html>