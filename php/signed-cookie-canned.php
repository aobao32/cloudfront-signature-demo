<?php

include 'config.php';

// clear existing cookie 
foreach($_COOKIE as $key=>$value){
    setCookie($key,"",time()-60);
}

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

# For signed cookie
function get_signature_in_base64($video_path, $private_key_filename, $key_pair_id, $expires) {
    // this policy is well known by CloudFront, but you still need to sign it, since it contains your parameters
    $canned_policy = '{"Statement":[{"Resource":"' . $video_path . '","Condition":{"DateLessThan":{"AWS:EpochTime":'. $expires . '}}}]}';
    // the policy contains characters that cannot be part of a URL, so we base64 encode it
    $encoded_policy = url_safe_base64_encode($canned_policy);
    // sign the original policy, not the encoded version
    $signature = rsa_sha1_sign($canned_policy, $private_key_filename);
    // make the signature safe to be included in a URL
    $encoded_signature = url_safe_base64_encode($signature);

    // only reture signature in base64 code
    return $encoded_signature;
}

$signature_in_base64 = get_signature_in_base64($video_path, $private_key_filename, $key_pair_id, $expires);

// set cookie
setcookie("CloudFront-Policy", "", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Expires", "$expires", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Signature", "$signature_in_base64", 0, "/", "$cookie_domain", false, true);
setcookie("CloudFront-Key-Pair-Id", "$key_pair_id", 0, "/", "$cookie_domain", false, true);
?>

<html>
<head>
    <title>CloudFront Signed Cookie - Canned Policy</title>
</head>
<body>
    <h1>Amazon CloudFronti Signed Cookie - Canned Policy</h1>
    <h2>Canned Policy</h2>
    <h3>Cookie for the canned policy, expires at <?= gmdate('Y-m-d H:i:s T', $expires) ?> viewable by any IP</h3>
    <div id='canned'>setcookie("CloudFront-Expires", "<?= $expires ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <div id='canned'>setcookie("CloudFront-Signature", "<?= $signature_in_base64 ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <div id='canned'>setcookie("CloudFront-Key-Pair-Id", "<?= $key_pair_id ?>", 0, "/", "<?= $cookie_domain ?>", false, false);</div>
    <h3>Click here to access with cookie: </h3>
        <div id='canned'><a href='<?= $video_path ?>' target="blank"><?= $video_path ?></a></div>

</body>
</html>