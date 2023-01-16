<?php

///-----------------------------------------------------

// Update your information for signautre
// Path to your private key.  Be very careful that this file is not accessible from the web!

$private_key_filename = '/home/ec2-user/yourprviatekey.pem';
$key_pair_id = 'ABCDEFGHABCDE';
$video_path = 'https://videocdn.yourdomain.com/video/content.mp4';
$expires = time() + 300; // 5 min from now

// For signed cookie, please set your domain.

$cookie_domain = 'yourdomain.com';

///-----------------------------------------------------

?>