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

function create_stream_name($stream, $policy, $signature, $key_pair_id, $expires) {
    $result = $stream;
    // if the stream already contains query parameters, attach the new query parameters to the end
    // otherwise, add the query parameters
    $separator = strpos($stream, '?') == FALSE ? '?' : '&';
    // the presence of an expires time means we're using a canned policy
    if($expires) {
        $result .= $path . $separator . "Expires=" . $expires . "&Signature=" . $signature . "&Key-Pair-Id=" . $key_pair_id;
    }
    // not using a canned policy, include the policy itself in the stream name
    else {
        $result .= $path . $separator . "Policy=" . $policy . "&Signature=" . $signature . "&Key-Pair-Id=" . $key_pair_id;
    }

    // new lines would break us, so remove them
    return str_replace('\n', '', $result);
}

function encode_query_params($stream_name) {
    // Adobe Flash Player has trouble with query parameters being passed into it,
    // so replace the bad characters with their URL-encoded forms
    return str_replace(
        array('?', '=', '&'),
        array('%3F', '%3D', '%26'),
        $stream_name);
}

// URL for signature with canned policy
function get_canned_policy_stream_name($video_path, $private_key_filename, $key_pair_id, $expires) {
    // this policy is well known by CloudFront, but you still need to sign it, since it contains your parameters
    $canned_policy = '{"Statement":[{"Resource":"' . $video_path . '","Condition":{"DateLessThan":{"AWS:EpochTime":'. $expires . '}}}]}';
    // the policy contains characters that cannot be part of a URL, so we base64 encode it
    $encoded_policy = url_safe_base64_encode($canned_policy);
    // sign the original policy, not the encoded version
    $signature = rsa_sha1_sign($canned_policy, $private_key_filename);
    // make the signature safe to be included in a URL
    $encoded_signature = url_safe_base64_encode($signature);

    // combine the above into a stream name
    $stream_name = create_stream_name($video_path, null, $encoded_signature, $key_pair_id, $expires);
    // URL-encode the query string characters to support Flash Player
    //return encode_query_params($stream_name);
    return $stream_name;
}

// URL for signature with custom policy
function get_custom_policy_stream_name($video_path, $private_key_filename, $key_pair_id, $policy) {
    // the policy contains characters that cannot be part of a URL, so we base64 encode it
    $encoded_policy = url_safe_base64_encode($policy);
    // sign the original policy, not the encoded version
    $signature = rsa_sha1_sign($policy, $private_key_filename);
    // make the signature safe to be included in a URL
    $encoded_signature = url_safe_base64_encode($signature);

    // combine the above into a stream name
    $stream_name = create_stream_name($video_path, $encoded_policy, $encoded_signature, $key_pair_id, null);
    // URL-encode the query string characters to support Flash Player
    //return encode_query_params($stream_name);
    return $stream_name;
}

$canned_policy_stream_name = get_canned_policy_stream_name($video_path, $private_key_filename, $key_pair_id, $expires);

# 
$client_ip = $_SERVER['REMOTE_ADDR'];

// Choose whether you need viewer's client IP address validation

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

$custom_policy_stream_name = get_custom_policy_stream_name($video_path, $private_key_filename, $key_pair_id, $policy);

?>

<html>
<head>
    <title>CloudFront Signed URL</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/video.js/7.6.6/video-js.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/video.js/7.6.6/video.min.js"></script>
    <script src="https://player.live-video.net/1.14.0/amazon-ivs-videojs-tech.min.js"></script>
    <script src="https://player.live-video.net/1.14.0/amazon-ivs-quality-plugin.min.js"></script>
    <style type="text/css">

body {
    margin: 0;
}

.src-container-direct {
    width: 1000px;
    margin-bottom: 15px;
    text-align: center;

    input {
        padding: 10px 5px;
        width: 500px;
    }

.customer-id-input {
        margin-right: 10px;
    }

.src-input {
        width: 800px;
    }
}

.src-submit {
    height: 37px;
    border-color: #ddd;
    margin: 1px 5px;
}

.video-container {
    width: 1024px;
    height: 600px;
    margin: 15px;
}

/* Align the quality menu to right side of video container */
.video-js .vjs-menu-button-popup .vjs-menu {
    left: auto;
    right: 0;
}

    </style>
    
</head>

<body>
    <h1>Amazon CloudFront Signed URL</h1>
    <h2>Canned Policy</h2>
    <h3>Expires at <?= gmdate('Y-m-d H:i:s T', $expires) ?> viewed by any IP</h3>
    <div id='canned'>The canned policy video will be here</div>
    <div id='canned'><?= $canned_policy_stream_name ?></div>

    <h2>Custom Policy</h2>
    <h3>Expires at <?= gmdate('Y-m-d H:i:s T', $expires) ?> only viewable by IP <?= $client_ip ?></h3>
    <div id='custom'>The custom policy video will be here</div>
    <div id='custom'><?= $custom_policy_stream_name ?></div>

    <h2>Copy URL to below player to test CloudFront signed URL</h2>
    <div class="video-container">
        <form class="src-container-direct">
            <input class="src-input" placeholder="Please input your URL to play" />
            <button class="src-submit" type="submit">Load</button>
        </form>
        <video id="amazon-ivs-videojs" class="video-js vjs-4-3 vjs-big-play-centered" controls autoplay playsinline>
        </video>
    </div>
    <script>
    
const DEFAULT_STREAM ="";

// Initialize player
(function () {
    // Set up IVS playback tech and quality plugin
    registerIVSTech(videojs);
    registerIVSQualityPlugin(videojs);

    // Initialize video.js player
    const videoJSPlayer = videojs("amazon-ivs-videojs", {
        techOrder: ["AmazonIVS"],
        controlBar: {
            playToggle: {
                replay: false
            }, // Hides the replay button for VOD
            pictureInPictureToggle: false // Hides the PiP button
        }
    });

    // Use the player API once the player instance's ready callback is fired
    const readyCallback = function () {
        // This executes after video.js is initialized and ready
        window.videoJSPlayer = videoJSPlayer;

        // Get reference to Amazon IVS player
        const ivsPlayer = videoJSPlayer.getIVSPlayer();

        // Show the "big play" button when the stream is paused
        const videoContainerEl = document.querySelector("#amazon-ivs-videojs");
        videoContainerEl.addEventListener("click", () => {
            if (videoJSPlayer.paused()) {
                videoContainerEl.classList.remove("vjs-has-started");
            } else {
                videoContainerEl.classList.add("vjs-has-started");
            }
        });

        // Logs low latency setting and latency value 5s after playback starts
        const PlayerState = videoJSPlayer.getIVSEvents().PlayerState;
        ivsPlayer.addEventListener(PlayerState.PLAYING, () => {
            console.log("Player State - PLAYING");
            setTimeout(() => {
                console.log(
                    `This stream is ${
                        ivsPlayer.isLiveLowLatency() ? "" : "not "
                    }playing in ultra low latency mode`
                );
                console.log(`Stream Latency: ${ivsPlayer.getLiveLatency()}s`);
            }, 5000);
        });

        // Log errors
        const PlayerEventType = videoJSPlayer.getIVSEvents().PlayerEventType;
        ivsPlayer.addEventListener(PlayerEventType.ERROR, (type, source) => {
            console.warn("Player Event - ERROR: ", type, source);
        });

        // Log and display timed metadata
        ivsPlayer.addEventListener(PlayerEventType.TEXT_METADATA_CUE, (cue) => {
            const metadataText = cue.text;
            const position = ivsPlayer.getPosition().toFixed(2);
            console.log(
                `Player Event - TEXT_METADATA_CUE: "${metadataText}". Observed ${position}s after playback started.`
            );
        });

        // Enables manual quality selection plugin
        videoJSPlayer.enableIVSQualityPlugin();

        // Set volume and play default stream
        videoJSPlayer.volume(0.5);
        videoJSPlayer.src(DEFAULT_STREAM);
    };

    // Register ready callback
    videoJSPlayer.ready(readyCallback);
})();

// Sets up input box for Amazon IVS manifest
(function () {
    const containerEl = document.querySelector(".video-container");
    const directSrcFormEl = containerEl.querySelector(".src-container-direct");
    const directSrcInputEl = containerEl.querySelector(".src-input");
    directSrcFormEl.addEventListener("submit", (e) => {
        e.preventDefault();
        videoJSPlayer.src(directSrcInputEl.value);
    });
})();
     
    </script>
</body>

</html>
