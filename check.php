
<?php
$sites_list    = file_get_contents('sites.txt');
$rows        = explode("\r\n", $sites_list);

// clear the statuslist
unlink('statuslist.txt');
file_put_contents('statuslist.txt','');

$redirectList = []; // Site for redirects
$threatSites = []; // dangerous sites

// Check if the sites is in the statuslist.txt

foreach($rows as $data)
    {
        $url = $data;
        $original_parse = trim(parse_url($url, PHP_URL_HOST));
        // check the SSL certificate and domain
        checkSSL($original_parse, $url);
    }
    echo "The sites are checked and safe to redirect \n\r"; // info for command line and redirect.php
    return $redirectList[0];

function checkSSL($original_parse, $url) {
    global $redirectList;
    $checkGoogle = $url;
    $g = stream_context_create (array("ssl" => array("capture_peer_cert" => true)));

    $r = @stream_socket_client("ssl://www.".$original_parse.":443", $errno, $errstr, 30,
    STREAM_CLIENT_CONNECT, $g);
    if($r == NULL) {
        file_put_contents("statuslist.txt", $original_parse.":unclean\n", FILE_APPEND | LOCK_EX); // add to status list unclean status
    }
    else {
        $cont = stream_context_get_params($r);
        $go = safeBrowsingGoogle($checkGoogle);

        array_push($redirectList, $go);
    }
}

// Check if the site is malware free with google safe broswering
function safeBrowsingGoogle($url) {
    $enablesSites = []; // Google browser safer
    $params = file_get_contents("browser_params.json");
    $json_a = json_decode($params, true);
    $api_key = $json_a['client']['clientId'];
   
    array_push($enablesSites, ['url' => $url]);

    $json_a['threatInfo']['threatEntries'] = $enablesSites;
    $res = json_encode($json_a);

    $opts = array(
        'http' => array(
        'method'  => 'POST',
        'header' => "Content-type: application/json\r\n" .
                        "Accept: application/json\r\n" .
                        "Connection: close\r\n" .
                        "Content-length: " . strlen($res) . "\r\n",
        'protocol_version' => 1.1, 
        'content' => $res,
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
        )
    );
    $context  = stream_context_create($opts);
    $result = file_get_contents('https://safebrowsing.googleapis.com/v4/threatMatches:find?key='.$api_key, false, $context);

    $dang = file_get_contents("dangerous.json");
    $dang = json_decode($dang, true);

    $result = json_decode($result, true);
    
    if(empty($result)) { // change $result to $dang to test dangerous urls
        file_put_contents("statuslist.txt", trim(parse_url($url, PHP_URL_HOST)).":clean\n", FILE_APPEND | LOCK_EX);
        $return_url = $url; // add URL for redirect 
    }
    else {
        // check if the matches found
        foreach($dang['matches'] as $threat) {
            $threat_url = $threat['threat']['url'];
            $threat_url = trim(parse_url($threat_url, PHP_URL_HOST)); // parse the gotted url
            file_put_contents("statuslist.txt", $threat_url.":unclean\n", FILE_APPEND | LOCK_EX);
        }
        
        $return_url = 0; 
    }  

  return $return_url;
}

?>