
<?php
$sites_list    = file_get_contents('sites.txt');
$rows        = explode("\r\n", $sites_list);

$check_status = [];
$statuslist = file_get_contents('statuslist.txt');
$s_rows        = explode("\n", $statuslist);
array_pop($s_rows);

foreach($s_rows as $status_row) {
    // echo $status_row.' ';
    $temp = explode(':', $status_row);
    // var_dump($temp);
    $check_status[$temp[0]] = $temp[1];
    
}

foreach($check_status as $key => $value) {
    if($value == "clean") {
        $whitelist[] = $key;
    }
    else {
        $blacklist[] = $key;
    }
}
// var_dump($whitelist);
// var_dump($blacklist);
// exit();

// var_dump($s_rows);
// exit();
$verifiedSites = []; // SSL check
$redirectList = []; // Site for redirects
$threatSites = []; // dangerous sites

// First - check if ssl certificate is enabled remotely

foreach($rows as $data)
{
    $url = $data;
    $original_parse = trim(parse_url($url, PHP_URL_HOST));
        // echo 'start = '.$original_parse;
            // var_dump('check', $check_status);
            if(!empty($blacklist)) {
                $status = array_search($original_parse, $blacklist);
            }
            else { $status = false; }
            
            if($status !== false) { // if the url in blacklist
                // echo 'blacklist - '.$original_parse;
                continue; // stop the process
            }
            else {
                // echo 'YANDEXU + '.$original_parse;
                if(!empty($whitelist)) {
                    $status = array_search($original_parse, $whitelist);
                }
                else { $status = false; }
                if($status !== false ) { // if the url in whitelist
                    // echo 'whitelist - '.$original_parse;
                    array_push($redirectList, $url); // just add URL for redirect
                }
                else {
                    // echo ' here ';
                    checkSSL($original_parse);
                }
            }
}
echo "The sites are checked and safe to redirect \n\r";
return $redirectList;
// var_dump($redirectList);

// var_dump($verifiedSites);
function checkSSL($original_parse) {
    $g = stream_context_create (array("ssl" => array("capture_peer_cert" => true)));

    $r = @stream_socket_client("ssl://www.".$original_parse.":443", $errno, $errstr, 30,
    STREAM_CLIENT_CONNECT, $g);
    if($r == NULL) {
        file_put_contents("statuslist.txt", $original_parse.":unclean\n", FILE_APPEND | LOCK_EX); // add to status list unclean status
    }
    else {
        $cont = stream_context_get_params($r);
        // array_push($verifiedSites, $url); // add URL for redirect 
        // var_dump($redirectList);
        // exit();
        // array_push($redirectList, $original_parse); 
        array_push($redirectList, safeBrowsingGoogle($url));

    }
}
// Second - check if the site is malware free with google safe broswering
function safeBrowsingGoogle($url) {
    $enablesSites = []; // Google browser safer
    // echo ' LLOK '.$url;
    // exit();
    $params = file_get_contents("browser_params.json");
    $json_a = json_decode($params, true);
    $api_key = $json_a['client']['clientId'];
   
    array_push($enablesSites, ['url' => $url]);

    $json_a['threatInfo']['threatEntries'] = $enablesSites;
    $res = json_encode($json_a);
// var_dump($json_a['client']['clientId']);
  
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
    //   echo 'empty';
    //$verified = file_get_contents("whitelist.txt");
    // Add clean sites to the whitelist
        // var_dump($add);
        file_put_contents("statuslist.txt", trim(parse_url($url, PHP_URL_HOST)).":clean\n", FILE_APPEND | LOCK_EX);
        $return_url = $url; // add URL for redirect 
      

  }
  else {
    //   echo 'DANGEROUS!';
      // check if the matches found
      foreach($dang['matches'] as $threat) {
        $threat_url = $threat['threat']['url'];
        $threat_url = trim(parse_url($threat_url, PHP_URL_HOST)); // parse the gotted url
        file_put_contents("statuslist.txt", $threat_url.":unclean\n", FILE_APPEND | LOCK_EX);
        
        // check if the url begins with www
        // if(substr( $threat_url, 0, 4 ) == "www.") {
        //     $threat_url = substr($threat_url, 4);
        // }
        // array_push($threatSites, $threat_url);
      }
    $return_url = 0;
    //   var_dump($threatSites, '1');
    //   var_dump($redirectList, '2');
    //   $clean = array_diff($redirectList, $threatSites); // remove all of dangerous sites from redirect list
    //   var_dump($redirectList);
    // Add the unclean sites to the blacklist
    //   foreach($clean as $add) {
    //     file_put_contents("statuslist.txt", $add.":clean\n", FILE_APPEND | LOCK_EX);
    //   }
 
        

  }  
    // var_dump($redirectList);
  return $return_url;
}


?>