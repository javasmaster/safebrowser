
<?php
$txt_file    = file_get_contents('sites.txt');
$rows        = explode("\r\n", $txt_file);
$verifiedSites = []; // SSL check
$enablesSites = []; // Google browser safer
$redirectList = []; // Site for redirects
$threatSites = []; // dangerous sites

var_dump($rows);

// First - check if ssl certificate is enabled remotely
foreach($rows as $data)
{
    $url = $data;
    $original_parse = trim(parse_url($url, PHP_URL_HOST));
    $g = stream_context_create (array("ssl" => array("capture_peer_cert" => true)));

    $r = @stream_socket_client("ssl://www.".$original_parse.":443", $errno, $errstr, 30,
    STREAM_CLIENT_CONNECT, $g);
    // echo "HEEEEERE ".$r;
    if($r == NULL) {
        break;
    }
    else {
        $cont = stream_context_get_params($r);
        array_push($verifiedSites, $data);
        array_push($redirectList, $original_parse);
        // var_dump($cont["options"]["ssl"]["peer_certificate"]);
    }
}
// var_dump($verifiedSites, ['VERIFIED']);


// Second - check if the site is malware free with google safe broswering

$params = file_get_contents("browser_params.json");
$json_a = json_decode($params, true);
$api_key = $json_a['client']['clientId'];
foreach ($verifiedSites as $vSite) {
    array_push($enablesSites, ['url' => $vSite]);
}
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
      echo 'empty';
      $verified = file_get_contents("verified.json");
      $verified = json_decode($params, true);
      array_push();

  }
  else {
      echo 'DANGEROUS!';
      // check if the matches found
      foreach($dang['matches'] as $threat) {
        $threat_url = $threat['threat']['url'];
        $threat_url = trim(parse_url($threat_url, PHP_URL_HOST)); // parse the gotted url
        // check if the url begins with www
        if(substr( $threat_url, 0, 4 ) == "www.") {
            $threat_url = substr($threat_url, 4);
        }
        array_push($threatSites, $threat_url);
      }
      var_dump($threatSites, '1');
      var_dump($redirectList, '2');
      $sum = array_diff($redirectList, $threatSites); // remove all of dangerous sites from redirect list
      var_dump($sum);
  }
?>