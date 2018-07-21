<head>
<?php

function redirect($url) { ?>
    <script>
        setTimeout(function() {
        var win = window.open('<?php echo $url ?>', '_blank');
            win.focus();
        }, 1000);
    </script>
<?php }

$check_status = [];
$statuslist = file_get_contents('statuslist.txt');

if(empty($statuslist)) {
    $url = include_once('check.php');
    echo 'First clean to redirect is '.$url;
    redirect($url);
}
else {
    $s_rows = explode("\n", $statuslist);
    array_pop($s_rows);

    // Parse statuses array
    foreach($s_rows as $status_row) {
        $temp = explode(':', $status_row);
        $check_status[$temp[0]] = $temp[1];
    }

    // Get the first clean URL
    foreach($check_status as $key => $value) {
        if($value == "clean") {
            $url = "http://".$key;
            break;
        }
    }
    echo "Status List is not empty. The first clean site is ".$url;
    redirect($url);
} ?>

</head>