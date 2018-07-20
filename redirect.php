<head>
<?php
$result = include_once('check.php');
echo '<br />';
foreach($result as $url) {
    echo $url."<br />";
}
foreach($result as $url) {
?>
<script>
setTimeout(function() {
    var win = window.open('<?php echo $url ?>', '_blank');
    win.focus();
}, 1000);
</script>
<?php } ?>

</head>