<?php

return [
    'bypass' => true, 
    'proxies' => env('IP_PROXIES'),
    'whitelist' => env('IP_WHITELIST'), // exp. 192.168.1.1,192.78.183.1,10.0.0.1
    'blacklist' => env('IP_BLACKLIST') // exp. 192.168.1.1,192.78.183.1,10.0.0.1
];