<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . "/../vendor/autoload.php";

use APConnectPhpClient\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://apconnect.dev',
                                'client_id',
                                'client_secret');

$oidc->addScope(array('profile', 'email'));
$oidc->setRedirectURL("http://127.0.0.1/client.php");
$oidc->setTokenLifetime(3600);

$oidc->authenticate();
$oidc->requestUserInfo();

$name = $oidc->getUserInfo('firstName');

?>

<html>
<head>
    <title>Apside Connect PHP Client example</title>
    <style>
        body {
            font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>

    <div>
        Hello <?php echo $name; ?>
    </div>

</body>
</html>

