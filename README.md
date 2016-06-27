PHP OpenID Connect Client
========================
A simple library that allows an application to authenticate a user through the basic OpenID Connect flow.

Adapted from [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP) created by Michael Jett.

# Requirements #
 1. PHP 5.2 or greater
 2. CURL extension
 3. JSON extension

## Install ##
 1. Install library using composer
```
composer require 'paquet-name'
```
 2. Include composer autoloader
```php
require '/vendor/autoload.php';
```

## Example 1 : Basic Client ##

```php
$oidc = new OpenIDConnectClient('https://id.provider.com/',
                                'ClientIDHere',
                                'ClientSecretHere');

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');

```

[See openid spec for available user attributes][1]

## Example 3 : Network and Security ##
```php
// Configure a proxy
$oidc->setHttpProxy("http://my.proxy.com:80/");

// Configure a cert
$oidc->setCertPath("/path/to/my.cert");
```
