<?php

namespace openidPhpClient;

/**
 * OpenID Connect Client for PHP5
 *
 * Created by Michael Jett <mjett@mitre.org>
 *
 * Adapted by Sebastien Laporte <seb_laporte_33@yahoo.com>
 *
 */

/**
 * Use session to manage a nonce
 */
if (!isset($_SESSION)) {
    session_start();
}

/**
 * A wrapper around base64_decode which decodes Base64URL-encoded data,
 * which is not the same alphabet as base64.
 */
function base64url_decode($base64url) {
    return base64_decode(b64url2b64($base64url));
}

/**
 * Per RFC4648, "base64 encoding with URL-safe and filename-safe
 * alphabet".  This just replaces characters 62 and 63.  None of the
 * reference implementations seem to restore the padding if necessary,
 * but we'll do it anyway.
 *
 */
function b64url2b64($base64url) {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
	$base64url .= str_repeat("=", 4 - $padding);
    }
    return strtr($base64url, '-_', '+/');
}

/**
 * Require the CURL and JSON PHP extentions to be installed
 */
if (!function_exists('curl_init')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the JSON PHP extension.');
}

/**
 *
 * Please note this class stores nonces in $_SESSION['openid_connect_nonce']
 *
 */
class OpenIDConnectClient
{

    /**
     * @var string arbitrary id value
     */
    private $clientID;

    /*
     * @var string arbitrary name value
     */
    private $clientName;

    /**
     * @var string arbitrary secret value
     */
    private $clientSecret;

    /**
     * @var array holds the provider configuration
     */
    private $providerConfig = array();

    /**
     * @var string http proxy if necessary
     */
    private $httpProxy;

    /**
     * @var string full system path to the SSL certificate
     */
    private $certPath;

    /**
     * @var string if we aquire an access token it will be stored here
     */
    private $accessToken;

    /**
     * @var array holds scopes
     */
    private $scopes = array();

    /**
     * @var array holds a cache of info returned from the user info endpoint
     */
    private $userInfo = array();

    /**
     * @var array holds authentication parameters
     */
    private $authParams = array();

    /**
     * @param $provider_url string optional
     *
     * @param $client_id string optional
     * @param $client_secret string optional
     *
     */
    public function __construct($provider_url = null, $client_id = null, $client_secret = null) {
        $this->setProviderURL($provider_url);
        $this->clientID = $client_id;
        $this->clientSecret = $client_secret;
    }

    /**
     * @param $provider_url
     */
    public function setProviderURL($provider_url) {
        $this->providerConfig['issuer'] = $provider_url;
    }

    /**
     * @return bool
     * @throws OpenIDConnectClientException
     */
    public function authenticate() {

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($_REQUEST['error'])) {
            throw new OpenIDConnectClientException("Error: " . $_REQUEST['error'] . " Description: " . $_REQUEST['error_description']);
        }

        if (isset($_COOKIE['id-token'])) {

            // Return true if JWT signature is ok
            return $this->verifyJWTsignature($_COOKIE['id-token']);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($_REQUEST["code"])) {

            $code = $_REQUEST["code"];
            $token_json = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($token_json->error)) {
                throw new OpenIDConnectClientException($token_json->error_description);
            }

            // Do an OpenID Connect session check
            if ($_REQUEST['state'] != $_SESSION['openid_connect_state']) {
                throw new OpenIDConnectClientException("Unable to determine state");
            }

            if (!property_exists($token_json, 'id_token')) {
                throw new OpenIDConnectClientException("User did not authorize openid scope.");
            }

            $claims = $this->decodeJWT($token_json->id_token, 1);

            // Verify the signature
            if (!$this->verifyJWTsignature($token_json->id_token)) {
                throw new OpenIDConnectClientException ("Unable to verify signature");
            }

            // Verify claims
            if (!$this->verifyJWTclaims($claims)) {
               throw new OpenIDConnectClientException ("Unable to verify JWT claims");
            }

            // Clean up the session
            unset($_SESSION['openid_connect_nonce']);

            // Save the access token
            $this->setAccessToken($token_json->access_token);

            // Set id-token in Cookie
            if ($this->getTokenLifetime() > 0) {
                $cookie_id_token = new Cookie();
                $cookie_id_token->setName('id-token');
                $cookie_id_token->setValue($token_json->id_token);
                $cookie_id_token->setTime($this->getTokenLifetime());
                $cookie_id_token->setPath("/");
                $cookie_id_token->create();
            }
            else {
                throw new OpenIDConnectClientException ("Token lifetime has not been set or need to be greater than 0");
            }

            return true;

        } else {

            $this->requestAuthorization();
            return false;
        }

    }

    /**
     * @param $scope - example: openid, given_name, etc...
     */
    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param $param
     * @throws OpenIDConnectClientException
     * @return string
     *
     */
    private function getProviderConfigValue($param) {

        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!isset($this->providerConfig[$param])) {
            $well_known_config_url = rtrim($this->getProviderURL(),"/") . "/openid-configuration";
            $value = json_decode($this->fetchURL($well_known_config_url))->{$param};

            if ($value) {
                $this->providerConfig[$param] = $value;
            } else {
                throw new OpenIDConnectClientException("The provider {$param} has not been set. Make sure your provider has a well known configuration available.");
            }

        }

        return $this->providerConfig[$param];
    }


    /**
     * @param $url Sets redirect URL for auth flow
     */
    public function setRedirectURL ($url) {
        if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
            $this->redirectURL = $url;
        }
    }

    /**
     * Gets the redirect URL
     *
     * @return string
     */
    public function getRedirectURL() {

        // If the redirect URL has been set then return it.
        if (property_exists($this, 'redirectURL') && $this->redirectURL) {

            return $this->redirectURL;
        }
        else {
            throw new OpenIDConnectClientException("The redirect URL has not been set.");
        }
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @return string
     */
    protected function generateRandString() {
        return md5(uniqid(rand(), TRUE));
    }

    /**
     * Start Here
     * @return void
     */
    private function requestAuthorization() {

        $auth_endpoint = $this->getProviderConfigValue("authorization_endpoint");
        $response_type = "code";
        
        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->generateRandString();
        $_SESSION['openid_connect_nonce'] = $nonce;

        // State essentially acts as a session key for OIDC
        $state = $this->generateRandString();
        $_SESSION['openid_connect_state'] = $state;

        $auth_params = array_merge($this->authParams, array(
            'response_type' => $response_type,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'nonce' => $nonce,
            'state' => $state,
            'scope' => 'openid'
        ));

        // If the client has been registered with additional scopes
        if (sizeof($this->scopes) > 0) {
            $auth_params = array_merge($auth_params,
                array('scope' => $auth_params['scope'] . ' ' . implode(' ', $this->scopes)));
        }
        
        $auth_endpoint .= '?' . http_build_query($auth_params, null, '&');

        session_commit();
        $this->redirect($auth_endpoint);
    }


    /**
     * Requests ID and Access tokens
     *
     * @param $code
     * @return mixed
     */
    private function requestTokens($code) {


        $token_endpoint = $this->getProviderConfigValue("token_endpoint");

        $grant_type = "authorization_code";

        $token_params = array(
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret
        );

        // Convert token params to string format
        $token_params = http_build_query($token_params, null, '&');

        return json_decode($this->fetchURL($token_endpoint, $token_params));
    }

    /**
     * @param $jwt string encoded JWT
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyJWTsignature($jwt) {

        $key = $this->getKey();

        if ($key === NULL) {
            throw new OpenIDConnectClientException('Error : key unreadable');
        }

        $jwtSigner = new \Lcobucci\JWT\Signer\Rsa\Sha256();

        try {
            $parsedJwt = (new \Lcobucci\JWT\Parser())->parse((string) $jwt);
        } catch (\RuntimeException $e) {
            return false;
        }
        
        return $parsedJwt->verify($jwtSigner, $key);
    }

    /**
     * @param $claims
     * @return bool
     */
    private function verifyJWTclaims($claims) {

        return (($claims->iss == $this->getProviderURL())
            && ($claims->aud == $this->clientID)
            && ($claims->nonce == $_SESSION['openid_connect_nonce']));
    }

    /**
     * @return string
     */
    public function getKey() {

        $params = '?client_id=' . $this->getClientID() . '&client_secret=' . $this->getClientSecret();
        return $this->fetchURL($this->getProviderConfigValue('key_endpoint') . $params);
    }

    /**
     * @param $jwt string encoded JWT
     * @param int $section the section we would like to decode
     * @return object
     */
    private function decodeJWT($jwt, $section = 0) {

        $parts = explode(".", $jwt);
        return json_decode(base64url_decode($parts[$section]));
    }

    /**
     * @param $attribute
     * @return mixed
     */
    public function getUserInfo($attribute) {

        if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo->$attribute;
        }

        return null;
    }

    /**
     * @param $attribute
     * @return mixed
     */
    public function requestUserInfo() {

        if ($this->getAccessToken()) {

            $user_info_endpoint = $this->getProviderConfigValue("userinfo_endpoint");

            //The accessToken has to be send in the Authorization header, so we create a new array with only this header.
            $headers = array("Authorization: Bearer {$this->getAccessToken()}");

            $user_json = json_decode($this->fetchURL($user_info_endpoint,null,$headers));

            $this->userInfo = $user_json;

            return $this->userInfo;
        }
        
        return false;
    }

    /**
     * @param $url
     * @param null $post_body string If this is set the post type will be POST
     * @param array() $headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @throws OpenIDConnectClientException
     * @return mixed
     */
    protected function fetchURL($url, $post_body = null,$headers = array()) {

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        // Determine whether this is a GET or POST
        if ($post_body != null) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);

            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_object(json_decode($post_body))) {
                $content_type = 'application/json';
            }

            // Add POST-specific headers
            $headers[] = "Content-Type: {$content_type}";
            $headers[] = 'Content-Length: ' . strlen($post_body);

        }

        // If we set some heaers include them
        if(count($headers) > 0) {
          curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        // Set URL to download
        curl_setopt($ch, CURLOPT_URL, $url);

        if (isset($this->httpProxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        // Include header in result? (0 = yes, 1 = no)
        curl_setopt($ch, CURLOPT_HEADER, 0);

        /**
         * Set cert
         * Otherwise ignore SSL peer verification
         */
        if (isset($this->certPath)) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        }

        // Should cURL return or print out the data? (true = return, false = print)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Timeout in seconds
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);

        // Download the given URL, and return output
        $output = curl_exec($ch);

        if ($output === false) {
            throw new OpenIDConnectClientException('Curl error: ' . curl_error($ch));
        }

        // Close the cURL resource, and free system resources
        curl_close($ch);

        return $output;
    }

    /**
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getProviderURL() {

        if (!isset($this->providerConfig['issuer'])) {
            throw new OpenIDConnectClientException("The provider URL has not been set");
        } else {
            return $this->providerConfig['issuer'];
        }
    }

    /**
     * @param $url
     */
    public function redirect($url) {
        header('Location: ' . $url);
        exit;
    }

    /**
     * @param $httpProxy
     */
    public function setHttpProxy($httpProxy) {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param $certPath
     */
    public function setCertPath($certPath) {
        $this->certPath = $certPath;
    }

    /**
     *
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param $array
     *        simple key => value
     */
    public function providerConfigParam($array) {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * @param $clientSecret
     */
    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param $clientID
     */
    public function setClientID($clientID) {
        $this->clientID = $clientID;
    }

    /**
     * @param int
     */
    public function setTokenLifetime($lifetime) {
        $this->tokenLifetime = $lifetime;
    }

    /**
     * @return int
     */
    private function getTokenLifetime() {
        return $this->tokenLifetime;
    }

    /**
     * @return mixed
     */
    public function getClientName() {
        return $this->clientName;
    }

    /**
     * @param $clientName
     */
    public function setClientName($clientName) {
        $this->clientName = $clientName;
    }

    /**
     * @return string
     */
    public function getClientID() {
        return $this->clientID;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    private function getAccessToken() {
        return $this->accessToken;
    }

    /**
     * @param string
     */
    private function setAccessToken($access_token) {
        $this->accessToken = $access_token;
    }

}
