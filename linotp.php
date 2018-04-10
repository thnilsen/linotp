<?php
class linotp extends rcube_plugin
{
  // registered tasks for this plugin.
  public $task = 'login|logout';

  // Dynalogin server and port
  private $linotp_server; 
  private $linotp_port;
  private $linotp_emergencypw;
  private $linotp_whitelist;

  function init()
  {
    $rcmail = rcmail::get_instance();

    // check whether the "global_config" plugin is available,
    // otherwise load the config manually.
    $plugins = $rcmail->config->get('plugins');
    $plugins = array_flip($plugins);
    if (!isset($plugins['global_config'])) {
      $this->load_config();
    }
    
    // load plugin configuration.
    $this->linotp_server = $rcmail->config->get('linotp_server', 'localhost');
    $this->linotp_port = $rcmail->config->get('linotp_port', 443);
    $this->linotp_emergencypw = $rcmail->config->get('linotp_emergencypw', '');
    $this->linotp_inc_pass = $rcmail->config->get('linotp_inc_pwd', false);
    $this->whitelist = $rcmail->config->get('linotp_whitelist', array('127.0.0.1'));
    $this->ipaddr = rcube_utils::remote_ip();

    // Check if IP is whitelisted, and if so do not show the OTP dialog field
    if (! $this->isWhitelisted($this->ipaddr)) {  

      // login form modification hook.
      $this->add_hook('template_object_loginform', array($this,'linotp_loginform'));

      // register hooks.
      $this->add_hook('authenticate', array($this, 'authenticate'));
    }
  }
  
  function linotp_loginform($content)
  {
    // load localizations.
    $this->add_texts('localization', true);
    
    // import javascript client code.
    $this->include_script('linotp.js');
    
    return $content;
  }
  
  function authenticate($args)
  {  
    $this->authenticate_args = $args;

    $user = $args['user'];
	$pass = $args['pass'];
    $code = rcube_utils::get_input_value('_code', rcube_utils::INPUT_POST);

    rcube::write_log('errors', 'linotp: OTP Code: ' . $code);

    if (!self::linotp_auth($user, $pass, $code, $this->linotp_server, $this->linotp_port, $this->linotp_emergencypw, $this->linotp_inc_pass))
    {
      rcube::write_log('errors', 'linotp: OTP verfication failed');
      $args['abort'] = true;
    }

    return $args;
  }
  
  function linotp_auth($user, $pass, $code, $server, $port, $emergencypw, $inc_pass)
  {
	$sock = fsockopen("ssl://".$server, $port, $errno, $errstr, 30);
	if (!$sock) {
		rcube::write_log('errors',"Network error: $errstr ($errno)");
		if ($code == $emergencypw){
			rcube::write_log('errors',"Allow user $user due to emergency password");
			return 1;
		}
		rcube::write_log('errors',"Disallow user $user due to network error");
		return 0;
	}

	$data = "user=" . urlencode(strtolower($user)) . "&pass=" . urlencode($code);
	// If password is to be included as part of the OTP
	if ( $inc_pass ) {
		$data = "user=" . urlencode(strtolower($user)) . "&pass=" . urlencode($pass.$code);
	}
	//$request = "POST /validate/check HTTPS/1.1\r\n";
	$request = "POST /validate/check HTTP/1.1\r\n";
	$request .= "Host: ".$server."\r\n";
	$request .= "Content-type: application/x-www-form-urlencoded\r\n";
	$request .= "Content-length: " . strlen($data) . "\r\n";
	$request .= "Connection: close\r\n\r\n";
	fputs($sock, $request);
	fputs($sock, $data);

	$headers = "";
	while ($str = trim(fgets($sock, 4096)))
	$headers .= "$str\n";
	$body = "";
	while (!feof($sock))
	$body .= fgets($sock, 4096);

	fclose($sock);
	
	$pos = strpos ( $body , "\"value\": true");
	if (!$pos) {
		rcube::write_log('errors', $user." not authorized");

		return 0;
	}
	if ($pos > 0){
		return 1;
	}
     return 0;
  }

 //** Most of the code below is taken from https://github.com/stalks/roundcube-defense/blob/master/defense.php by Steve Allison <roundcube-defense@nooblet.org>

  /**
    * Check if IP is matched against all IPs in array,
    * including CIDR matches
    *
    * @param string
    *       ip address
    * @param array
    *       ip/cidr addresses to match against
    * @return bool
    */
    private function isIPinArray($ip, $array) {
        foreach ($array as $value) {
            // If no slash '/' then its not a CIDR address and we can just string match
            if ((strpos($value, '/') === false) && (strcmp($ip, $value) == 0)) { $this->debug("IP Comp"); return true; }
            if (($this->isIPv6($ip)) && (!$this->isIPv6($value))) {  $this->debug("ipv6 1"); return false; }
            if (($this->isIPv4($value)) && (!$this->isIPv4($ip))) {  $this->debug("ipv4 2"); return false; }
            if (($this->isIPv4($ip) && ($this->isIPv4inCIDR($ip, $value)))) {  $this->debug("ipv4 3"); return true; }
            if (($this->isIPv6($ip) && ($this->isIPv6inCIDR($ip, $value)))) {  $this->debug("Ipv6 4"); return true; }
        }
        return false;
    }
  /**
    * Check if IPv4 is within stated CIDR address
    *
    * @param string
    *       ip address
    * @param string
    *       cidr address
    * @return bool
    */
    private function isIPv4inCIDR($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
	$this->debug($subnet);
        return ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet));
    }
  /**
    * Convert IPv6 mask to bytearray
    *
    * @param string
    *       subnet mask
    * @return string
    */
    private function IPv6MaskToByteArray($subnetMask) {
        $addr = str_repeat("f", $subnetMask / 4);
        switch ($subnetMask % 4) {
            case 0:
                break;
            case 1:
                $addr .= "8";
                break;
            case 2:
                $addr .= "c";
                break;
            case 3:
                $addr .= "e";
                break;
        }
        $addr = str_pad($addr, 32, '0');
        $addr = pack("H*" , $addr);
        return $addr;
    }
  /**
    * Check if IPv6 is within stated CIDR address
    *
    * @param string
    *       subnet mask
    * @return bool
    */
    private function isIPv6inCIDR($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        $binMask = $this->IPv6MaskToByteArray($mask);
        return ($ip & $binMask) == $subnet;
    }
  /**
    * Check string if it is IPv6
    *
    * @param string
    *       ip address
    * @return bool
    */
    private function isIPv6($ip) {
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

  /**
    * Check string if it is IPv4
    *
    * @param string
    *       ip address
    * @return bool
    */
    private function isIPv4($ip) {
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

  /**
    * Return true if IP matches config whitelist
    *
    * @param string
    *       ip address
    * @return bool
    */
    private function isWhitelisted($ip) {
        // If IP is listed in whitelist, return true
        if ($this->isIPinArray($this->ipaddr, $this->whitelist)) {
            return true;
        }
        return false;
    }
  /**
    * Output text to log file: $this->logfile
    *
    * @param string
    *       text for log
    */
    private function debug($string) {
        if (!$this->debugEnabled) { return; }
        rcube::write_log($this->logfile, "linotp : " . $this->ipaddr . " # " . $string);
    }
}
