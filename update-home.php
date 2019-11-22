<?php

require 'vendor/autoload.php';

$credentials   = parse_ini_file(dirname(__FILE__) . '/cloudflare.ini');

$cfEmail       = $credentials['dns_cloudflare_email'];
$cfKey         = $credentials['dns_cloudflare_api_key'];
$domain        = $credentials['dns_cloudflare_domain'];
$subdomain     = $credentials['dns_cloudflare_subdomain'];

$key           = new Cloudflare\API\Auth\APIKey($cfEmail, $cfKey);
$adapter       = new Cloudflare\API\Adapter\Guzzle($key);
$zones         = new Cloudflare\API\Endpoints\Zones($adapter);
$dns           = new Cloudflare\API\Endpoints\DNS($adapter);

$zoneId        = $zones->getZoneID($domain);
$recordId      = $dns->getRecordId($zoneId, 'A', $subdomain);
$recordDetails = $dns->getRecordDetails($zoneId, $recordId);
$cfRecord      = $recordDetails->content;

$command       = "dig +short myip.opendns.com @resolver1.opendns.com";
$results       = shell_exec("$command 2>&1");
$dnsRecord     = nl2br(htmlentities(trim($results)));

if (filter_var($dnsRecord, FILTER_VALIDATE_IP) !== false) {
    if ($cfRecord !== $dnsRecord) {
	$details = [
	    'name'    => $subdomain,
	    'type'    => 'A',
	    'content' => $dnsRecord
	];
	$response = $dns->updateRecordDetails($zoneId, $recordId, $details);
	if ($response->success !== true) {
	    syslog(LOG_ALERT, 'Unable to update Cloudflare DNS address.');
	    exit;
	}
    }
    else {
        syslog(LOG_INFO, 'DNS IP and Cloudflare record match.');
    }
}
else {
    syslog(LOG_ALERT, 'Unable to obtain DNS using dig.');
    exit;
}

