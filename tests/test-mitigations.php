<?php
/**
 * Standalone PHP Mitigation Verification Script
 *
 * Can be run from CLI on any PHP environment:
 * php tests/test-mitigations.php
 */

define( 'PHP_ARMOR_STANDALONE', true );
require_once dirname( __DIR__ ) . '/includes/class-php-armor-firewall.php';

echo "========================================================\n";
echo "PHP ARMOR NATIVE PHP ENGINE MITIGATION TEST SUITE\n";
echo "========================================================\n\n";

$passed = 0;
$failed = 0;

function assert_test( $name, $result, $expected = true ) {
	global $passed, $failed;
	if ( $result === $expected ) {
		echo " [PASS] $name\n";
		$passed++;
	} else {
		echo " [FAIL] $name (Expected " . var_export( $expected, true ) . ", got " . var_export( $result, true ) . ")\n";
		$failed++;
	}
}

// 1. CVE-2024-4577 Tests
echo "--- Testing CVE-2024-4577 (PHP-CGI Argument Injection) ---\n";
$_SERVER['QUERY_STRING'] = '%ad-d+auto_prepend_file=php://input';
$_SERVER['REQUEST_URI']  = '/index.php?' . $_SERVER['QUERY_STRING'];
$threat = PHP_Armor_Firewall::detect_cve_2024_4577();
assert_test( 'Soft-hyphen %ad + auto_prepend_file', is_array( $threat ) );

$_SERVER['QUERY_STRING'] = '-d+allow_url_include=1+-d+auto_prepend_file=php://input';
$_SERVER['REQUEST_URI']  = '/index.php?' . $_SERVER['QUERY_STRING'];
$threat = PHP_Armor_Firewall::detect_cve_2024_4577();
assert_test( 'Direct -d argument injection', is_array( $threat ) );

$_SERVER['QUERY_STRING'] = 's=wordpress+plugins&category=security';
$_SERVER['REQUEST_URI']  = '/index.php?' . $_SERVER['QUERY_STRING'];
$threat = PHP_Armor_Firewall::detect_cve_2024_4577();
assert_test( 'Legitimate search query false-positive check', false === $threat );

// 2. PHP2Shell Tests
echo "\n--- Testing PHP2Shell (Session Upload Progress) ---\n";
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST['PHP_SESSION_UPLOAD_PROGRESS'] = '<?php phpinfo(); ?>';
$_FILES = array();
$threat = PHP_Armor_Firewall::detect_php2shell();
assert_test( 'PHP tag in session upload progress', is_array( $threat ) );

// 3. CVE-2024-2961 Stream Filter Chain Tests
echo "\n--- Testing CVE-2024-2961 & Filter Chains ---\n";
$_GET['filter'] = 'php://filter/convert.iconv.ISO-2022-CN-EXT.UTF-8/resource=test';
$threat = PHP_Armor_Firewall::detect_stream_wrapper_exploits();
assert_test( 'ISO-2022-CN-EXT iconv filter chain', is_array( $threat ) );

$_GET['filter'] = 'php://filter/read=convert.base64-encode|convert.base64-decode|convert.base64-encode/resource=wp-config.php';
$threat = PHP_Armor_Firewall::detect_stream_wrapper_exploits();
assert_test( 'Excessive pipe chained filter targeting wp-config.php', is_array( $threat ) );

$_GET['filter'] = 'phar://malicious.phar/exploit';
$threat = PHP_Armor_Firewall::detect_stream_wrapper_exploits();
assert_test( 'phar:// stream wrapper deserialization', is_array( $threat ) );

$_GET['filter'] = 'https://example.com/safe-article';
$threat = PHP_Armor_Firewall::detect_stream_wrapper_exploits();
assert_test( 'Safe HTTP URL parameter false-positive check', false === $threat );

// 4. Object Injection Tests
echo "\n--- Testing PHP Object Injection ---\n";
$_GET['payload'] = 'O:14:"App\\Vulnerable":1:{s:3:"cmd";s:6:"whoami";}';
$threat = PHP_Armor_Firewall::detect_object_injection();
assert_test( 'Serialized object payload O:14', is_array( $threat ) );

$_GET['payload'] = 'normal_string_value_without_objects';
$threat = PHP_Armor_Firewall::detect_object_injection();
assert_test( 'Normal text false-positive check', false === $threat );

echo "\n========================================================\n";
echo "SUMMARY: Passed: $passed, Failed: $failed\n";
echo "========================================================\n";

