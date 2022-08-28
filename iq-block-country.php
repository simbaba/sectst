<?php   
/*
Plugin Name: iQ Block Country
Plugin URI: https://www.webence.nl/plugins/iq-block-country-the-wordpress-plugin-that-blocks-countries-for-you/
Version: 1.2.0
Author: Pascal
Author URI: https://www.webence.nl/
Description: Block visitors from visiting your website and backend website based on which country their IP address is from. The Maxmind GeoIP lite database is used for looking up from which country an ip address is from.
License: GPL2
Text Domain: iq-block-country
Domain Path: /lang
*/

/* This script uses GeoLite Country from MaxMind (http://www.maxmind.com) which is available under terms of GPL/LGPL */

/*  Copyright 2010-2018  Pascal  (email: pascal@webence.nl)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*
 * 
 * This software is dedicated to my one true love.
 * Luvya :)
 * 
 */

/*
 * Try to make this plugin the first plugin that is loaded.
 * Because we output header info we don't want other plugins to send output first.
 */
function iqblockcountry_this_plugin_first() 
{
	$wp_path_to_this_file = preg_replace('/(.*)plugins\/(.*)$/', WP_PLUGIN_DIR."/$2", __FILE__);
	$this_plugin = plugin_basename(trim($wp_path_to_this_file));
	$active_plugins = get_option('active_plugins');
	$this_plugin_key = array_search($this_plugin, $active_plugins);
	if ($this_plugin_key) { // if it's 0 it's the first plugin already, no need to continue
		array_splice($active_plugins, $this_plugin_key, 1);
		array_unshift($active_plugins, $this_plugin);
		update_option('active_plugins', $active_plugins);
	}     
}


/*
 * Attempt on output buffering to protect against headers already send mistakes 
 */
function iqblockcountry_buffer() {
	ob_start();
} 

/*
 * Attempt on output buffering to protect against headers already send mistakes 
 */
function iqblockcountry_buffer_flush() {
	ob_end_flush();
} 


/*
 * Localization
 */
function iqblockcountry_localization()
{
    load_plugin_textdomain( 'iq-block-country', false, dirname( plugin_basename( __FILE__ ) ) . '/lang' );
}

 /*
  * Retrieves the IP address from the HTTP Headers
 */
function iqblockcountry_get_ipaddress() {
    global $ip_address;
    return '178.18.25.17';

    
    if ( isset($_SERVER['HTTP_CF_CONNECTING_IP']) && !empty($_SERVER['HTTP_CF_CONNECTING_IP']) ) {
    $ip_address = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    elseif ( isset($_SERVER['HTTP_X_SUCURI_CLIENTIP']) && !empty($_SERVER['HTTP_X_SUCURI_CLIENTIP']) ) {
    $ip_address = $_SERVER['HTTP_X_SUCURI_CLIENTIP'];
    }
    elseif ( isset($_SERVER['HTTP_INCAP_CLIENT_IP']) && !empty($_SERVER['HTTP_INCAP_CLIENT_IP']) ) {
    $ip_address = $_SERVER['HTTP_INCAP_CLIENT_IP'];
    }
    elseif ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ) {
    $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } 
    elseif ( isset($_SERVER['HTTP_X_FORWARDED']) && !empty($_SERVER['HTTP_X_FORWARDED']) ) {
    $ip_address = $_SERVER['HTTP_X_FORWARDED'];
    }
    elseif ( isset($_SERVER['HTTP_CLIENT_IP']) && !empty($_SERVER['HTTP_CLIENT_IP']) ) {
    $ip_address = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif ( isset($_SERVER['HTTP_X_REAL_IP']) && !empty($_SERVER['HTTP_X_REAL_IP']) ) {
    $ip_address = $_SERVER['HTTP_X_REAL_IP'];
    } 
    elseif ( isset($_SERVER['HTTP_FORWARDED']) && !empty($_SERVER['HTTP_FORWARDED']) ) {
    $ip_address = $_SERVER['HTTP_FORWARDED'];
    }
    elseif ( isset($_SERVER['REMOTE_ADDR']) && !empty($_SERVER['REMOTE_ADDR']) ) {
    $ip_address = $_SERVER['REMOTE_ADDR'];
    }

    // Get first ip if ip_address contains multiple addresses
    $ips = explode(',', $ip_address);
    $ip_address = trim($ips[0]);

    return $ip_address;
}


function iqblockcountry_upgrade()
{
    /* Check if update is necessary */
    $dbversion = get_option( 'blockcountry_version' );
    update_option('blockcountry_version',VERSION);

    if ($dbversion != "" && version_compare($dbversion, "1.1.51", '<') )
    {
        iqblockcountry_find_geoip_location();
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.1.44", '<') )
    {
        $server_addr = array_key_exists( 'SERVER_ADDR', $_SERVER ) ? $_SERVER['SERVER_ADDR'] : $_SERVER['LOCAL_ADDR'];
        if (get_option('blockcountry_frontendwhitelist') === FALSE || (get_option('blockcountry_frontendwhitelist') == "")) { update_option('blockcountry_frontendwhitelist',$server_addr); }        iqblockcountry_install_db();       
        
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.1.41", '<') )
    {
        iqblockcountry_find_geoip_location();
        update_option('blockcountry_daysstatistics',30);
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.1.31", '<') )
    {
        if (!get_option('blockcountry_blocktag'))
        {
            update_option('blockcountry_blocktag','on');
        }
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.1.19", '<') )
    {
        update_option('blockcountry_blocksearch','on');
    }
    if ($dbversion != "" && version_compare($dbversion, "1.1.17", '<') )
    {
        delete_option('blockcountry_automaticupdate');
        delete_option('blockcountry_lastupdate');
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.1.11", '<') )
    {
        update_option('blockcountry_nrstatistics', 15);
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.0.10", '<') )
    {
        $frontendbanlist = get_option('blockcountry_banlist');
        update_option('blockcountry_backendbanlist',$frontendbanlist);
        update_option('blockcountry_backendnrblocks', 0);
        update_option('blockcountry_frontendnrblocks', 0);
        update_option('blockcountry_header', 'on');
    }
    elseif ($dbversion != "" && version_compare($dbversion, "1.0.10", '=') )
    {
        iqblockcountry_install_db();
        update_option('blockcountry_backendnrblocks', 0);
        update_option('blockcountry_frontendnrblocks', 0);
        update_option('blockcountry_header', 'on');
    }        
    elseif ($dbversion == "")
    {
        iqblockcountry_install_db();
        add_option( "blockcountry_dbversion", DBVERSION );
        update_option('blockcountry_blockfrontend' , 'on');
        update_option('blockcountry_version',VERSION);
        update_option('blockcountry_backendnrblocks', 0);
        update_option('blockcountry_frontendnrblocks', 0);
        update_option('blockcountry_header', 'on');
        $frontendbanlist = get_option('blockcountry_banlist');
        update_option('blockcountry_backendbanlist',$frontendbanlist);
    }    

    iqblockcountry_update_db_check();
   
}


/*
 * Main plugin works.
 */
$upload_dir = wp_upload_dir();
define("CHOSENJS", plugins_url('/js/chosen.jquery.js', __FILE__));
define("CHOSENCSS", plugins_url('/chosen.css', __FILE__));
define("CHOSENCUSTOM",plugins_url('/js/chosen.custom.js', __FILE__));
define("GEOIP2DB","http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz"); // Used to display download location.
define("IPV4DBFILE",$upload_dir['basedir'] . "/GeoIP.dat");
define("IPV6DBFILE",$upload_dir['basedir'] . "/GeoIPv6.dat");
define("GEOIP2DBFILE",$upload_dir['basedir'] . "/GeoLite2-Country.mmdb");
define("TRACKINGURL","https://tracking.webence.nl/iq-block-country-tracking.php");
define("BANLISTRETRIEVEURL","https://eu.adminblock.webence.nl/iq-block-country-retrieve.php");
define("GEOIPAPIURL","https://eu.geoip.webence.nl/geoipapi.php");
define("GEOIPAPIURLUS","https://us.geoip.webence.nl/geoipapi.php");
define("GEOIPAPIURLUS2","https://us2.geoip.webence.nl/geoipapi.php");
define("GEOIPAPIURLUS3","https://us3.geoip.webence.nl/geoipapi.php");
define("GEOIPAPIURLASIA","https://asia.geoip.webence.nl/geoipapi.php");
define("GEOIPAPICHECKURL","https://eu.geoip.webence.nl/geoipapi-keycheck.php");
define("ADMINAPICHECKURL","https://tracking.webence.nl/adminapi-keycheck.php");
define("IPLOOKUPURL",'https://geoip.webence.nl/iplookup/iplookup.php');
define("VERSION","1.2.0");
define("DBVERSION","122");
define("PLUGINPATH",plugin_dir_path( __FILE__ )); 



/*
 * Include libraries
 */
require_once('libs/blockcountry-geoip.php');
require_once('libs/blockcountry-checks.php');
require_once('libs/blockcountry-settings.php');
require_once('libs/blockcountry-validation.php');
require_once('libs/blockcountry-logging.php');
require_once('libs/blockcountry-tracking.php');
require_once('libs/blockcountry-search-engines.php');
require_once('vendor/autoload.php');

global $apiblacklist;
$apiblacklist = FALSE;
$backendblacklistcheck = FALSE;

$blockcountry_is_login_page = iqblockcountry_is_login_page();
$blockcountry_is_xmlrpc = iqblockcountry_is_xmlrpc();

register_activation_hook(__file__, 'iqblockcountry_this_plugin_first');
register_activation_hook(__file__, 'iqblockcountry_set_defaults');
register_uninstall_hook(__file__, 'iqblockcountry_uninstall');

 // Check if upgrade is necessary
 iqblockcountry_upgrade();
  
 /* Clean logging database */
 iqblockcountry_clean_db();
iqblockcountry_get_blackwhitelist(); 
 
if (isset($_GET['action']))
{       

    $iqaction = filter_var($_GET['action'],FILTER_SANITIZE_STRING);
    if ($iqaction == 'csvoutput') {
        if(!function_exists('is_user_logged_in')) {
            include(ABSPATH . "wp-includes/pluggable.php"); 
        }
    
        global $wpdb;
        $output = "";
        $table_name = $wpdb->prefix . "iqblock_logging";
        $format = get_option('date_format') . ' ' . get_option('time_format');
        $q = $wpdb->get_results( "SELECT datetime, ipaddress, url FROM $table_name WHERE ipaddress = '" . $_GET['ip'] . "' ORDER BY datetime ASC" );
        foreach ($q as $row)
        {
            $datetime = strtotime($row->datetime);
            $mysqldate = date($format, $datetime);
            echo '"' . $mysqldate . '"' . ';"' . $row->ipaddress . '";"' . $row->url . '"'. "\n";
        }
        exit();
    }
}

    $ip_address = iqblockcountry_get_ipaddress();
    $country = iqblockcountry_check_ipaddress($ip_address);
    iqblockcountry_debug_logging($ip_address,$country,'');

    
function iq_add_my_scripts() {
    // Scripts
    wp_enqueue_script( 'chosen', CHOSENJS, array( 'jquery' ), false, true );
    wp_enqueue_script( 'custom', CHOSENCUSTOM, array( 'jquery', 'chosen' ), false, true );
}

add_action( 'admin_enqueue_scripts', 'iq_add_my_scripts' );    
    

  /*
 * Check first if users want to block the backend.
 */
if (($blockcountry_is_login_page || is_admin() || $blockcountry_is_xmlrpc) && get_option('blockcountry_blockbackend') == 'on')
{
    add_action ( 'init', 'iqblockcountry_checkCountryBackEnd', 1 );
}
elseif ((!$blockcountry_is_login_page && !is_admin() && !$blockcountry_is_xmlrpc) && get_option('blockcountry_blockfrontend') == 'on')
{
    add_action ( 'wp', 'iqblockcountry_checkCountryFrontEnd', 1 );
}
else
{
    $ip_address = iqblockcountry_get_ipaddress();
    $country = iqblockcountry_check_ipaddress($ip_address);
    iqblockcountry_debug_logging($ip_address,$country,'NH');

}

add_action ( 'admin_init', 'iqblockcountry_localization');
add_action ( 'admin_menu', 'iqblockcountry_create_menu' );
add_filter ( 'update_option_blockcountry_tracking', 'iqblockcountry_schedule_tracking', 10, 2);
add_filter ( 'add_option_blockcountry_tracking', 'iqblockcountry_schedule_tracking', 10, 2);
add_filter ( 'update_option_blockcountry_apikey', 'iqblockcountry_schedule_retrieving', 10, 2);
add_filter ( 'add_option_blockcountry_apikey', 'iqblockcountry_schedule_retrieving', 10, 2);

add_filter ( 'update_option_blockcountry_debuglogging', 'iqblockcountry_blockcountry_debuglogging', 10, 2);
add_filter ( 'add_option_blockcountry_debuglogging', 'iqblockcountry_blockcountry_debuglogging', 10, 2);
add_action ( 'blockcountry_tracking', 'iqblockcountry_tracking' );
add_action ( 'blockcountry_retrievebanlist',  'iqblockcountry_tracking_retrieve_xml');
if (get_option('blockcountry_buffer') == "on")
{
    add_action ( 'init', 'iqblockcountry_buffer',1);
    add_action ( 'shutdown', 'iqblockcountry_buffer_flush');
}


?>
