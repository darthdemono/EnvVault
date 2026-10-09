<?php
$CONFIG = array (
  'htaccess.RewriteBase' => '/',
  'memcache.local' => '\\OC\\Memcache\\APCu',
  'apps_paths' => 
  array (
    0 => 
    array (
      'path' => '/var/www/html/apps',
      'url' => '/apps',
      'writable' => false,
    ),
    1 => 
    array (
      'path' => '/var/www/html/custom_apps',
      'url' => '/custom_apps',
      'writable' => true,
    ),
  ),
  'upgrade.disable-web' => true,
  'passwordsalt' => '7BqCsBMWVXScGINU5K3Irf5RyffdgC',
  'secret' => 'mFrqYbFBLdOuJDvoBYxNUx5a8Ic3jNvCKchNmGmZ+udSoqvp',
  'trusted_domains' => 
  array (
    0 => 'localhost',
  ),
  'datadirectory' => '/var/www/html/data',
  'dbtype' => 'sqlite3',
  'version' => '29.0.16.1',
  'overwrite.cli.url' => 'http://localhost',
  'dbname' => 'nc',
  'installed' => true,
  'instanceid' => 'oc8u6g4icnd8',
);
