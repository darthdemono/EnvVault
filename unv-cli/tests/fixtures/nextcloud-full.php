<?php
// A synthetic config.php in the shapes config.sample.php documents: MySQL,
// Redis, SMTP and an S3 object store, with one value PHP must compute.
$CONFIG = array (
  'instanceid' => 'ocabc123',
  'passwordsalt' => 'EXAMPLE_SALT_aaaaaaaaaaaaaaaaaaaaaaaa',
  'secret' => 'EXAMPLE_SECRET_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'trusted_domains' =>
  array (
    0 => 'cloud.example.com',
  ),
  'overwrite.cli.url' => 'https://cloud.example.com',
  'dbtype' => 'mysql',
  'dbname' => 'nextcloud',
  'dbhost' => 'db:3306',
  'dbuser' => 'nc',
  'dbpassword' => 'EXAMPLE_DB_cccccccccccc',
  'mail_smtphost' => 'smtp.example.com',
  'mail_smtpname' => 'mailer@example.com',
  'mail_smtppassword' => 'EXAMPLE_SMTP_dddddddddddd',
  'redis' => [
    'host' => 'redis',
    'port' => 6379,
    'password' => 'EXAMPLE_REDIS_eeeeeeeeeeee', // Optional
  ],
  'objectstore' => [
    'class' => '\\OC\\Files\\ObjectStore\\S3',
    'arguments' => [
      'bucket' => 'nc-data',
      'key' => 'EXAMPLE_S3KEY',
      'secret' => 'EXAMPLE_S3SECRET_ffffffffffff',
      'hostname' => 's3.example.com',
      'use_ssl' => true,
    ],
  ],
  'license-key' => getenv('NC_LICENSE'),
  'version' => '29.0.16.1',
);
