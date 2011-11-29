use strict;
use warnings;
use lib 't';

use Mojolicious::Lite;
use Test::Mojo;

use TestHelper;

# url (req_uri, script_name, ie fix, QS)

my $url = '/';
get $url => create_action();

my $t = Test::Mojo->new;

# Mojo related URL handling
$t->get_ok($url)
  ->status_is(401);
$t->get_ok($url, build_auth_request($t->tx, uri => $url))
  ->status_is(200);

$t->get_ok($url);
$t->get_ok($url, build_auth_request($t->tx, uri => '/?'))
  ->status_is(200);

$t->get_ok($url)
  ->status_is(401);
$t->get_ok($url, build_auth_request($t->tx, uri => '//'))
  ->status_is(200);

$t->get_ok($url)
  ->status_is(401);
$t->get_ok("$url?a=b", build_auth_request($t->tx, uri => '//?a=b'))
  ->status_is(200);

$t->get_ok($url);
$t->get_ok($url, build_auth_request($t->tx, uri => 'http://a.com'))
  ->status_is(200);

$t->get_ok($url);
$t->get_ok("$url?a=b%20c", build_auth_request($t->tx, uri => 'http://a.com?a=b%20c'))
  ->status_is(200);

$t->get_ok($url);
$t->get_ok("$url?a=b%20c", build_auth_request($t->tx, uri => 'http://a.com?a=b c'))
  ->status_is(200);

####  support_broken_browsers => 1/0 for this
# $t->get_ok($url)
#   ->status_is(401);
# $t->get_ok("$url?a=b", build_auth_request($t->tx, uri => '//'))
#   ->status_is(200);
#######

#$url = '/a';
#get $url => create_action(env => { REQUEST_URI => '/a/' });

# $url = '/a/b';
# get $url => create_action();
# $t->get_ok($url);
# $t->get_ok($url, build_auth_request($t->tx, uri => '/a/b?\\'))
#   ->status_is(200);

# $t->get_ok($url);
# $t->get_ok($url, build_auth_request($t->tx, uri => '//a/b'))
#   ->status_is(200);

# $t->get_ok($url);
# $t->get_ok($url, build_auth_request($t->tx, uri => '/a///b/'))
#   ->status_is(200);

# $t->get_ok($url);
# $t->get_ok($url, build_auth_request($t->tx, uri => 'a//b'))
#   ->status_is(200);
