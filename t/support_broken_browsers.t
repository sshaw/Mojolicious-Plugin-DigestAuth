use strict;
use warnings;
use lib 't';

use Mojolicious::Lite;
use Test::Mojo;

use TestHelper;

my $t = Test::Mojo->new;
my $uri = '/dont_support_broken_browsers';
my $req = "$uri?x=y";
get $uri => create_action(support_broken_browsers => 0);
$t->get_ok($req)
  ->status_is(401);

my $headers = build_auth_request($t->tx, uri => $uri);
$headers->{'User-Agent'} = IE6;
$t->get_ok($req, $headers)
  ->status_is(400);

$uri = '/support_broken_browsers';
$req = "$uri?x=y";
get $uri => create_action(support_broken_browsers => 1);
$t->get_ok($req)
  ->status_is(401);

$headers = build_auth_request($t->tx, uri => $uri);
$headers->{'User-Agent'} = IE6;
$t->get_ok($req, $headers)
  ->status_is(200);

# Request without opaque
