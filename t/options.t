use strict;
use warnings;
use lib 't';

use Mojolicious::Lite;

use Test::Mojo;
use Test::More 'no_plan';

use TestHelper;
 
my $error_checker = sub { 
    my ($self, %options) = @_;
    my $reply  = 'No error';

    eval { $self->digest_auth(%options) };
    if($@) {	    
	$reply = $@;		
	$self->res->code(500);
    }
    
    $self->render(text => $reply);
};

plugin 'digest_auth';

get '/no_allow' => sub { $error_checker->(shift) };
get '/unsupported_qop' => sub { $error_checker->(shift, allow => users(), qop => 'huh?') };
get '/unsupported_algorithm' => sub { $error_checker->(shift, allow => users(), algorithm => '3DES') };    
get '/MD5-sess_no_qop' => sub { $error_checker->(shift, allow => users(), algorithm => 'MD5-sess', qop => '') };

my $t = Test::Mojo->new;
$t->get_ok('/no_allow');
$t->status_is(500);
$t->content_like(qr/you must setup an authentication source/);

$t->get_ok('/MD5-sess_no_qop');
$t->status_is(500);
$t->content_like(qr/requires a qop/);

$t->get_ok('/unsupported_qop');
$t->status_is(500);
$t->content_like(qr/unsupported qop/);

$t->get_ok('/unsupported_algorithm');
$t->status_is(500);
$t->content_like(qr/unsupported algorithm/);

any '/test_defaults' => create_action();
$t->get_ok('/test_defaults')
  ->status_is(401)
  ->header_like('WWW-Authenticate', qr/^Digest\s/)
  ->header_like('WWW-Authenticate', qr/realm="WWW"/)
  ->header_like('WWW-Authenticate', qr/nonce="[^"]+"/)
  ->header_like('WWW-Authenticate', qr/opaque="\w+"/)
  ->header_like('WWW-Authenticate', qr/domain="\/"/)
  ->header_like('WWW-Authenticate', qr/algorithm=MD5/)
  ->header_like('WWW-Authenticate', qr/qop="auth"/)  #,auth-int"/)
  ->content_isnt("You're in!");

$t->get_ok('/test_defaults', build_auth_request($t->tx, username => 'sshaw', password => 'bad_bad_bad'))
  ->status_is(401)
  ->content_is('HTTP 401: Unauthorized');

# #REQ    
# $t->get_ok('/test_defaults', { Authorization => build_auth_request($t->tx, username => 'not_in_realm') })
#   ->status_is(401);

$t->get_ok('/test_defaults', build_auth_request($t->tx, username => '', password => ''))
  ->status_is(401);
    
$t->get_ok('/test_defaults', build_auth_request($t->tx, algorithm => 'unknown'))
  ->status_is(400)
  ->content_is('HTTP 400: Bad Request');

$t->get_ok('/test_defaults')
  ->status_is(401);
$t->get_ok('/test_defaults', build_auth_request($t->tx, qop => 'unknown')) 
  ->status_is(400);

$t->get_ok('/test_defaults')
  ->status_is(401);
$t->get_ok('/test_defaults', build_auth_request($t->tx, opaque => 'baaaaahd'))
  ->status_is(400);

$t->get_ok('/test_defaults')
  ->status_is(401);
$t->get_ok('/test_defaults', build_auth_request($t->tx))
  ->status_is(200)
  ->content_is("You're in!");

# By default support_broken_browsers = 1 
$t->get_ok('/test_defaults?a=b')
  ->status_is(401);
$t->get_ok('/test_defaults?a=b', { %{build_auth_request($t->tx)}, 'User-Agent' => IE6 })
  ->status_is(200)
  ->content_is("You're in!");

$t->post_ok('/test_defaults')
  ->status_is(401);
$t->post_ok('/test_defaults', build_auth_request($t->tx))
  ->status_is(200)
  ->content_is("You're in!");

get '/test_defaults_overridden' => create_action(realm     => 'MD5-sess Realm',
						 domain    => 'example.com,dev.example.com',						 
						 algorithm => 'MD5-sess');
							                  
$t->get_ok('/test_defaults_overridden')    
  ->status_is(401)
  ->header_like('WWW-Authenticate', qr/realm="MD5-sess Realm"/)
  ->header_like('WWW-Authenticate', qr/domain="example.com,dev.example.com"/)
  ->header_like('WWW-Authenticate', qr/algorithm=MD5-sess/)
  ->header_unlike('WWW-Authenticate', qr/qop=auth/);   

$t->get_ok('/test_defaults_overridden', { Authorization => build_auth_request($t->tx, qop => 'auth-int') })
  ->status_is(400);

$t->get_ok('/test_defaults_overridden');
$t->get_ok('/test_defaults_overridden', { Authorization => build_auth_request($t->tx, algorithm => 'MD5') })
  ->status_is(400);

