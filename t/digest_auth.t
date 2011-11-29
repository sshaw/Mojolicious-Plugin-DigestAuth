use strict;
use warnings;
use lib 't';

use Test::More 'no_plan';
use Test::Mojo;
#use TestHelper;

use Mojolicious::Lite;
use Mojolicious::Plugin::DigestAuth::Util qw{parse_header checksum};

my $users = { sshaw => 'itzme!' };

# options (defaults, invalid)
# requests 
# bridge
# nonce

# This fx() should use the same code as DigestAuth!
sub build_auth_response
{
    my ($tx, %defaults) = @_;
    my $req_header = parse_header($tx->res->headers->www_authenticate);	
    my $res_header = {};
    my $user = delete $defaults{username};
    my $pass = delete $defaults{password};
    my @common_parts = qw{algorithm nonce opaque realm};	

    $user = 'sshaw' if !defined $user;
    $pass = $users->{$user} || '' if !defined $pass;

    @$res_header{@common_parts, keys %defaults} = (@$req_header{@common_parts}, values %defaults);

    # Test::Mojo handles the url differently between versions
    if(!$res_header->{uri}) {
	$res_header->{uri} = $tx->req->url->path->to_string;
	$res_header->{uri} .= '?' . $tx->req->url->query if $tx->req->url->query->to_string;
    }
    
    $res_header->{nc} ||= 1;
    $res_header->{cnonce} ||= time();
    $res_header->{qop} ||= 'auth';
    $res_header->{username} = $user;
    $res_header->{response} = checksum(checksum($user, $res_header->{realm}, $pass),
				       $res_header->{nonce},
				       $res_header->{nc},
				       $res_header->{cnonce},
				       $res_header->{qop},
				       checksum($tx->req->method, $res_header->{uri}));

    sprintf 'Digest %s', join ', ', map { "$_=\"$res_header->{$_}\"" } keys %$res_header;
}

{ 
    plugin 'digest_auth';
    
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

    get '/no_allow'  => sub { $error_checker->(shift) };
    get '/wrong_qop' => sub { $error_checker->(shift, allow => $users, qop => 'huh?') };
    get '/MD5-sess_no_qop' => sub { $error_checker->(shift, allow => $users, algorithm => 'MD5-sess', qop => '') };
    get '/wrong_algorithm' => sub { $error_checker->(shift, allow => $users, algorithm => '3DES') };    

     my $t = Test::Mojo->new;
     $t->get_ok('/no_allow');
     $t->status_is(500);
     $t->content_like(qr/you must setup an authentication source/);

     $t->get_ok('/MD5-sess_no_qop');
     $t->status_is(500);
     $t->content_like(qr/requires a qop/);

     $t->get_ok('/wrong_qop');
     $t->status_is(500);
     $t->content_like(qr/unsupported qop/);

     $t->get_ok('/wrong_algorithm');
     $t->status_is(500);
     $t->content_like(qr/unsupported algorithm/);
}

{
    plugin 'digest_auth';
    
    any '/test_defaults' => sub {
	my $self = shift;
	$self->render_text("You're in!") if $self->digest_auth(allow => $users);
    };

    get '/test_defaults_overridden' => sub {
	my $self = shift;    
	$self->render_text("You're in!") if $self->digest_auth(allow => $users, 
							       domain => 'example.com,dev.example.com',
							       realm => 'MD5-sess Realm',
							       algorithm => 'MD5-sess');
							       
    };
    
    my $t = Test::Mojo->new;
    $t->get_ok('/test_defaults')
	->status_is(401)
	->header_like('WWW-Authenticate', qr/^Digest\s/)
	->header_like('WWW-Authenticate', qr/realm="WWW"/)
	->header_like('WWW-Authenticate', qr/nonce="[^"]+"/)
	->header_like('WWW-Authenticate', qr/opaque="\w+"/)
	->header_like('WWW-Authenticate', qr/domain="\/"/)
	->header_like('WWW-Authenticate', qr/algorithm=MD5/)
	->header_like('WWW-Authenticate', qr/qop="auth"/) #,auth-int"/)
	->content_isnt("You're in!");

    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => 'sshaw', password => 'bad_bad_bad') })
	->status_is(401)
	->content_is('HTTP 401: Unauthorized');
# #REQ
    
    # $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => 'not_in_realm') })
    # 	->status_is(401);

    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => '', password => '') })
    	->status_is(401);
    
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, algorithm => 'unknown') }) 
    	->status_is(400)
    	->content_is('HTTP 400: Bad Request');

    $t->get_ok('/test_defaults');
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, qop => 'unknown') }) 
	->status_is(400);

    $t->get_ok('/test_defaults');
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, opaque => 'baaaaahd') }) 
	->status_is(400);

    $t->get_ok('/test_defaults');
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx), HTTP_SCRIPT_NAME => 'Ass'})
	->status_is(200)
	->content_is("You're in!");

    # Needs useragent of IE
    # Test without query string 
#    $t->get_ok('/test_defaults');
#    $t->get_ok('/test_defaults?a=b&x=y', { Authorization => build_auth_response($t->tx, uri => '/test_defaults') })
#	->status_is(200);

    $t->post_ok('/test_defaults');
    $t->post_ok('/test_defaults', { Authorization => build_auth_response($t->tx) }) 
	->status_is(200)
	->content_is("You're in!");

    $t->get_ok('/test_defaults_overridden')    
	->status_is(401)
	->header_like('WWW-Authenticate', qr/realm="MD5-sess Realm"/)
	->header_like('WWW-Authenticate', qr/domain="example.com,dev.example.com"/)
	->header_like('WWW-Authenticate', qr/algorithm=MD5-sess/)
	->header_unlike('WWW-Authenticate', qr/qop=auth/);   

    $t->get_ok('/test_defaults_overridden', { Authorization => build_auth_response($t->tx, qop => 'auth-int') })
	->status_is(400);

    $t->get_ok('/test_defaults_overridden');
    $t->get_ok('/test_defaults_overridden', { Authorization => build_auth_response($t->tx, algorithm => 'MD5') })
	->status_is(400);

}

#OPT 
{
    plugin 'digest_auth', domain => 'example.com', 
    			  realm => 'Default', 
		 	  algorithm => 'MD5-sess', 
    			  allow => $users;

    get '/test_user_defined_defaults' => sub { $_[0]->digest_auth };
    
    my $t = Test::Mojo->new;     
    $t->get_ok('/test_user_defined_defaults')
	->status_is(401)
	->header_like('WWW-Authenticate', qr/^Digest\s/)
	->header_like('WWW-Authenticate', qr/domain="example.com"/)
	->header_like('WWW-Authenticate', qr/realm="Default"/)
	->header_like('WWW-Authenticate', qr/algorithm=MD5-sess/);    
}

# BR
{
    package App;
    use Mojo::Base 'Mojolicious';
    
    sub startup
    {
	my $self = shift;
	$self->plugin('digest_auth');

	my $r = $self->digest_auth('/admin', allow => $users);	
	$r->route('/:id')->to('controller#show');	
    }

    package App::Controller;
    use Mojo::Base 'Mojolicious::Controller';
   
    sub show { shift->render(text => 'In!') }

    package main;

    my $t = Test::Mojo->new;
    $t->app(App->new);        
    $t->get_ok('/admin/123')
        ->status_is(401)
	->content_is('HTTP 401: Unauthorized');

    my $headers = { Authorization => build_auth_response($t->tx) };
    $t->get_ok('/admin/123', $headers)
        ->status_is(200)
        ->content_is('In!');
}

#Nonce
{

    plugin 'digest_auth';
    
    get '/test_nonce_expires' => sub {
	my $self = shift;    
	$self->render_text("You're in!") if $self->digest_auth(allow => $users, expires => 1);
    };
    
    my $t = Test::Mojo->new;     
    $t->get_ok('/test_nonce_expires')
	->status_is(401);
    
    my $headers = { Authorization => build_auth_response($t->tx) };
    $t->get_ok('/test_nonce_expires', $headers)
    ->status_is(200);
    
    # Let nonce expire
    sleep(2);
    $t->get_ok('/test_nonce_expires', $headers)
	->status_is(401)
	->header_like('WWW-Authenticate', qr/stale=true/);
    
    # Authenticate with new nonce
    $t->get_ok('/test_nonce_expires', { Authorization => build_auth_response($t->tx) })
	->status_is(200);
}
