use strict;
use warnings;

use Test::More 'no_plan';
use Test::Mojo;

use Mojolicious::Lite;
use Mojolicious::Plugin::DigestAuth::Util qw{parse_header checksum};

my $users = { sshaw => 'itzme!' };

# TODO: Still need to test bad options, opaque, path, IE qs
# Some of this code ---v should be the same as the code used by DigestAuth!
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
    
    $res_header->{uri} ||= '/' . $tx->req->url->to_rel; 
    $res_header->{nc} ||= 1;
    $res_header->{cnonce} ||= time;
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
    
    get '/test_defaults' => sub {
	my $self = shift;
	$self->render_text("You're in!") if $self->digest_auth(allow => $users);
    };

    get '/test_defaults_overridden' => sub {
	my $self = shift;    
	$self->render_text("You're in!") if $self->digest_auth(allow => $users, 
							       domain => 'example.com,dev.example.com',
							       realm => 'MD5-sess Realm',
							       algorithm => 'MD5-sess',
							       qop => '');
    };
    
    my $t = Test::Mojo->new;
    $t->get_ok('/test_defaults')
	->status_is(401)
	->header_like('WWW-Authenticate', qr/^Digest\s/)
	->header_like('WWW-Authenticate', qr/realm="WWW"/)
	->header_like('WWW-Authenticate', qr/nonce="[^"]+"/)
	->header_like('WWW-Authenticate', qr/opaque="\w+"/)
	->header_like('WWW-Authenticate', qr/domain="\/"/)
	->header_like('WWW-Authenticate', qr/algorithm="MD5"/)
	->header_like('WWW-Authenticate', qr/qop="auth,auth-int"/)
	->content_isnt("You're in!");


    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => 'sshaw', password => 'bad_bad_bad') })
	->status_is(401)
	->content_isnt("You're in!");

    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => 'not_in_realm') })
	->status_is(401)
	->content_isnt("You're in!");

    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, username => '', password => '') })
	->status_is(401)
	->content_isnt("You're in!");
    
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, algorithm => 'unknown') }) 
	->status_is(400)
	->content_isnt("You're in!");

    $t->get_ok('/test_defaults');
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx, qop => 'unknown') }) 
	->status_is(400)
	->content_isnt("You're in!");

    $t->get_ok('/test_defaults');
    $t->get_ok('/test_defaults', { Authorization => build_auth_response($t->tx) }) 
	->status_is(200)
	->content_is("You're in!");
        
    $t->get_ok('/test_defaults_overridden')    
	->status_is(401)
	->header_like('WWW-Authenticate', qr/realm="MD5-sess Realm"/)
	->header_like('WWW-Authenticate', qr/domain="example.com,dev.example.com"/)
	->header_like('WWW-Authenticate', qr/algorithm="MD5-sess"/)
	->header_unlike('WWW-Authenticate', qr/qop=/);   
}
 
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
	->header_like('WWW-Authenticate', qr/algorithm="MD5-sess"/);    
}

{
    package App;
    use Mojo::Base 'Mojolicious';
    
    sub startup
    {
	my $self = shift;
	$self->plugin('digest_auth');

	my $r    = $self->routes;
	$r = $self->digest_auth('/admin', allow => $users);	
	$r->route('/:id')->to('controller#show');	
    }

    package App::Controller;
    use Mojo::Base 'Mojolicious::Controller';
   
    sub show { shift->render(text => 'In!') }

    package main;

    my $t = Test::Mojo->new(App->new);     
    $t->get_ok('/admin/123')
        ->status_is(401)
        ->content_isnt('In!');

    my $headers = { Authorization => build_auth_response($t->tx) };
    $t->get_ok('/admin/123', $headers)
        ->status_is(200)
        ->content_is('In!');
}

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
