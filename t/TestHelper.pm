package TestHelper;

use strict;
use warnings;
use base 'Exporter';

use Mojolicious::Lite;
use Mojolicious::Plugin::DigestAuth::Util qw{checksum parse_header};

our @EXPORT = qw{build_auth_request users create_action};

my $users = { sshaw => 'itzme!' };
sub users { $_[0] ? $users->{$_[0]} : $users }

sub create_action
{
    my $options = { @_ };
    $options->{allow} ||= users();

    my $env = delete $options->{env} || {};
    sub { 
	my $self = shift;
	$self->app->plugin('digest_auth', $options);
	$self->req->env($env);
	$self->render_text("You're in!") if $self->digest_auth;
    };
}

sub create_actionaaa
{
    my $req = pop;
    my $url = '/test';
    $url = shift if @_ % 2;
    
    my $options = { @_ };
    $options->{allow} ||= users();
    plugin 'digest_auth';
    get $url => sub { 
	my $self = shift;
	$self->render_text("You're in!") if $self->digest_auth($options);
    };
    
    $req->();
}

# This fx() should use the same code as DigestAuth!
sub build_auth_request
{
    my ($tx, %defaults) = @_;
    my $req_header = parse_header($tx->res->headers->www_authenticate);	
    use Data::Dump 'dd';
    #dd($req_header);
    #dd($tx->res->headers->to_hash);
    my $res_header = {};
    my $user = delete $defaults{username};
    my $pass = delete $defaults{password};
    my @common_parts = qw{algorithm nonce opaque realm};	

    local $_;

    $user = 'sshaw' if !defined $user;
    $pass = users($user) || '' if !defined $pass;

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

    { Authorization => sprintf('Digest %s', join ', ', map { qq|$_="$res_header->{$_}"| } keys %$res_header) };      
}

1;
