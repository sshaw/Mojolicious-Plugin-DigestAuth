package Mojolicious::Plugin::DigestAuth::RequestHandler;

use strict;
use warnings;
use Carp 'croak';
use Scalar::Util 'weaken';

use Mojo::Util qw{b64_encode b64_decode unquote quote};
use Mojolicious::Plugin::DigestAuth::Util qw{checksum parse_header};

my $QOP_AUTH = 'auth';
my $QOP_AUTH_INT = 'auth-int';	
my %VALID_QOPS = ($QOP_AUTH => 1); #, $QOP_AUTH_INT => 1);

my $ALGORITHM_MD5 = 'MD5';
my $ALGORITHM_MD5_SESS = 'MD5-sess';
my %VALID_ALGORITHMS = ($ALGORITHM_MD5 => 1, $ALGORITHM_MD5_SESS => 1);

sub new
{
    my ($class, $config) = @_;
    my $header = {
	realm     => $config->{realm}	  || '',
	domain    => $config->{domain}    || '/',
	algorithm => $config->{algorithm} || $ALGORITHM_MD5,
	qop       => defined $config->{qop} ? $config->{qop} : $QOP_AUTH # "$QOP_AUTH,$QOP_AUTH_INT" # No qop = ''
    };

    $header->{opaque} = checksum($header->{domain}, $config->{secret});

    my $self  = {
	opaque         => $header->{opaque},
	secret         => $config->{secret},
	expires        => $config->{expires},
	password_db    => $config->{password_db},
	default_header => $header,
    };

    for my $qop (split /\s*,\s*/, $header->{qop}) {
	croak "unsupported qop: $qop" unless $VALID_QOPS{$qop};
	$self->{qops}->{$qop} = 1;
    }

    croak "unsupported algorithm: $header->{algorithm}" unless $VALID_ALGORITHMS{$header->{algorithm}};
    croak "algorithm $ALGORITHM_MD5_SESS requires a qop" if $header->{algorithm} eq $ALGORITHM_MD5_SESS and !$self->{qops};

    $self->{algorithm} = $header->{algorithm};

    bless $self, $class;
}

sub _request
{
    (shift)->_controller->req;
}

sub _response
{
    (shift)->_controller->res;
}

sub _controller
{
    (shift)->{controller};
}

sub _nonce_expired
{
    my ($self, $nonce) = @_;
    my $t;

    $t = ($self->_parse_nonce($nonce))[0];
    $t && (time() - int($t)) > $self->{expires};
}

sub _parse_nonce
{
    my ($self, $nonce) = @_;

    b64_decode $nonce;
    split ' ', $nonce, 2;
}

sub _valid_nonce
{
    my ($self, $nonce) = @_;
    my ($t, $sig) = $self->_parse_nonce($nonce);

    $t && $sig && $sig eq checksum($t, $self->{secret});
}

sub _create_nonce
{
    my $self  = shift;
    my $t     = time();
    my $nonce = sprintf '%s %s', $t, checksum($t, $self->{secret});

    b64_encode $nonce;
    chomp $nonce;

    $nonce;
}

sub authenticate
{
    my $self = shift;

    $self->{controller} = shift;
    weaken $self->{controller};

    $self->{response_header} = { %{$self->{default_header}} };

    my $auth = $self->_request->headers->authorization;
    if($auth) {
	my $header = parse_header($auth);
	if(!$self->_valid_header($header)) {
	    $self->_bad_request;
	    return;
	}

	# $header->{opaque} eq $self->{opaque} &&
	# $self->_nonce_valid($header->{nonce});
	if($self->_authorized($header)) {
	    return 1 unless $self->_nonce_expired($header->{nonce});
	    $self->{response_header}->{stale} = 'true';
	}
    }

    $self->_unauthorized;
}

sub _unauthorized
{
    my $self = shift;
    my $header = $self->_build_auth_header;

    $self->_response->headers->www_authenticate($header);
    $self->_response->code(401);
    $self->_controller->render(text => 'HTTP 401: Unauthorized');
}

sub _bad_request
{
    my $self = shift;
    $self->_response->code(400);
    $self->_controller->render(text => 'HTTP 400: Bad Request');
}

sub _valid_header
{
    my ($self, $header) = @_;
    
    # Uhhh seriously..?
    return unless
	$header &&
	$header->{realm} &&
	$header->{nonce} &&
	$header->{response} &&
	$header->{opaque} &&
	$header->{opaque} eq $self->{opaque} &&
	exists $header->{username} &&
	($header->{algorithm} && $self->{algorithm} eq $header->{algorithm}) &&
	($header->{qop} && $header->{nc} || !$header->{qop} && !defined $header->{nc}) &&
	($header->{uri} && $self->_fix_uri($header->{uri}) eq $self->_request->url) &&

	# Either there's no QOP from the client and we require one, or the client does not
	# send a qop because they dont support what we want (i.e. auth-int).       
	(defined $header->{qop} && $self->{qops}->{$header->{qop}} ||
	 !$header->{qop} && keys %{$self->{qops}} != 0);

    return 1;
}

# IE 5 & 6 (others?) do not append the query string to the URI sent in the Authentication header.
sub _fix_uri
{
    my ($self, $uri) = @_;
    my $params = $self->_request->query_params->to_string;

    if($uri && $self->_request->method eq 'GET' && $params && index($uri, '?') == -1) {
	$uri .= "?$params";
    }

    $uri;
}

sub _build_auth_header
{
    my $self   = shift;
    my $header = $self->{response_header};

    my %no_quote;
    @no_quote{qw{algorithm stale}} = ();

    if($header->{stale} || !$header->{nonce}) {
	$header->{nonce} = $self->_create_nonce;
    }

    local $_;
    sprintf 'Digest %s', join ', ', map {
	quote $header->{$_} unless exists $no_quote{$_};
	"$_=$header->{$_}";
    } grep $header->{$_}, keys %$header;
}


# rename to _authenticate
# and add some former 400 checks here
sub _authorized
{
    my ($self, $header) = @_;
    return unless $self->_valid_nonce($header->{nonce});

    my $a1 = $self->_compute_a1($header);
    return unless $a1;

    my @fields = ($a1, $header->{nonce});
    if($header->{qop}) {
	push @fields, $header->{nc},
		      $header->{cnonce},
		      $header->{qop},
		      $self->_compute_a2($header);
    }
    else {
	push @fields, $self->_compute_a2($header);
    }

    checksum(@fields) eq $header->{response};
}

sub _compute_a1
{
    my ($self, $header) = @_;
    my $hash = $self->{password_db}->get($header->{realm}, $header->{username});

    if($hash && $header->{algorithm} && $header->{algorithm} eq $ALGORITHM_MD5_SESS) {
	$hash = checksum($hash, $header->{nonce}, $header->{cnonce});
    }

    $hash;
}

sub _compute_a2
{
    my ($self, $header) = @_;
    my @fields = ($self->_request->method, $header->{uri});

# Not yet...
#     if(defined $header->{qop} && $header->{qop} eq $QOP_AUTH_INT) {
#         # TODO: has body been decoded?
# 	push @fields, checksum($self->_request->content->headers->to_string . "\015\012\015\012" . $self->_request->body);
#     }

    checksum(@fields);
}

1;
