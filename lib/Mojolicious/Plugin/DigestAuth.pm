package Mojolicious::Plugin::DigestAuth;

use strict;
use warnings;

use Carp 'croak';
use Scalar::Util 'blessed';

use Mojo::Base 'Mojolicious::Plugin';
use Mojolicious::Plugin::DigestAuth::DB;
use Mojolicious::Plugin::DigestAuth::RequestHandler;

our $VERSION = '0.001';

sub register
{
    my ($self, $app, $user_defaults) = @_;

    my %defaults = %$user_defaults;
    $defaults{realm}   ||= 'WWW';
    $defaults{secret}  ||= $app->secret;
    $defaults{expires} ||= 300;

    $app->helper(digest_auth => sub {
	my $c = shift;
	
	my $route;
	$route = shift if @_ % 2;
	
	my $options = { %defaults, @_ };
	croak 'you must setup an authentication source via the "allow" option' if !defined $options->{allow};
	
	my $allow = delete $options->{allow};
	if(blessed($allow) && $allow->can('get')) {
	  $options->{password_db} = $allow;
	}
	elsif(ref($allow) eq 'HASH') {
	  # Normalize simple config, otherwise we assume nested hash of realm => { user => 'password' }
	  # Allow undef or blank password...?
	  if(ref((values %$allow)[0]) ne 'HASH') {
	    $allow = { $options->{realm} => { %$allow } };
	  }
	  
	  $options->{password_db} = Mojolicious::Plugin::DigestAuth::DB::Hash->new($allow);
	}
	else {
	  # Assume it's a file
	  $options->{password_db} = Mojolicious::Plugin::DigestAuth::DB::File->new($allow);
	}

	my $handler = Mojolicious::Plugin::DigestAuth::RequestHandler->new($options);
	if($route) {
	    return $c->app->routes->bridge($route)->to(cb => sub {
		$handler->authenticate(shift);
	    });
	}

	$handler->authenticate($c);
    });
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::DigestAuth - HTTP Digest Authentication for Mojolicious

=head1 SYNOPSIS

   plugin 'digest_auth';

   get '/admin/users' => sub {
       my $self = shift;
       return unless $self->digest_auth(realm => 'Thangz',
				        allow => '/some/file/htdigest_formated');

       # ...
   }

   # Setup (and override) a lot of defaults
   plugin 'digest_auth',
	   realm => 'My Realm',
	   expires => 120,
	   algorithm => 'MD5-sess',
	   allow => { 	
	     # Will use 'My Realm'
	     sshaw => 'Ay3Br4h_!',
	     bob   => 'lovemywife'
	   };

   get '/account/edit' => sub { 
       my $self = shift;
       return unless $self->digest_auth;

       # ...
   }

   # Override some of the defaults here
   get '/' => sub { 
       my $self = shift;
       return unless $self->digest_auth(realm => 'RealmX',
				        qop   => 'auth',
				        algorithm => 'MD5,
				        allow => { 
				          RealmX => { user => 'password' }
				       });

       # ...
   }
  
   # Setup authorization for a set of of routes
   package YourApp;
   use Mojo::Base 'Mojolicious';
    
   sub startup
   {
     my $self = shift;
     $self->plugin('digest_auth');

     # ...

     my $admin = $self->digest_auth('/admin',
			     	    realm => 'Admin',
			     	    allow => '/www/auth/admin');
     
     $admin->route('/:id')->to('users#show');
     $admin->route('/edit/:id')->to('users#edit')
   }


=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Plugin::BasicAuth>

=head1 AUTHOR

(C) 2011 Skye Shaw (sshaw AT lucas.cis.temple.edu)

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.
