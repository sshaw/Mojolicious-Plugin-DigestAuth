package Mojolicious::Plugin::DigestAuth;

use strict;
use warnings;

use Carp 'croak';
use Scalar::Util 'blessed';

use Mojo::Base 'Mojolicious::Plugin';
use Mojolicious::Plugin::DigestAuth::DB;
use Mojolicious::Plugin::DigestAuth::RequestHandler;

our $VERSION = '0.001_1';

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
	  # Normalize simple config, otherwise we assume a hash of: realm => { user => 'password' ... }
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

   use Mojolicious::Lite;

   plugin 'digest_auth';

   get '/admin/users' => sub {
       my $self = shift;
       return unless $self->digest_auth(realm => 'Thangz',
				        allow => '/some/file/htdigest_formated');

       # ...
   }

   # Setup with user-defined defaults
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
  
   # Setup authentication for a set of routes
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


=head1 CONFIGURATION

Options can be set globally when L<< loading the plugin|Mojolicious/plugin >>:

   plugin 'digest_auth', %options

Or locally when calling L<< C<digest_auth>|/digest_auth >> 

    $self->digest_auth(%options);

Local options override their global counterparts. 

Digest Authentication can be perfomed on a set of routes:

   sub startup
   {
     my $self = shift;
     $self->plugin('digest_auth');

     # ...

     my $admin = $self->digest_auth('/admin', %options);
     $admin->route('/edit/:id')->to('users#edit');
   }

Or from within an action:

   sub some_action
   {
       my $self = shift;
       return unless $self->digest_auth(realm => 'RealmX',
				        allow => { 
				          RealmX => { user => 'password' }
				       });
   }   

=head1 METHODS

=head2 digest_auth 

   # In your action
   $self->digest_auth(allow => { bob => 'password' });

   # Or, in startup()
   my $r = $self->digest_auth('/admin', allow => { bob => 'password' });
   $r->route('/new')->to('users#new');

=head3 Arguments

C<$url>

Optional. If provided authentication will be performed for all routes defined under C<$url>. 
This form can only be used to configure authentication in your app's 
L<< C<startup()>|Mojolicious/startup >> method.

C<%options>

=over4

=item * C<< realm => 'Your Realm' >>

Authentication realm. Defaults to C<< 'WWW' >>.

=item * C<< allow => { user => password } >>

=item * C<< allow => { realm => { user => password }} >>

=item * C<< allow => 'htdigest_file' >>

=item * C<< allow => $obj->can('get') >>

Realms, usernames, and passwords used for authentication. Can be a hash reference, an Apache 
htdigest like file, or an object that responds to C<get()>.

When using a hash reference passwords must be given in plain text. Users without a realm 
will be put in the realm specified by the C<realm> option. 
If no realm option was provided the default realm (C<'WWW'>) is used. 

When using an object arguments will be passed to C<get()> in the following order: 
C<realm, username>. The C<get()> must return the hashed version of the password. 

=item * C<< algorithm => 'MD5' | 'MD5-sess' >>

Digest algorithm, either C<MD5> or C<MD5-sess>. Defaults to C<MD5>. C<MD5-sess> requires a C<qop>. 

=item * C<< qop => 'auth' | '' >>

=item * C<< expires => seconds >>

Nonce lifetime. Defaults to C<300> seconds (5 minutes). 

=back

=head3 Returns

Without a URL prefix:

C<1> if authentication was successful, C<undef> otherwise. 

With a URL prefix:

An instance of L<Mojolicious::Routes>. Use this to define a set of actions that require authentication. 
In this case authentication is performed via a L<bridge|Mojolicious::Guides::Routing/Bridges> with a callback.

=head3 Errors

Will C<croak> if any of the options are invalid.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Plugin::BasicAuth>

=head1 AUTHOR

(C) 2011 Skye Shaw (sshaw AT lucas.cis.temple.edu)

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.
