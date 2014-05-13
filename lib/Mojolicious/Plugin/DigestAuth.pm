package Mojolicious::Plugin::DigestAuth;

use strict;
use warnings;

use Carp 'croak';
use Scalar::Util 'blessed';

use Mojo::Base 'Mojolicious::Plugin';
use Mojolicious::Plugin::DigestAuth::DB;
use Mojolicious::Plugin::DigestAuth::RequestHandler;

our $VERSION = '0.07';

sub register
{
    my ($self, $app, $user_defaults) = @_;

    my %defaults = %$user_defaults;
    $defaults{realm}   ||= 'WWW';
    $defaults{secret}  ||= $app->can('secret') ? $app->secret : ($app->secrets||[])->[0]; # >= 4.91 has no secret()
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

=pod

=head1 NAME

Mojolicious::Plugin::DigestAuth - HTTP Digest Authentication for Mojolicious

=head1 SYNOPSIS

   $self->plugin('digest_auth');

   # In your action
   return unless $self->digest_auth(allow => { sshaw => 'password' });

   # Or, in startup()
   my $r = $self->digest_auth('/admin', allow => { sshaw => 'password' });
   $r->route('/new')->to('users#new');

=head1 CONFIGURATION

=head2 SETUP

Configuration can be done globally when loading the plugin

    $self->plugin('digest_auth', %options)

or locally when calling L<< C<digest_auth>|/digest_auth >>

    $self->digest_auth(%options);

Local options override their global counterparts. For example, the following
will apply to all authentication requests

   # setup()
   $self->plugin('digest_auth', realm   => 'Thangz',
                                expires => 120,
                                allow   => '/path/to/htdigest_file');


   # controller
   sub show
   {
       my $self = shift;
       return unless $self->digest_auth;

       # ...
   }

But can be overridden within an action

   sub edit
   {
       my $self = shift;
       return unless $self->digest_auth(realm   => 'RealmX',
                                        expires => 24*3600,
                                        allow   => { sshaw => 'Ay3Br4h_!' });
       # ...
   }

For a full list of options see L</digest_auth>.

=head2 AUTHENTICATION

By default MD5/auth authentication is performed. This is configurable, see L</digest_auth>.

=head3 DB

Authentication information is given via the C<allow> option and can be retrieved
from a variety of sources:

=over 4

=item * A hash reference without a realm

    $self->plugin('digest_auth', allow => { sshaw => 'my_pAzw3rD',
                                            admin => '->fofinha!' });

In this case users will either be placed into the realm given by the C<realm> option or
the default realm, C<WWW>.

Passwords must be given in plain text.

=item * A hash reference with realm(s)

    $self->plugin('digest_auth', allow => { 'Admin Realm' => { sshaw => 'my_pAzw3rD' },
                                            'WWW Users'   => { tony  => 'vrooooooom' });

Passwords must be given in plain text.

=item * A htdigest style file

    $self->plugin('digest_auth', allow => '/home/sshaw/www_users');

=item * An object with a C<get()> method that returns B<hashed> passwords

    $self->plugin('digest_auth', allow => $db);

Arguments are passed to C<get()> in the following order: C<realm, username>.

=back

=head3 PERFORMING AUTHENTICATION

Authentication can be performed by calling the C<digest_auth> method
from within the action you'd like to protect:

   sub some_action
   {
       my $self = shift;
       return unless $self->digest_auth;

       # Authenticated users get here
   }

If authentication is successful C<digest_auth> returns true, otherwise C<undef> is returned
and a HTTP 401 status code and the message: C<HTTP 401: Unauthorized> are sent
to the client. Currently this message cannot be changed.

Authentication can also be performed for a set of routes by calling
C<digest_auth> from within your application's startup function. This form performs authentication automatically
for all of the routes defined under the given URL:

   package YourWebApp;

   use Mojo::Base 'Mojolicious';

   sub startup
   {
     my $self = shift;
     $self->plugin('digest_auth', %options);

     # ...

     my $admin = $self->digest_auth('/admin');
     $admin->route('/new')->to('users#new');
     $admin->route('/edit/:id')->to('users#edit');
   }

In this case authentication is performed via a L<bridge|Mojolicious::Guides::Routing/Bridges> with a callback.

=head3 WEB SERVERS

Authentication will fail if your application is sitting behind a web server does not pass the Authorization header
to your application. In Apache this can be achieved with C<mod_rewrite>:

   RewriteEngine On
   RewriteRule ^ - [E=X-HTTP_AUTHORIZATION:%{HTTP:Authorization}]

=head1 METHODS

=head2 plugin

     $self->plugin('digest_auth', %options)

Loads the plugin and sets up the defaults given by C<%options>.

=head3 Arguments

C<%options>

See L</digest_auth>.

=head3 Errors

This method will C<croak> if if any of the options are invalid or if there is an error loading the password database.

=head2 digest_auth

     $self->digest_auth(%options)
     $routes = $self->digest_auth($url, %options)

=head3 Arguments

C<$url>

Optional. If provided authentication will be performed for all routes defined under C<$url>.
See L</PERFORMING AUTHENTICATION>.

C<%options>

=over 4

=item * C<< allow => { user => password } >>

=item * C<< allow => { realm => { user => password }} >>

=item * C<< allow => 'htdigest_file' >>

=item * C<< allow => $obj >>

See L</DB>.

=item * C<< algorithm => 'MD5' | 'MD5-sess' >>

Digest algorithm, either C<'MD5'> or C<'MD5-sess'>. Defaults to C<'MD5'>, C<'MD5-sess'> requires a C<qop>.

=item * C<< domain => '/path' | 'your.domain.com' >>

Authentication domain. Defaults to C<'/'>.

=item * C<< expires => seconds >>

Nonce lifetime. Defaults to C<300> seconds (5 minutes).

=item * C<< qop => 'auth' | '' >>

Quality of protection. Defaults to C<'auth'>.  C<auth-int> is not supported.

=item * C<< realm => 'Your Realm' >>

Authentication realm. Defaults to C<'WWW'>.

=item * C<< support_broken_browsers => 1 | 0 >>

When processing requests from certain browsers skip steps that would otherwise result in a HTTP 400 response. Defaults to C<1>.

Currently only applies to IE 5 and 6. These two browsers fail to append the query string to the URI included in the
Authorization header and, after authenticating, fail to include the opaque value.

=back

=head3 Returns

Without a URL prefix:

True if authentication was successful, C<undef> otherwise. If unsuccessful a HTTP 401 status code and message are sent to the client.

With a URL prefix:

An instance of L<Mojolicious::Routes>. See L</PERFORMING AUTHENTICATION>.

=head3 Errors

Will C<croak> if any of the options are invalid.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Plugin::BasicAuth>, http://en.wikipedia.org/wiki/Digest_access_authentication

=head1 AUTHOR

Skye Shaw (sshaw AT lucas.cis.temple.edu)

=head1 LICENSE

Copyright (c) 2011 Skye Shaw.
This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.
