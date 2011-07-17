package Mojolicious::Plugin::DigestAuth::DB;

use strict;
use warnings;

use Carp ();

sub get
{
    Carp::croak 'usage: ', __PACKAGE__, '->get(REALM, USER)' unless @_ == 3; 
    my($self, $realm, $user) = @_;    
    return unless defined $realm and defined $user;
    $self->{users}->{$realm}->{$user};
}

package Mojolicious::Plugin::DigestAuth::DB::File;

use base 'Mojolicious::Plugin::DigestAuth::DB';

sub new
{
    my ($class, $file) = @_;
    Carp::croak 'usage: ', __PACKAGE__, '->new(FILE)' unless $file;
   
    local $_;
    my $users = {};

    open my $passwords, '<', $file or Carp::croak "error opening digest file '$file': $!";

    while(<$passwords>) {
	# "\r\n" used w/ Apache digest files on Win?
	chomp;
	next unless $_;
	
	# user:realm:hashed_password
	my @user = split /:/, $_, 3;
	if(@user != 3 || grep { !defined or !length } @user) {
	    Carp::croak "password file '$file' contains an invalid entry: $_";
	}
	
	$users->{$user[1]}->{$user[0]} = $user[2];	    
    }

    bless { users => $users }, $class;
}

package Mojolicious::Plugin::DigestAuth::DB::Hash;

use base 'Mojolicious::Plugin::DigestAuth::DB';
use Mojolicious::Plugin::DigestAuth::Util 'checksum';

sub new
{
    my ($class, $config) = @_;
    Carp::croak 'usage: ', __PACKAGE__, '->new(HASH)' unless $config and ref $config eq 'HASH';

    my $users;
    for my $realm (keys %$config) {
	Carp::croak "config for realm '$realm' is invalid: values must be a HASH" unless ref $config->{$realm} eq 'HASH';
	while(my ($user, $password) = each %{$config->{$realm}}) {
	    #allow blank passowrdz?
	    $users->{$realm}->{$user} = checksum($user, $realm, $password);
	}
    }

    bless { users => $users }, $class;
}

1;
