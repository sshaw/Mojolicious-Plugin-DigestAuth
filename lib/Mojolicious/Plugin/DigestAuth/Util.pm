package Mojolicious::Plugin::DigestAuth::Util;

use strict;
use warnings;

use Mojo::Util qw{md5_sum};
use base 'Exporter';

our @EXPORT_OK = qw{checksum parse_header quote unquote b64_encode b64_decode};

sub checksum
{
  local $_;
  md5_sum join ':', grep(defined, @_);
}

sub parse_header
{
    my $header = shift;
    my $parsed;

    # TODO: I think there's a browser with a quoting issue that might affect this
    if($header && $header =~ s/^Digest\s//) {
        while($header =~ /([a-zA-Z]+)=(".*?"|[^,]+)/g){
	  $parsed->{$1} = unquote($2);
        }
    }

    $parsed;
}

#
# These 4 functions are used to maintain backwards compatibility with older versions
# of Mojolicious and will be removed in the next release.
#
sub quote
{
  my $str = shift;
  my $t = Mojo::Util::quote($str);
  $str = $t if $t;
  $str;
}

sub unquote
{
  my $str = shift;
  my $t = Mojo::Util::unquote($str);
  $str = $t if $t;
  $str;
}

sub b64_encode
{
  my $str = shift;
  my $t = Mojo::Util::b64_encode($str);
  $str = $t if $t;
  $str;
}

sub b64_decode
{
  my $str = shift;
  my $t = Mojo::Util::b64_decode($str);
  $str = $t if $t;
  $str;
}

1;
