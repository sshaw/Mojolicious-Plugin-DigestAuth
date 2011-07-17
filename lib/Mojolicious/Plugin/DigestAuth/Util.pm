package Mojolicious::Plugin::DigestAuth::Util;

use strict;
use warnings;

use Mojo::Util 'md5_sum';
use base 'Exporter';

our @EXPORT_OK = qw{checksum parse_header};

sub checksum { md5_sum join ':', @_; }

sub parse_header
{
    my $header = shift;
    my $parsed;

    if($header && $header =~ s/^Digest\s//) {
	while($header =~ /([a-zA-Z]+)=(".*?"|[^,]+)/g){
	    Mojo::Util::unquote $parsed->{$1} = $2;
	}
    }

    $parsed;
}


1;
