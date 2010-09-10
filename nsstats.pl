#!/usr/bin/perl

use strict;
use warnings;

my %stats;

# Count all domains per NS
while (<>) {
    /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)/;
    my $domain = $1;
    my $rrtype = $4;
    my $rdata = $5;
    if (defined $rdata and $rrtype eq 'NS') # must be type NS
    {
	$stats{$rdata}++; # key is the nameserver
    }
}

# Sort the number of domains per NS
my @sorted = sort { $stats{$b} <=> $stats{$a} } keys %stats;

my $i = 0;
foreach (@sorted)
{
    print ++$i.",".$_.",".$stats{$_}."\n";
}
