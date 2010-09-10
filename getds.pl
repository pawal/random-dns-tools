#!/usr/bin/perl

use warnings;
use strict;

use Getopt::Long;
use Net::DNS;
use Net::DNS::SEC;

use Data::Dumper;

my $DEBUG = 0; # set to true if you want some debug output

my $maxlines = 50000; # max number of lines to read for example...
my $i = 0;   # line counter

my $par = 0; # think of the parenthesis
my $rr = ""; # global rr var

# calculate the average value of numbers in an array
sub average {
    @_ == 1 or die ('Sub usage: $average = average(\@array);');
    my ($array_ref) = @_;
    my $sum;
    my $count = scalar @$array_ref;
    foreach (@$array_ref) { $sum += $_; }
    return $sum / $count;
}

# calculate the median value of numbers in an array
sub median {
    @_ == 1 or die ('Sub usage: $median = median(\@array);');
    my ($array_ref) = @_;
    my $count = scalar @$array_ref;
    # Sort a COPY of the array, leaving the original untouched
    my @array = sort { $a <=> $b } @$array_ref;
    if ($count % 2) {
	return $array[int($count/2)];
    } else
    {
	return ($array[$count/2] + $array[$count/2 - 1]) / 2;
    }
}

# read and parse the zonefile, building a hash with the data we want
sub readZone
{
    my $zoneFile = 'se.bak'; # TODO: make arg later
    my %dnsData;

    print " -=> Reading and parsing <=-\n" if $DEBUG;

    open(ZONE, "<$zoneFile") or die "can't read se.bak";
    while (<ZONE>)
    {
        #last if $i++ > $maxlines;

	# remove comments and empty lines
	next if /^\s*$/;     # jump empty lines
	next if /^\;/;       # jump all-comment lines
	s/^(.*)\s*\;.*$/$1/; # remove comments
	my $line = $_;

	# parentheses states to get whole RR
	$rr = $line if not $par;
	$rr.= $line if $par;
	$par = 1 if $line =~ /\($/;
	$par = 0 if $line =~ /\)\s?$/;

	# we have got a full RR, lets parse and store
	if (not $par)
	{
	    if ($rr =~ /IN\s+DS/)
	    {
		my $dnsrr = Net::DNS::RR->new($rr);
		if ($dnsrr->type eq 'DS')
		{
		    print $dnsrr->name.":".$dnsrr->digest."\n" if $DEBUG;
		    $dnsData{$dnsrr->name}->{'DS'}->{$dnsrr->digest} = $dnsrr;
		}
	    }
	    elsif ($rr =~ /IN\s+DNSKEY/)
	    {
		my $i = 0;
		my $dnsrr = Net::DNS::RR->new($rr);
		if ($dnsrr->type eq 'DNSKEY')
		{
		    print $dnsrr->name.":".$dnsrr->keytag."\n" if $DEBUG;
		    $dnsData{$dnsrr->name}->{'DNSKEY'}->{$i++} = $dnsrr;
		}
	    }
	}
    }
    close ZONE;
    return \%dnsData;
}

# lets fetch all keys and params from the child zones
sub fetchKeys
{
    my $dnsData = shift;

    print " -=> Fetching stuff from DNS <=-\n" if $DEBUG;

    # setup resolver
    my $res = Net::DNS::Resolver->new;
    $res->nameservers('127.0.0.1');
    $res->recurse(1);
    $res->dnssec(1);
    $res->cdflag(0);
    $res->udppacketsize(4096);

    foreach my $domain (keys %$dnsData)
    {
	next if not exists $dnsData->{$domain}->{'DS'};

	# DNSKEY query
	print "Quering DNSKEY for $domain\n" if $DEBUG;
	my $answer = $res->query($domain,'DNSKEY');
	if (defined $answer) {
	    my $i = 0; # temp counter
	    foreach my $data ($answer->answer)
	    {
		if ($data->type eq 'DNSKEY') {
		    $dnsData->{$domain}->{'DNSKEY'}->{$i}->{'RR'} = $data;
		    print "DNSKEY $domain: ".$data->keytag."\n" if $DEBUG;
		}
		if ($data->type eq 'RRSIG') {
		    $dnsData->{$domain}->{'RRSIG'}->{$i}->{'RR'} = $data;
		    print "RRSIG $domain: ".$data->keytag."\n" if $DEBUG;
		}
		$i++;
	    }
	}

	# NSEC3PARAM query
	print "Quering NSEC3PARAM for $domain\n" if $DEBUG;
	$answer = $res->query($domain,'NSEC3PARAM');
	if (defined $answer) {
	    foreach my $data ($answer->answer)
	    {
		if ($data->type eq 'NSEC3PARAM') {
		    print "NSEC3PARAM: ".$data->string."\n";
		    $dnsData->{$domain}->{'NSEC3PARAM'} = $data;
		}
	    }
	}
    }
}

# verify all DS records with the keys we have
sub validateDS
{
    my $dnsData = shift;

    # iterate over the DS and verify all of them with the keys
    # using Net::DNS::RR::DS->verify(key)

    foreach my $domain (keys %$dnsData) {
	my $valid = 0; # indicator for a valid delegation yet
	foreach my $data (keys %{$dnsData->{$domain}->{'DS'}}) {
	    #print "DSDATA: $data\n";
	}
    }
}

sub printStatistics
{
    my $dnsData = shift;

    my $totalDomains    = 0;
    my $totalDS         = 0;
    my $totalDSDigType  = {};
    my $totalDNSKEY     = 0;
    my $totalRRSIG      = 0;
    my $totalKeyAlgo    = {};
    print " -=> Making statistics <=-\n" if $DEBUG;
    foreach my $domain (keys %$dnsData) {
	next if not exists $dnsData->{$domain}->{'DS'};
	$totalDomains++; # now we count domains that just have DS

	# totalDS counter
	$totalDS += scalar keys %{$dnsData->{$domain}->{'DS'}};
	# DS digest type analysis
	foreach my $data (keys %{$dnsData->{$domain}->{'DS'}})
	{
	    foreach my $ds ($dnsData->{$domain}->{'DS'}->{$data})
	    {
		# print "DIGTYPE: ".$ds->digtype."\n";
		$totalDSDigType->{$ds->digtype}++;
	    }
	}

	# total DNSKEY counter
	if (exists $dnsData->{$domain}->{'DNSKEY'} and $domain ne 'se') {  ## TODO
	    $totalDNSKEY += scalar keys %{$dnsData->{$domain}->{'DNSKEY'}};
	    foreach my $data (keys %{$dnsData->{$domain}->{'DNSKEY'}})
	    {
		foreach my $key ($dnsData->{$domain}->{'DNSKEY'}->{$data})
		{
		    print "DOMAIN: $domain\n";
		    print "KEY: $data\n";
		    $totalKeyAlgo->{$key->{'RR'}->algorithm('mnemonic')}++;
		    print "Algo: ".$key->{'RR'}->algorithm('mnemonic')."\n";
		    # TODO: total DNSKEY with SEP
		    # TODO: total DNSKEY without SEP
		}
	    }
	}
	# TODO: NSEC3PARAM
	# hash-algo
	# salt-längd
	# iterations

	# total RRSIG counter
	if (exists $dnsData->{$domain}->{'RRSIG'}) {
	    $totalRRSIG += scalar keys %{$dnsData->{$domain}->{'RRSIG'}};
	}

	# total bogus test
	if (scalar keys %{$dnsData->{$domain}->{'RRSIG'}} >
	    scalar keys %{$dnsData->{$domain}->{'DNSKEY'}})
	{
	    print "FOO: $domain\n";
	}

    }
    map { printf("Total DS Digest type %s: %i\n",
		  $_,$totalDSDigType->{$_}); } keys %{$totalDSDigType};
    map { printf("Total DNSKEY Algorithm %s: %i\n",
		  $_,$totalKeyAlgo->{$_}); } keys %{$totalKeyAlgo};
    print "Total domains with DS: $totalDomains\n";
    print "Total DS: $totalDS\n";
    print "Total DNSKEY: $totalDNSKEY\n";
    print "Total RRSIG: $totalRRSIG\n";

}

sub main() {
    my $help = 0;
    GetOptions('help|?' => \$help,
	       'debug' => \$DEBUG,);
    pod2usage(1) if($help);

    my $dnsData = readZone;
    fetchKeys($dnsData);
    validateDS($dnsData);
    printStatistics($dnsData);
}

main;


#
# We want this:
#  Number of DS per domain
#  Number of working DNSSEC domains
#  Number of "wrong DS used" / DS<->DNSKEY mismatch
#  Number of stale RRSIGs
#  The number of DS published per zone
#  - The number of DNSKEYs per zone
#  Popular algorithms
#  - NSEC / NSEC3
#
# TODO: signature lifetimes!

