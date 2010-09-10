#!/usr/bin/perl

my ($dom, $ttl, $type, $rr, $host);
my %gianthash;


while (<>)
{
    next if /^\s*$/;     # jump empty lines
    next if /^\;/;       # jump all-comment lines
    s/^(.*)\s*\;.*$/$1/; # remove comments
    next unless $_ =~ /NS/;
    next if $_ =~ /RRSIG/;
    next if $_ =~ /DNSKEY/;
    ($dom, $ttl, $type, $rr, $host) = split /\s+/;
    $host = lc $host;
    next if $host eq '' or $dom eq '';
    $gianthash{$host}->{count}++;
    $host =~ s/(\w+\.\w+\.)$/$1/;
    $hosthash{$1}->{count}++ unless $1 eq '';
    print $_ if $1 eq '';
}


open(HOSTS, '>se.ns1') or die "can't write se.ns1";
foreach (keys %gianthash)
{
#    print HOSTS "$_\n";
    print HOSTS sprintf "%d %s\n", $gianthash{$_}->{count}, $_;
}
close HOSTS or die "can't close se.ns1";


open(HOSTS, '>se.ns2') or die "can't write se.ns2";
foreach (keys %hosthash)
{
#    print HOSTS "$_\n";
    print HOSTS sprintf "%d %s\n", $hosthash{$_}->{count}, $_;
}
close HOSTS or die "can't close se.ns2";
