#!/usr/bin/perl -w

use strict;

use Net::DNS;

my $resolver = Net::DNS::Resolver->new;
$resolver->nameservers('127.0.0.1');

open(DOMAIN, "bank.txt") ||
  die "Can't open zone file";
while (<DOMAIN>) {
    chomp;
    treat($_);
}
close(DOMAIN);

sub treat {
  my $domain = shift;
  my $query = $resolver->send("$domain",'MX');
  foreach my $rr ($query->answer) {
    if ($rr->type eq 'MX') {
      print $rr->string, "\n";
#	print "$domain\n";
    }
  }
}
