#!/usr/bin/perl
# mellifera - incident response scripts for snort+dionaea setup
# don't ask me why, i needed a name 
# You may consider this under GPL v2
# Any comments or queries to myself at jamie@honeynet.org

# it is assumed:
# you have root on your honeypot and no other non-trusted users
# you are going to be careful and not start nmapping random addresses on the Internet!
# (don't turn on active response if you are collecting hits from addresses you don't 
# own - this is for augmenting incident response in DMZs and internal networks)

# designed for Debian, but should work on others. 
# But dionaea is easier to install on Debian anyway
#
# Linux honeypot 2.6.32-5-686 #1 SMP Sun May 6 04:01:19 UTC 2012 i686 GNU/Linux
# you will need something like dionaea (compile yourself)
# apt-get install snort
# some sendmail-compatible thing that you have configured with the appropriate delivery
# options. i like exim4
#
# apt-get install nmap (for active response)
#
#and the following in your local snort rules:
#/etc/snort/rules/local.rules
#alert tcp any any -> any 445 (msg:"SMB connection to honeypot"; classtype:attempted-admin; sid:1234001; rev:1;)
#alert tcp any any -> any 42 (msg:"WINS connection to honeypot"; classtype:attempted-admin; sid:1234002; rev:1;)
#alert tcp any any -> any 135 (msg:"RPC connection to honeypot"; classtype:attempted-admin; sid:1234003; rev:1;)
#alert tcp any any -> any 1433 (msg:"MSSQL connection to honeypot"; classtype:attempted-admin; sid:1234004; rev:1;)
#alert tcp any any -> any 88 (msg:"KRB connection to honeypot"; classtype:attempted-admin; sid:1234005; rev:1;)
#alert tcp any any -> any 3389 (msg:"RDP connection to honeypot"; classtype:attempted-admin; sid:1234005; rev:1;)

#example /etc/mellifera.cfg
#to=jamie@honeynet.org
#from=jamie@honeynet.org
#use_active_response=0
#output_dir=/tmp/mellifera

use strict;

open CFH, "</etc/mellifera.cfg" or die $!;

my $line;
my $to="NOCONFIG";
my $from;
my $op="/tmp/mellifera";
my $use_active_response;
my $isodate=`date -I`;
my $errors_to="UNDEF";
chomp($isodate);

my $result=`mkdir -p $op`;

while ($line=<CFH>) {
    if ($line=~m/to=(.*)/) {
	$to=$1;
    }
    if ($line=~m/from=(.*)/) {
	$from=$1;
    }
    if ($line=~m/use_active_response=(.*)/) {
	$use_active_response=$1;
    }
    if ($line=~m/output_dir=(.*)/) {
	$op=$1;
    }
    if ($line=~m/errors_to=(.*)/) {
	$errors=$1;
    }
}

if ($errors_to eq "UNDEF") {
    $errors_to=$to;
}

#print STDERR "debug $to / $from / $use_active_response \n";

if ($to eq "NOCONFIG") {
    die "Something's wrong with reading the config file - I haven't got a 'To' address\n";
}

sub sendEmail
{
    my ($to, $from, $subject, $message) = @_;
    my $sendmail = '/usr/lib/sendmail';

    open(MAIL, "|$sendmail -oi -t");
    print MAIL "From: $from\n";
    print MAIL "To: $to\n";
    print MAIL "X-Priority: 1 (High)\n";
    print MAIL "Subject: $subject\n\n";
    print MAIL "$message\n";
    close(MAIL);
}

sub activeResponse
{
    my ($src, $dst) = @_;

    #print STDERR "$src attacked $dst\n";
    #make sure we only do this once per daily alert cycle

    my $nmapfn=$op."/nmap-$src-$isodate.nmap";
    my $nmapcmd="nmap -A $dst -oA $nmapfn";

    #print "$nmapcmd\n";
    if (! -f $nmapfn) {
	my $result=`nmap -A $dst -oA $nmapfn`;
	sendEmail($to, $from, "Scanned $dst as part of active response", `cat $nmapfn`);
    } else {
	print STDERR "already seen\n";
    }
}

# main

open SFH, "</var/log/snort/alert_fast" or die $!;

# read healthcheck file
open HEALTH, "<$op/health";

my $healthcheck="";
$healthcheck=<HEALTH>;
chomp($healthcheck);

close HEALTH;

# read alert file

open STATS, "<$op/stats";

my $holddown="";

$holddown=<STATS>;
chomp($holddown);

close STATS;

# process snort logs
my $line;

while ($line=<SFH>) {
    if ($line=~m/honeypot/) {

        if ($holddown ne "alerted") {

            # deal with emailing the admin if anything has gone amiss
            my $contents=`/usr/sbin/snort-stat -a -t 1 < /var/log/snort/alert_full`;  
            sendEmail($to, $from, "Honeypot hit", "$contents");

            open STATS, ">$op/stats";

            print STATS "alerted\n";

            close STATS;

            $holddown="alerted";
	}

	if ($use_active_response==1) {
	    
	    if ($line=~m/([\d\.]+):(\d+) .. ([\d\.]+):(\d+)/) {
		my $src=$1; my $dst=$3;
		activeResponse($src,$dst);
	    } else {
		die "BAD MATCH\n$line";
	    }
	}

    }

#example line
#    10/17-20:38:06.942595  [**] [1:100000160:2] COMMUNITY SIP TCP/IP message flooding directed to SIP proxy [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 207.97.227.239:443 -> 192.168.202.201:58138

    
}

#health checks
my $disk=0;
my $ports=0;

# is dionaea running
my $query=`ps aux | grep dionaea | grep -v grep`;

my $errors="";

if ($query!~m!/opt/dionaea/!mg) {
    $errors=$errors."Dionaea not running... trying to restart\n";
    $query=`/bin/rm -rf /opt/dionaea/var/run/dionaea.pid`;
    $query=`/usr/bin/killall dionaea`;
    $errors=$errors.`/etc/init.d/dionaea restart`;
}

# is snort running
$query=`ps aux | grep snort | grep -v grep`;

if ($query!~m!/usr/sbin/snort!mg) {
    $errors=$errors."Snort not running... trying to restart\n";

    $errors=$errors.`/etc/init.d/snort restart`;
}

# check disk space
$query=`df -m / | tail -1`;

if ($query=~m/([0-9]+)%/) {
    $disk = $1;

    if ($disk>90) {
        $errors=$errors."Disk space low - $disk percent full\n";
    }
}

# ports check - no good if you're listening on localhost
$query=`lsof -Pni  | grep dionaea | grep -v 127.0.0.1 | wc  -l`;

if ($query=~m/([0-9]+)/) {
    $ports=$1;
    if ($ports<2) {
        $errors=$errors."Not enough ports listening - check lsof -Pni\n";
    }
}

# deal with emailing the admin if anything has gone amiss
if ($errors ne "") {

    # send email
    sendEmail($errors_to, $from ,  "Honeypot error - restarting services", "$errors");

    open HEALTH, ">$op/health";

    print HEALTH "alerted\n";

    close HEALTH;
}

# finished

