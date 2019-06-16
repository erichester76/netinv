#!/usr/bin/perl

# NetInv
#
# Network Discovery using arp, upnp, mdns, netbios, dropbox, wsdd
# 
# Requires 
# nmap
# arping
# curl
#
# 2019-06-12 - First Version - Eric Hester
#
#

#print progress
$debug = 1;
#arping entire subnet enable
$arping = 0;
#upnp multicast lookup enable
$upnp = 1;
#mdns multicast lookup enable
$mdns = 1;
#netbios lookup enable
$netbios = 1;
#dropbox lookup enable
$dropbox = 1;
#wsdd lookup enable
$wsdd = 1;
#macvendors.com mac address lookup enable
$maclookup = 1;
#router dns reverse dns lookup enable
$routerptr = 1;

## get network info by sending a DHCP DISCOVER and parse the OFFER
#
#| broadcast-dhcp-discover:
#|   IP Offered: 192.168.1.185
#|   DHCP Message Type: DHCPOFFER
#|   Server Identifier: 192.168.1.1
#|   IP Address Lease Time: 0 days, 0:02:00
#|   Renewal Time Value: 0 days, 0:01:00
#|   Rebinding Time Value: 0 days, 0:01:45
#|   Subnet Mask: 255.255.255.0
#|   Broadcast Address: 192.168.1.255
#|   NetBIOS Name Server: 192.168.1.1
#|   Domain Name: local
#|   Domain Name Server: 8.8.8.8, 192.168.1.1
#|_  Router: 192.168.1.1

print "Getting DHCP Info..." if $debug;
open(NMAP,"nmap --script=broadcast-dhcp-discover 2>/dev/null|");

while (chomp(my $line = <NMAP>)){
  if ($line =~ /\|\_*\ +Server Identifier\: (.+)$/){
    $devices{$1}{'is_dhcp_server'}=1;
  }
  if ($line =~ /\|\_*\ +Router\: (.+)$/){
    $devices{$1}{'is_gateway'}=1;
    our $router = $1;
  }
  if ($line =~ /\|\_*\ +IP Offered\: (.+)$/){
    our $my_ip = $1;
  }
  if ($line =~ /\|\_*\ +Subnet Mask\: (.+)$/){
    our $netmask = $1;
    # convert IP addresses to unsigned long integers
    my @addrb=split("[.]",$my_ip);
    my ( $addrval ) = unpack( "N", pack( "C4",@addrb ) );
    my @maskb=split("[.]",$netmask);
    my ( $maskval ) = unpack( "N", pack( "C4",@maskb ) );

    # calculate network address
    my $netwval = ( $addrval & $maskval );

    # convert network address to IP address
    my @netwb=unpack( "C4", pack( "N",$netwval ) );
    our $network=join(".",@netwb);

  }
  if ($line =~ /\|\_*\ +Broadcast Address\: (.+)$/){
    our $broadcast = $1;
  }
  if ($line =~ /\|\_*\ +Domain Name\: (.+)$/){
    our $domain_name = $1;
  }
  if ($line =~ /\|\_*\ +Domain Name Server\: (.+)$/){
    our $dns_servers = $1;
  }

}

close(NMAP);

print "Done\n" if $debug;

## ARP discovery
#
# arp the whole subnet
if ($arping){
  my ($one,$two,$three,$start)=split(/\./,$network);
  my ($junk,$junk,$junk,$end)=split(/\./,$broadcast);
  $start++;
  $end--;

  for ($i=$start;$i<=$end;$i++){
    print "Arping whole subnet... $one.$two.$three.$i\r" if $debug;
    $arping = `arping -q -f -c 1 -w 1 $one.$two.$three.$i`;
  }

print "Arping whole subnet...Done\n" if $debug;
}

if (mdns){
  print "mDNS PTR lookup for arp table... " if $debug;
  open(ARP,"arp -en | awk '{ print \$1, \$3 }' |");

  while (chomp(my $line = <ARP>)){
    if ($line =~ /^(\d+\.\d+\.\d+\.\d+) (.+)$/){
      my $ip = $1;
      my $ether = $2;
      $devices{$ip}{'ether'}=$ether;
      chomp(my $hostname = `dig \@224.0.0.251 -p 5353 +short +time=1 +tries=1 -x $ip`);
      if ($hostname =~ /timed out/ and $routerptr){
        chomp($hostname = `dig \@$router +short +time=1 +tries=1 -x $ip`);
      }
      $hostname =~ s/.local.//g;
      if ($hostname !~ /timed out/) {
        $devices{$ip}{'hostname'}=$hostname;
      }
    }
  }

  close(ARP);
  print "Done\n" if $debug;
}

## uPnP discovery
#| broadcast-upnp-info:
#|   192.168.1.5
#|       Server: Samsung-Linux/4.1, UPnP/1.0, Samsung_UPnP_SDK/1.0
#|       Location: http://192.168.1.5:9110/ip_control
#|         Webserver: SHP, UPnP/1.0, Samsung UPnP SDK/1.0
#|         Name: [TV] Samsung Frame Series (55)
#|         Manufacturer: Samsung Electronics
#|         Model Descr: Samsung TV IPControl
#|         Model Name: UN55LS03N
#|         Model Version: AllShare1.0
if (upnp){
  print "Getting upnp info..." if $debug;

  open(NMAP,"nmap --script=broadcast-upnp-info 2>/dev/null|");

  while (chomp(my $line = <NMAP>)){
    if ($line =~ /\|\_*\ +(\d+\.\d+\.\d+\.\d+)/){
      $devices{$1}{'upnp'}=1;
      $current_device=$1;
    }
    if ($line =~ /\|\_*\ +Name\: (.+)$/){
      if (!$devices{$current_device}{'name'}){
        $devices{$current_device}{'name'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +Manufacturer\: (.+)$/){
      if (!$devices{$current_device}{'manufacturer'}){
        $devices{$current_device}{'manufacturer'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +Model Name\: (.+)$/){
      if (!$devices{$current_device}{'model'}){
        $devices{$current_device}{'model'}=$1;
      }
    }
  }
  close(NMAP);
  print "Done\n" if $debug;

}

## mDNS discovery
#|   192.168.1.230
#|     9/tcp workstation
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     445/tcp smb
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     548/tcp afpovertcp
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     3986/tcp qmobile
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     8080/tcp qdiscover
#|       accessType=http,accessPort=8080,model=TS-X53D,displayModel=HS-453DX,fwVer=4.4.1,fwBuildNum=20190528,serialNum=Q191I12804
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     8080/tcp http
#|       path=/
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|     Device Information
#|       model=Xserve
#|       Address=192.168.1.230 fe80:0:0:0:265e:beff:fe38:70ce
#|   192.168.1.125
#|     80/tcp uscan
#|       txtvers=1
#|       ty=Canon MG3600 series
#|       pdl=image/jpeg,application/pdf
#|       note=
#|       adminurl=http://A27BC1000000.local./index.html?page=PAGE_AAP
#|       UUID=00000000-0000-1000-8000-F4A997A27BC1
#|       vers=2.5
#|       representation=http://A27BC1000000.local./icon/printer_icon.png
#|       rs=eSCL
if (mdns){
  print "Getting mdns info..." if $debug;

  open(NMAP,"nmap --script=broadcast-dns-service-discovery 2>/dev/null|");

  while (chomp(my $line = <NMAP>)){
    if ($line =~ /\|\_*\ +(\d+\.\d+\.\d+\.\d+)/){
      $devices{$1}{'mdns'}=1;
      $current_device=$1;
    }
    if ($line =~ /\|\_*\ +model\=(.+)$/){
      if (!$devices{$current_device}{'model'}){
        $devices{$current_device}{'model'}=$1;
        if ($1 =~ /macbook/i or /macmini/i or /macpro/i or /imac/i){
          $devices{$current_device}{'manufacturer'}='Apple, Inc.';
          $devices{$current_device}{'os'}='OSX';
        }
        if ($1 =~ /ipad/i or /iphone/i){
          $devices{$current_device}{'manufacturer'}='Apple, Inc.';
          $devices{$current_device}{'os'}='IOS';
        }
        if ($1 =~ /applewatch/i){
          $devices{$current_device}{'manufacturer'}='Apple, Inc.';
          $devices{$current_device}{'os'}='watchOS';
        }
      }
    }
    if ($line =~ /\|\_*\ +ty\=(.+)$/){
      if (!$devices{$current_device}{'model'}){
        $devices{$current_device}{'model'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +serialNumber\=(.+)$/){
      if (!$devices{$current_device}{'serial_number'}){
        $devices{$current_device}{'serial_number'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +type\=printer$/i){
      if (!$devices{$current_device}{'is_printer'}){
        $devices{$current_device}{'is_printer'}=1;
      }
    }
    if ($line =~ /\|\_*\ +445\/tcp smb$/i){
      if (!$devices{$current_device}{'is_fileserver'}){
        $devices{$current_device}{'is_filserver'}=1;
      }
    }
  }
  close(NMAP);
  print "Done\n" if $debug;
}

## get list of dropbox clients 
#if ($dropbox){
#  open(NMAP,"nmap --script=broadcast-dropbox-listener 2>/dev/null|");;
#  close(NMAP);
#}

## get list of clients advertising via wsdd
#if (wsdd){
#  open(NMAP,"nmap --script=broadcast-wsdd 2>/dev/null|");x;
#  close(NMAP)
#}

print "\n\n" if $debug;
foreach my $device (keys %devices){
  if (!$devices{$device}{'manufacturer'} and $maclookup){
    my $response=`curl -s http://api.macvendors.com/$devices{$device}{'ether'}`;
    if ($response ne ''){
      $devices{$device}{'manufacturer'}=$response;
      sleep 2;
    }
  }
  foreach my $attrib (keys %{$devices{$device}}){
    print "$device : $attrib = $devices{$device}{$attrib}\n" if $debug;
  }
  print "---\n" if $debug;
  $total++;
}

print "$total total devices found\n" if $debug;
