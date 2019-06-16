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
# todo:
# netbios-ns
# snmp
# dropbox
# wsdd
# dump to sqlite

#
#key for macvendors.com API
$macvendors_api_key="eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtYWN2ZW5kb3JzIiwiZXhwIjoxODc1MjAyMDAyLCJpYXQiOjE1NjA3MDYwMDIsImlzcyI6Im1hY3ZlbmRvcnMiLCJqdGkiOiJmOTYwNjk1ZS05YjBjLTQ5OTgtYmQ2Ni1mYmVlMGIyYjM4YmIiLCJuYmYiOjE1NjA3MDYwMDEsInN1YiI6IjE1NjgiLCJ0eXAiOiJhY2Nlc3MifQ.gaJmI0_CVqa8Y20nbmQLGZZUSAvnWAyo9oASGNR9ngDvzCzbU-BOxJkGzAOfOm2AUoHN8y_N4KXsdw13TZab1w";

#local of critical binaries 
$bin_arping="/usr/local/sbin/arping";
$bin_nmap="/usr/local/bin/nmap";
$bin_curl="/usr/bin/curl";

#set interface to wired interface you wish to scan
#linux default
#$interface = eth0
#osx usb ethernet
$interface = en7;
#
#print progress
$debug = 1;
#
#arping entire subnet enable
$arping = 1;
#
#upnp multicast lookup enable
$upnp = 1;
#
#mdns multicast lookup enable
$mdns = 1;
#
#netbios lookup enable
$netbios = 1;
#
#dropbox lookup enable
$dropbox = 1;
#
#wsdd lookup enable
$wsdd = 1;
#
#macvendors.com mac address lookup enable
$maclookup = 1;
#
#router reverse dns lookup enable
$routerptr = 1;
#
#dns reverse dns lookup enable
$dnsptr = 1;

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
open(NMAP,"$bin_nmap --script=broadcast-dhcp-discover -e $interface 2>/dev/null|");

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

    # calculate network and broadcast address
    my $netwval = ( $addrval & $maskval );
    my $broadval = ( $addrval | ~$maskval );

    # convert network address to IP address
    my @netwb=unpack( "C4", pack( "N",$netwval ) );
    our $network=join(".",@netwb);
    # convert broadcast address to IP address
    my @broadb=unpack( "C4", pack( "N",$broadval ) );
    our $broadcast=join(".",@broadb);

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
print "Network = $network / $netmask / $broadcast\n" if $debug;
print "Domain Name = $domain_name\n" if $debug;
print "DNS = $dns_servers\n" if $debug;


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
    $arping = `$bin_arping -I $interface -q -c 1 -w 1 $one.$two.$three.$i`;
  }

print "Arping whole subnet...Done              \n" if $debug;
}

#mDNS and DNS PTR  name discovery
if (mdns){
  print "mDNS PTR lookup for arp table... " if $debug;
  open(ARP,"arp -an | awk '{ print \$2,\$4}' | sed 's/[\)\(]//g' |");

  while (chomp(my $line = <ARP>)){
    if ($line =~ /^(\d+\.\d+\.\d+\.\d+) (.+)$/ and $line !~ /ff:ff:ff:ff:ff:ff/){
      my $ip = $1;
      my $mac_address = $2;
      $mac_address =~ s/^(\d\:.+)/0$1/;
      $devices{$ip}{'mac_address'}=$mac_address;
      chomp(my $hostname = `dig \@224.0.0.251 -p 5353 +short +time=1 +tries=1 -x $ip`);
      if ($hostname =~ / / and $routerptr){
        chomp($hostname = `dig \@$router +short +time=1 +tries=1 -x $ip`);
      } 
      if ($hostname =~ / / and $dnsptr){
        ($dns,$junk)=split(/\,\ /,$dns_servers);
        chomp($hostname = `dig \@$dns +short +time=1 +tries=1 -x $ip`);
      } 
      if ($hostname =~ / /){$hostname='unknown';}
      $devices{$ip}{'hostname'}=$hostname;
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

  open(NMAP,"$bin_nmap --script=broadcast-upnp-info -e $interface 2>/dev/null|");

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

  open(NMAP,"$bin_nmap --script=broadcast-dns-service-discovery -e $interface 2>/dev/null|");

  while (chomp(my $line = <NMAP>)){
    if ($line =~ /\|\_*\ +Address=(\d+\.\d+\.\d+\.\d+)/){
      $devices{$1}{'mdns'}=1;
      $current_device=$1;
      foreach $attrib (keys %tmp_device){
        if (!$devices{$current_device}{$attrib}){ 
          $devices{$current_device}{$attrib}=$tmp_device{$attrib};
        }
        delete $tmp_device{$attrib};
      } 
    }
    if ($line =~ /\|\_*\ +model\=(.+)$/){
      if (!$tmp_device{'model'}){
        $tmp_device{'model'}=$1;
        if ($1 =~ /macbook/i or /macmini/i or /macpro/i or /imac/i){
          $tmp_device{'manufacturer'}='Apple, Inc.';
          $tmp_device{'os'}='osx';
          $tmp_device{'is_workstation'}=1;
        }
        if ($1 =~ /appletv/i){
          $tmp_device{'manufacturer'}='Apple, Inc.';
          $tmp_device{'os'}='tvOS';
        }
      }
    }
    if ($line =~ /\|\_*\ +ty\=(.+)$/){
      if (!$tmp_device{'model'}){
        $tmp_device{'model'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +serialNumber\=(.+)$/){
      if (!$tmp_device{'serial_number'}){
        $tmp_device{'serial_number'}=$1;
      }
    }
    if ($line =~ /\|\_*\ +type\=printer$/i){
      $tmp_device{'is_printer'}=1;
      $tmp_device{'is_iot'}=1;
    }
    if ($line =~ /tcp smb$/i){
      $tmp_device{'is_fileserver'}=1;
    }
    if ($line =~ /roap$/i){
      $tmp_device{'has_airplay'}=1;
    }
  }
  close(NMAP);
  print "Done\n" if $debug;
}

## get list of dropbox clients 
#if ($dropbox){
#  open(NMAP,"$bin_nmap --script=broadcast-dropbox-listener -e $interface 2>/dev/null|");;
#  close(NMAP);
#}

## get list of clients advertising via wsdd
#if (wsdd){
#  open(NMAP,"$bin_nmap --script=broadcast-wsdd -e $interface 2>/dev/null|");x;
#  close(NMAP)
#}

print "\n\n" if $debug;
foreach my $device (keys %devices){
  if (!$devices{$device}{'manufacturer'} and $maclookup){
    sleep 2;
    my $response=`$bin_curl -s -H "Accept: text/plain" -H "Authorization: bearer $macvendors_api_key" http://api.macvendors.com/v1/lookup/$devices{$device}{'mac_address'}`;
    if ($response !~ /error/){
      $devices{$device}{'manufacturer'}=$response;
    }
  }

  if ($devices{$device}{'hostname'} =~ /^hub/ and $devices{$device}{'manufacturer'} =~ /SAMJIN/){
    ($devices{$device}{'model'}) = $devices{$device}{'hostname'} =~ m/^(hub.*)\-/;
    $devices{$device}{'manufacturer'} = 'Samsung';
    $devices{$device}{'is_iot'} = 1;
    $devices{$device}{'is_hub'} = 1;
  }
  if ($devices{$device}{'hostname'} =~ /^dp\-/i and $devices{$device}{'manufacturer'} =~ /amazon/i){
    $devices{$device}{'manufacturer'} = 'Amazon';
    ($devices{$device}{'model'}) = 'Amazon Echo';
    $devices{$device}{'is_iot'} = 1;
    $devices{$device}{'is_assistant'} = 1;
  }
  if ($devices{$device}{'hostname'} =~ /^(Ring.*)\-/ and $devices{$device}{'manufacturer'} =~ /Universal Global Scientific Industrial/){
    $devices{$device}{'manufacturer'} = 'Ring';
    ($devices{$device}{'model'}) = $devices{$device}{'hostname'} =~ m/^(Ring.*)\-/;
    $devices{$device}{'is_iot'} = 1;
  }
  if ($devices{$device}{'manufacturer'} =~ /roku/i){
    $devices{$device}{'is_iot'}=1;
    $devices{$device}{'is_tv'}=1;
  }
  if ($devices{$device}{'manufacturer'} =~ /apple/i){
    if ($devices{$device}{'hostname'} =~ /ipad/i or $devices{$device}{'hostname'} =~ /iphone/i){
      $devices{$device}{'name'}=$devices{$device}{'hostname'};
      $devices{$device}{'model'}=$devices{$device}{'hostname'} =~ m/(ipad|iphone)/i;
      $devices{$device}{'os'}='ios';
      $devices{$device}{'is_mobile'}=1;
    }
    if ($devices{$device}{'hostname'} =~ /applewatch/i){
      $devices{$device}{'name'}=$devices{$device}{'hostname'};
      $devices{$device}{'os'}='watchOS';
      $devices{$device}{'model'}='Apple Watch';
      $devices{$device}{'is_mobile'}=1;
    }
  }

  foreach my $attrib (keys %{$devices{$device}}){
    print "$device : $attrib = $devices{$device}{$attrib}\n" if $debug;
  }
  print "---\n" if $debug;
  $total++;
}

print "$total total devices found\n" if $debug;
