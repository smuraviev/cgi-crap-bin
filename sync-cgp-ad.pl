#!/usr/local/bin/perl -w
#use strict;
use MIME::Lite;
use Encode;
use Net::LDAPS;
use CGI qw(:standard);
use CLI;
use Config::Simple;
my %cfg;
use JSON::XS;
print "Content-type: text/html; charset=UTF-8\n\n";
# Config:
Config::Simple->import_from('/usr/home/-/-.cfg', \%cfg) || die Config::Simple->error(); # боевая конфа
#Config::Simple->import_from('/usr/home/-/-.cfg', \%cfg);# || die Config::Simple->error();
# Ввод
$i = param('st');
$r = param('rec');
$t1 = param('exp');
$t2 = param('del');
$t = localtime;

sub new_acc {
    my $user=$i;
    my $record=$r;
    # был ли создан ранее ------------------------------
    print " Rejected: Record ID is invalid or missing!<br>" unless $record =~m/\d{7,}$/;
    return undef unless $record =~m/\d{7,}$/;
    $count=0;
    $path = '/var/log/RecordId.log';
    open (RO,"<$path");
    while (<RO>){
    if (/($record)/i){
                      $count=1}
        };
    close(RO);
   #------------------------------------------------------------
    if( $count == 0 ){
    #------------------------------------------------------------
    if ( $user =~m/^[a-z]\d{6}$/) { # проверка вида учетки и наличия ящика 
    #print $user." ".$record;
    # LDAP
    $ldap = Net::LDAPS->new($cfg{'AD.server'},port=>636,timeout=>20,require=>'verify',capath=>$cfg{'SSL.path'})
        || print "Can't connect to ".$cfg{'AD.server'}." via LDAP";

        $result=$ldap->bind($cfg{'AD.admin'},password=>$cfg{'AD.pass'}) 
        || print "Can't bind as admin: ".$result->error;
        $result->code && print "Can't bind as admin: ".$result->error;
 
        $mesg = $ldap->search (  # perform a search
               base   => $cfg{'AD.base'},  #"cn=$domain",
               filter => "(&(sAMAccountName=$user)(MemberOf=CN=cgp-mail,OU=MAIL,OU=Группы,DC=ad,DC=pu,DC=ru) (objectclass=user))"
             );

        $ldap->unbind();

    unless(defined $mesg && !$mesg->code){
     print "LDAP search failed: ".$result->error;   
     } 
     if($mesg->all_entries() eq 0){
     print "LDAP: nothing found for '$user'";
    }
    my ($realName,$password);  
    foreach $entry ($mesg->all_entries) {
    my $ref1=@$entry{'asn'};
    my $attrs=@$ref1{'attributes'};
    foreach $atrRef (@$attrs) {
    my $type=@$atrRef{'type'};
    my $vals=@$atrRef{'vals'};
    $realName=@$vals[0] if($type eq 'cn');
    $password=@$vals[0] if($type eq 'userPassword');
    }
    last; # we need only 1 entry
  }
    my %userData;
   $userData{'RealName'}=$mesg->entry(0)->get_value('DisplayName');#$realName if(defined $realName);
    $userData {'ou'}=($mesg->entry(0)->get_value('department'));
    $userData {'ou'}=~ s/\"/\\"/g;
	$userData {'title'}=($mesg->entry(0)->get_value('title'));
	$userData {'company'}=($mesg->entry(0)->get_value('company'));
    $userData {'company'}=~ s/\"/\\"/g;
	$userData {'telephoneNumber'}= ($mesg->entry(0)->get_value('telephoneNumber'));
  $userData {'mail'}= ($mesg->entry(0)->get_value('mail'));
  #$userData{'Password'}=$password if(defined $password); 
  my $Translit = $mesg->entry(0)->get_value('displayNamePrintable') || '';
  my $aliases1 = ($mesg->entry(0)->get_value('otherMailbox',asref=>1));
  #print $userData {'mail'};
  my $dn;
  my $Fullname = $userData{'RealName'};
  if ($Translit ne '' ) { $dn = $Translit } else {$dn = $Fullname}


  #----added by <haelkar>---------------------------------------
  # fields for web-user
    my @froms;
    my @alias_all;
    my %webSettings;
    #my $Fullname = $mesg->entry(0)->get_value('DisplayName');
    my $Nacc = $mesg->entry(0)->get_value('mail');
    $webSettings{UserFrom} = '\"'.$dn.'\" <'.$Nacc.'>';
    #undef @alias_all; 
    my $mail = ($mesg->entry(0)->get_value('mail'));
                $mail =~ /(.+)\@(.+)/; # spit "@***.**"
                if ($2 eq 'spbu.ru'){
                push  @alias_all,$1};

              my $al;
              foreach $al (@$aliases1){
                  $al =~ /(.+)\@(.+)/;
		  if ($2 eq 'spbu.ru'){
        push @alias_all,$1;
        my $string = '\"'.$userData{'RealName'}.'\" <'.$1.'@spbu.ru>';
        push @froms, $string;
        };
               };
    $webSettings{UserFroms} =   [@froms];       
      
  # back to business
        my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )  
    || print "Can't login to CGPro via CLI: ".$CGP::ERR_STRING;
  $cli->CreateAccount(accountName=>"$user",settings=>\%userData) || return "Can't create account via CLI:".$cli->getErrMessage;
  $cli->SetAccountAliases("$user",[@alias_all]) || return "Can't create alias ".$cli->getErrMessage." "."@alias_all" ;
  $cli->SetWebUser("$user", {%webSettings} ) || return "Can't set Web settings for $user:" . $cli->getErrMessage;
  $cli->Logout();
# инфа для вывода  
    $t = localtime;
    print "Information: \n";  
    print $i." | ".$userData {'mail'}." | ".$t;
# запись в файл номера события
    $path = '/var/log/RecordId.log';
    open (LOG,">>$path") || print $!;
    print LOG $record."\n";
    close(LOG);
# ----------------------------
  return undef;
        }
    }
}
sub new_acc_old {
    
    my $user=$i;
    my $record=$r;

# был ли создан ранее ------------------------------
    
    print " Rejected: Record ID is invalid or missing!<br>" unless $record =~m/\d{7,}$/;
    return undef unless $record =~m/\d{7,}$/;
    $count=0;
    $path = '/var/log/RecordId.log';
    open (RO,"<$path");
    while (<RO>){
    if (/($record)/i){
                      $count=1}
        };
    close(RO);

#------------------------------------------------------------
    if( $count == 0 ){
#------------------------------------------------------------
        if ( $user =~m/^st\d{6}$/) { # проверка вида учетки и наличия ящика
# отправляемся в АД  
        $ldap = Net::LDAPS->new($cfg{'AD.server'},port=>636,timeout=>20,require=>'verify',capath=>$cfg{'SSL.path'})
        || print "Can't connect to ".$cfg{'AD.server'}." via LDAP";

        $result=$ldap->bind($cfg{'AD.admin'},password=>$cfg{'AD.pass'}) 
        || print "Can't bind as admin: ".$result->error;
        $result->code && print "Can't bind as admin: ".$result->error;
 
        $mesg = $ldap->search (  # perform a search
               base   => $cfg{'AD.base'},  #"cn=$domain",
               filter => "(&(sAMAccountName=$user)(MemberOf=CN=cgp-mail,OU=MAIL,OU=Группы,DC=ad,DC=pu,DC=ru) (objectclass=user))"
             );

        $ldap->unbind();                        # unbind & disconnect

  
     unless(defined $mesg && !$mesg->code){
     print "LDAP search failed: ".$result->error;   
     } 
     if($mesg->all_entries() eq 0){
     print "LDAP: nothing found for '$user'";
    }
    my ($realName,$password);  
    foreach $entry ($mesg->all_entries) {
    my $ref1=@$entry{'asn'};
    my $attrs=@$ref1{'attributes'};
    foreach $atrRef (@$attrs) {
      my $type=@$atrRef{'type'};
      my $vals=@$atrRef{'vals'};
      $realName=@$vals[0] if($type eq 'cn');
      $password=@$vals[0] if($type eq 'userPassword');
    }
    last; # we need only 1 entry
  }
#-----------------------------------------------------------
# Fix for realname from AD and 'mail' attribute
our $st = $mesg->entry(0)->get_value('sAMAccountName');
our $acc = $mesg->entry(0)->get_value('mail');# добавление
our $Fullname = $mesg->entry(0)->get_value('DisplayName');

#----------------------------------------------------------- 
  my %userData;
  $userData{'RealName'}=$Fullname if(defined $Fullname); 
  $userData{'Password'}=$password if(defined $password);
# connect to CGP
  my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )  
   || print "Can't login to CGPro via CLI: ".$CGP::ERR_STRING;
  
   
  
  $acc =~ /(.+)\@(.+)/;
  $acc=$1;
  $domain=$2; 

    $cli->CreateAccount(accountName=>"$st"."@"."$cfg{'CGP.domain'}",settings=>\%userData)
    || print  "Can't create ".$user.": ".$cli->getErrMessage."\n";

   if ($domain =~/spbu.ru/ ) # проверка домена в алиасе
     {
    $cli->SetAccountAliases("$user",["$acc"])
    || print "Can't create ".$acc."@".$domain.": ".$cli->getErrMessage."\n";
# инфа для вывода  
    $t = localtime;
    print "Information: \n";  
    print $i." | ".$acc."@".$domain." | ".$t;
# запись в файл номера события
    $path = '/var/log/RecordId.log';
    open (LOG,">>$path") || print $!;
    print LOG $record."\n";
    close(LOG);
# ----------------------------
    } else {print "Invalid alias for ".$user.", only spbu.ru allowed\n"};
   
    } else {print "Invalid account: ".$user};

##----------------------------------------------------------
#  if ($domain =~/spbu.ru/ )
#  {
#  $cli->SetAccountAliases("$user",["$acc"])
#  || print "Can't create alias ".$cli->getErrMessage."\n";
#  } else {print "Invalid alias for ".$user.", only spbu.ru allowed\n"};
##----------------------------------------------------------    
    my $cli->Logout(); # logoff

    }
    else {print "Rejected : " .$user. " is already created. RecordId: ".$record};
};
#----------------------------------------------------------------------------------
sub change_alias {
    
    my $user=$i;
    
    if ( $user =~m/^st\d{6}$/) { # проверка вида учетки и наличия ящика
# отправляемся в АД  
        $ldap = Net::LDAPS->new($cfg{'AD.server'},port=>636,timeout=>20,require=>'verify',capath=>$cfg{'SSL.path'})
        || die '[{"Status":false,"Message":Can\'t connect to '.$cfg{'AD.server'}.' via LDAP\"}]<br>';

        $result=$ldap->bind($cfg{'AD.admin'},password=>$cfg{'AD.pass'}) 
        || print "Can't bind as admin: ".$result->error;
        $result->code && print "Can't bind as admin: ".$result->error;
 
        $mesg = $ldap->search (  # perform a search
               base   => $cfg{'AD.base'},  #"cn=$domain",
               filter => "(&(sAMAccountName=$user)(objectclass=user))"
             );

        $ldap->unbind();
        
        my $acc = $mesg->entry(0)->get_value('mail');# добавление
        open(STDERR, ">&STDOUT");
        # connect to CGP
        my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )  
        || die "[{\"Status\":false,\"Message\":\"Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\"}]<br>";
        close(STDERR);
   
  
        $acc =~ /(.+)\@(.+)/;
        $acc=$1;
        $domain=$2; 

           if ($domain eq 'spbu.ru' ) # проверка домена в алиасе
         {  open(STDERR, ">&STDOUT");
            $cli->SetAccountAliases("$user",["$acc"])
                || die "[{\"Status\":false,\"Message\":\"Can't change alias ".$acc."@".$domain.": ".$cli->getErrMessage."\"}]<br>";
            close(STDERR);
            # инфа для вывода  
            $t = localtime;
            print "[{\"Status\":true,\"Message\":\"Changed for ".$i." : ".$acc."@".$domain." at ".$t."\"}]";  
            #print $acc."@".$domain." | ".$t;

    } else {print "[{\"Status\":false,\"Message\":\"Invalid alias for ".$user.", only spbu.ru allowed\"}]"};
   
    } else {print "[{\"Status\":false,\"Message\":\"Invalid account: ".$user."\"}]"};
    $t = localtime;
        };
#----------------------------------------------------------------------------------
sub sync_aliases { # upd sync all stuff & swag & get some bitches
    my $user = $i;
    if ( $user =~m/^st\d{6}$/) { # проверка вида учетки и наличия ящика
# отправляемся в АД  
 $ldap = Net::LDAPS->new($cfg{'AD.server'},port=>636,timeout=>20,require=>'verify',capath=>$cfg{'SSL.path'})
        || print "Can't connect to ".$cfg{'AD.server'}." via LDAP";

        $result=$ldap->bind($cfg{'AD.admin'},password=>$cfg{'AD.pass'}) 
        || print "Can't bind as admin: ".$result->error;
        $result->code && print "Can't bind as admin: ".$result->error;
 
        $mesg = $ldap->search (  # perform a search
               base   => $cfg{'AD.base'},  #"cn=$domain",
               filter => "(&(sAMAccountName=$user)(MemberOf=CN=cgp-mail,OU=MAIL,OU=Группы,DC=ad,DC=pu,DC=ru) (objectclass=user))"
             );

        $ldap->unbind();

    unless(defined $mesg && !$mesg->code){
     print "LDAP search failed: ".$result->error;   
     } 
     if($mesg->all_entries() eq 0){
     print "LDAP: nothing found for '$user'";
    }
    my ($realName,$password);  
    foreach $entry ($mesg->all_entries) {
    my $ref1=@$entry{'asn'};
    my $attrs=@$ref1{'attributes'};
    foreach $atrRef (@$attrs) {
    my $type=@$atrRef{'type'};
    my $vals=@$atrRef{'vals'};
    $realName=@$vals[0] if($type eq 'cn');
    $password=@$vals[0] if($type eq 'userPassword');
    }
    last; # we need only 1 entry
  }
    my %userData;
    $userData{'RealName'}=$mesg->entry(0)->get_value('DisplayName');#$realName if(defined $realName);
    $userData {'ou'}=($mesg->entry(0)->get_value('department'));
    $userData {'ou'}=~ s/\"/\\"/g;
	$userData {'title'}=($mesg->entry(0)->get_value('title'));
	$userData {'company'}=($mesg->entry(0)->get_value('company'));
    $userData {'company'}=~ s/\"/\\"/g; # 
	$userData {'telephoneNumber'}= ($mesg->entry(0)->get_value('telephoneNumber'));
    $userData {'mail'}= ($mesg->entry(0)->get_value('mail'));
  #$userData{'Password'}=$password if(defined $password); 
    my $Translit = $mesg->entry(0)->get_value('displayNamePrintable') || '';
    my $aliases1 = ($mesg->entry(0)->get_value('otherMailbox',asref=>1));
    my $dn;
    my $Fullname = $userData{'RealName'};
    if ($Translit ne '' ) { $dn = $Translit } else {$dn = $Fullname};


  #----added by <haelkar>---------------------------------------
  # fields for web-user
    my @froms;
    my @alias_all;
    my %webSettings;
    #my $Fullname = $mesg->entry(0)->get_value('DisplayName');
    my $Nacc = $mesg->entry(0)->get_value('mail');
    $webSettings{UserFrom} = '\"'.$dn.'\" <'.$Nacc.'>';
    #undef @alias_all; 
    my $mail = ($mesg->entry(0)->get_value('mail'));
                $mail =~ /(.+)\@(.+)/; # spit "@***.**"
                if ($2 eq 'spbu.ru'){
                push  @alias_all,$1};

              my $al;
              foreach $al (@$aliases1){
                  $al =~ /(.+)\@(.+)/;
		  if ($2 eq 'spbu.ru'){
        push @alias_all,$1;
        my $string = '\"'.$userData{RealName}.'\" <'.$1.'@spbu.ru>';
        push @froms, $string;
        };
               };
    $webSettings{'UserFroms'} =   [@froms];       
      
  # back to business
  my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )  
   || print "Can't login to CGPro via CLI: ".$CGP::ERR_STRING;
    $Web=$cli->GetWebUser($user) || print "Error: ".$cli->getErrMessage.", quitting";
    if(defined @$Web{'Signature'}){$webSettings{Signature} = @$Web{'Signature'}};
    if(defined @$Web{'SkinName'}) { $webSettings{SkinName} = @$Web{'SkinName'}};
    if(defined @$Web{'TimeZone'}) { $webSettings{TimeZone} = @$Web{'TimeZone'}};
    if(defined @$Web{'Language'}) { $webSettings{Language} = @$Web{'Language'}};
    if(defined @$Web{'RosterIMMode'}) { $webSettings{RosterIMMode} = @$Web{'RosterIMMode'}};
    $cli->UpdateAccountSettings($user,{%userData}) || print "Can't update account via CLI:".$cli->getErrMessage;
    $cli->SetAccountAliases("$user",[@alias_all]) || print "Can't create alias ".$cli->getErrMessage." "."@alias_all" ;
    $cli->SetWebUser("$user", {%webSettings} ) || print "Can't set Web settings for $user:" . $cli->getErrMessage;
    $cli->Logout();
            # инфа для вывода  
            
            print "Sync aliases and info for ".$i.": <br>";  
            print "Ok";

    #} else {print "Invalid alias for ".$user.", only spbu.ru allowed\n"};
   
    } else {print "Invalid account: ".$user};
    
}

#----------------------------------------------------------------------------------
sub cgp_pass {
    
    my $user = $i;
    my $pass = $t1;
    my $host = $ENV{'REMOTE_ADDR'};
    
    if ($host eq '81.89.183.113') {
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.su'}, #$cfg{'CGP.usr'},
                            password => $cfg{'CGP.sp'} #{'CGP.pwd'}
                          } )  
|| die "[{\"Status\":False,\"Message\":\"Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\"}]<br>";

    
    #$settings{'PWDAllowed'}= "NO";
    #$settings{'UseAppPassword'}= "NO";
    #$cli->UpdateAccountSettings ("$user\@spbu.ru", {%settings}) || print $cli->getErrMessage;
    
    #$info = $cli->GetAccountSettings("$user\@spbu.ru");
    $cli->SetAccountPassword($user, $pass) || print "Can't change: ".$cli->getErrMessage."\"}]<br>";
    print "$user : CGP-pass changed";
    $cli->Logout(); # logoff
    } else { print "$host";}
    
}
#----------------------------------------------------------------------------------
sub forwarder {
    
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.su'}, #$cfg{'CGP.usr'},
                            password => $cfg{'CGP.sp'} #{'CGP.pwd'}
                          } )  
|| die "[{\"Status\":False,\"Message\":\"Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\"}]<br>";

$forwarderName = $i;
$address = $t1;

$cli->CreateForwarder ($forwarderName, $address) || print $cli->getErrMessage;
#$answer = $cli->getForwarder($forwarderName);
print $forwarderName." to ".$address;

$cli->Logout(); # logoff

}

#----------------------------------------------------------------------------------
sub whois {
    # connect to CGP
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )
    || die "[{\"Status\":False,\"Message\":\"Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\"}]<br>";
    my $sign = $i;
    my $infoF = $cli->GetForwarder($sign) ;#|| print $cli->getErrMessage ."\n";
    if($infoF){print $infoF}
    else{  
    my $info = $cli->GetAccountMailRules($sign) ;#|| print $cli->getErrMessage ."\n";
    @a = @{$info}; # массив распидорасило!!!1111 (разыменовываем массив)
    $s = $#a;
    if ($info->[$s][1] eq '#Redirect')
        {
        print $info->[$s][3][0][1];
        
        }
    }
}


#----------------------------------------------------------------------------------
sub lists {
    my $mail = $i;
    my $list = $t1;
    my $exec = $t2;
    
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                            PeerPort => 106,
                            login    => $cfg{'CGP.usr'},
                            password => $cfg{'CGP.pwd'}
                          } )
    || die "[{\"Status\":False,\"Message\":\"Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\"}]<br>";
    
    if ($exec eq 'add') {
	$cli->List($list, 'subscribe', $mail , 'silently') || die $cli->getErrMessage .": $_ "."\n";
	print $mail." subscribed to ".$list
	}
    elsif ($exec eq 'remove'){
	$cli->List($list, 'unsubscribe', $mail , 'silently') || die $cli->getErrMessage .": $_ "."\n";
	print $mail." unsubscribed to ".$list;
	}
    elsif ($exec eq 'list'){
	my $subscr = $cli->ListSubscribers($list) || die $cli->getErrMessage ."\n";
	foreach (@$subscr){print $_."<br>"};
    }
    else {
	print "Hey, Valera!!"
    };
}
#----------------------------------------------------------------------------------
sub get_info {
    my $CGServerAddress = $cfg{'CGP.srv'};   # redefine these values
    my $CLILogin = $cfg{'CGP.usr'};
    my $CLIPassword = $cfg{'CGP.pwd'};
    #my $domain = 'spbu.ru';
    my $cli = new CGP::CLI( { PeerAddr => $CGServerAddress,
                          PeerPort => 106,
                          login    => $CLILogin,
                          password => $CLIPassword
                        } )
    || die "Can't login to CGPro via CLI: ".$CGP::ERR_STRING || die "Can't login to CG: ".$CGP::ERR_STRING."\n";
    
    print "[";
    #
sub usa {
    my $in = $_[0];
    # split #T
    (my $in1 = $in) =~ s/\#T(\d)/$1/g;
    # Fucking stupid USA-style routine
    (my $db = $in1) =~ s/(\d\d)-(\d\d)-(\d\d\d\d)_(\d\d):(\d\d):(\d\d)/$3-$2-$1 $4:$5:$6/;
    return $db;
        };
#
    
    my $account = $i;
    #my $domain = 'spbu.ru';
    my $ss = $cli->GetAccountSettings ($account);
    my $ll = $cli->GetAccountInfo ("$account")|| die "ERROR: ".$cli->getErrMessage.", gofuckyourself";
    my $mail = $account;
        my $cr = '';
    $aliases = $cli->GetAccountAliases("$account") || die "Error: ".$cli->getErrMessage.", omfg";
	    my $quota = @$ss{'MaxAccountSize'};
	    if ($quota eq '') {$quota = "5G(Default)"};

            my $last = usa("@$ll{LastLogin}");
            $cr = usa("@$ll{Created}");
            my %info = ('account' =>  "$mail",
                        'RealName' => "@$ss{RealName}",
                        'Created' => "$cr",
                        'LastLogin' => "$last",
                        'StorageUsed' => "@$ll{StorageUsed}",
                        'Aliases' => "@$aliases",
                        'accountExpires' => "@$ss{accountExpires}",
                        'deleteAccount' => "@$ss{deleteAccount}",
                        'LoginIP' => "@$ll{'PrevLoginAddress'}",
                        'Quota' => "$quota"
                         );

                        $json = JSON::XS->new->encode (\%info);
                        print $json."]";
                        
}

sub gfw {
    my $a = $i."\@spbu.ru";
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
	                      PeerPort => 106,
	                      login    => $cfg{'CGP.su'},
	                      password => $cfg{'CGP.sp'}
	                    } )
    || die "Can't login to CGPro via CLI: ".$CGP::ERR_STRING || die "Can't login to CG: ".$CGP::ERR_STRING."\n";
    my $dom = $cli->ListDomains;
    foreach $d (@$dom) {
	$fw = $cli->FindForwarders($d,$a) || die "Error: ".$cli->getErrMessage.", wtf";
	if (@$fw) {
	    foreach $f(@$fw){
	    print $f."\@".$d."\n"};
	    };
	};
};

sub exc {
    
    our $pass="";
    sub randomPassword {
    my @chars;
    my $rand32;
    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
    $rand32 = join("", @chars[ map { rand @chars } (0 .. 7) ]); 
    $pass = $rand32;
    #print $pass."\n";
    return $pass;
    1;
    }
    randomPassword
    
    my $user = $i;
    my $pwd = $pass;
    my $mail_init = $t1;
    my $title = $t2;
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
	                      PeerPort => 106,
	                      login    => $cfg{'CGP.su'},
	                      password => $cfg{'CGP.sp'}
	                    } )
    || die "Can't login to CGPro via CLI: ".$CGP::ERR_STRING || die "Can't login to CG: ".$CGP::ERR_STRING."\n";
    
    my %userData;
    $userData{'RealName'}=$realName if(defined $realName); 
    $userData{'Password'}=$pwd if(defined $pwd);
    $userData{'title'}=$title;
    $userData{'accountType'}='exc';
    my $data = "Добрый день!
На основании документа $title
Создан ящик: $user
Пароль: $pwd";
    print "На основании документа $title<br>Создан ящик: $user <br>Данные доступа отправлены инициатору на почту $mail_init <br><br>$pwd";
    $msg = MIME::Lite->new (
             From =>"Sergey E. Muraviev <s.muraviev\@spbu.ru>",
             To =>"$mail_init",
             Bcc =>"s.muraviev\@spb.edu",
             #Encoding=>'utf8',
             Subject =>"$title",
             Type => 'text/plain; charset="UTF-8"',
             Data =>  "Добрый день!
              
На основании документа $title
Создан ящик: $user
Пароль: $pwd

-- 
С уважением,
Муравьев Сергей
Системный администратор СПбГУ УСИТ,
+7(812)3264981 
"
             );
         $msg->send;
    $cli->CreateAccount(accountName=>"$user",settings=>\%userData)
    || return "Can't create account via CLI:".$cli->getErrMessage;
};

sub GetSession {


#die "Usage: ./createwebusersession.pl accountName IP_Address\n" if(@ARGV<2);

my $accountName=$i;
my $IP_Address=$t1;
#my $agent=$t2;
   # if ($IP_Address=~ /*/ ) {

        my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                          PeerPort => 106,
                          login    => $cfg{'CGP.su'},
                          password => $cfg{'CGP.sp'}
                          });

        unless($cli)
        {print "* $CGProLogin can't login to CGPro via CLI: ".$CGP::ERR_STRING."\n";
        exit(0);
        }

        my $sessionid = "undef";

        unless($sessionid=$cli->CreateWebUserSession($accountName, $IP_Address, 'SKIN "viewpoint"')) {
        print "Error: ".$cli->getErrMessage."\n";
        }

    printf "https:\/\/mail.spbu.ru\/Session\/$sessionid\/frameset.wssp?\n"
  #  }else {print "Access Denied!"}
};
#----------------------------------------------------------------------------------
sub KillSession{
    my $cli = new CGP::CLI( { PeerAddr => $cfg{'CGP.srv'},
                          PeerPort => 106,
                          login    => $cfg{'CGP.usr'},
                          password => $cfg{'CGP.pwd'}
                          });

        unless($cli)
        {print "* $CGProLogin can't login to CGPro via CLI: ".$CGP::ERR_STRING."\n";
        exit(0);
        }
        $cli->KillAccountSessions($i) || die "ERROR: ".$cli->getErrMessage.", D'OH";
        print "All $i sessions killed";
}

sub Check_Name {
    $test_name = $i;

$ldap = Net::LDAPS->new('cgp2.pu.ru',port=>636,timeout=>20,require=>'verify',capath=>$cfg{'SSL.path'})
        || print "Can't connect to ".'cgp2.pu.ru'." via LDAP";

        $result=$ldap->bind($cfg{'CGP.su'},password=>$cfg{'CGP.sp'}) 
        || print "Can't bind as admin: ".$result->error;
        $result->code && print "Can't bind as admin: ".$result->error;
 
        $mesg = $ldap->search (  # perform a search
               base   => 'dc=cgprouter',  #"cn=$domain",
               filter => "mail=$test_name"
             );

        $ldap->unbind();
 if($mesg->all_entries() eq 0) {
       print $test_name." free";
# get values and update cgp account      
    } else {
#        # fields for web-user
	$mail_web = ($mesg->entry(0)->get_value('mail'));
    print $mail_web." busy";
 }
}
#----------------------------------------------------------------------------------
if ($r =~m/\d{7,}$/){new_acc($i)} # create post passphrase
elsif ($r eq '***') {get_info($i)}
elsif ($r eq '***') {change_alias($i)}
elsif ($r eq '***') {cgp_pass($i)}
elsif ($r eq '***') {forwarder($i)}
elsif ($r eq '***') {whois($i)}
elsif ($r eq '***') {lists($i)}
elsif ($r eq '***') {gfw($i)}
elsif ($r eq '***') {exc($i)}
elsif($r eq '***'){GetSession($i)}
elsif($r eq '***'){KillSession($i)}
elsif($r eq '***'){Check_Name($i)}
elsif($r eq '***') {sync_aliases($i)} 
elsif($r eq '***'){new_test($i)} else {print "[{\"Status\":\"ERROR\",\"Message\":\"Hey, stupid! What are ya tryin' to do?\"}]"};


# запись в log
if($t1){$record = $t." : ".$i." : ".$r." - ".$t1." ".$ENV{'REMOTE_ADDR'}}
else{$record = $t." : ".$i." : ".$r." - --- ".$ENV{'REMOTE_ADDR'}}
    $path = '/var/log/sync-ad.log';
    open (LOG,">>$path") || print $!;
    print LOG $record."\n";
    close(LOG);
# ----------------------------
