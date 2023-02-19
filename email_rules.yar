ule notPresent
{
  strings:
    $a = "KnowBe4" nocase

  condition:
    (not $a) and (filesize > 0)
}


rule CEO_Fraud
{
  strings:
    $FromEmail        = /From:.{0,20}\<yourCEO@yourDomain.com\>/ nocase
    $FromName	        = /From:.{0,20}yourCEO.{0,20}<.{5,100}>/ nocase
    $FromNameEmail    = /From:.{0,20}yourCEO.{0,20}\<yourCEO@yourDomain.com\>/ nocase

    $Reply            = /Reply-To:.{0,20}/ nocase
    $ReplyEmail       = /Reply-To:.{0,20}\<yourCEO@yourDomain.com\>/ nocase
    $ReplyName	      = /Reply-To:.{0,20}yourCEO.{0,20}\</ nocase
    $ReplyNameEmail   = /Reply-To:.{0,20}yourCEO.{0,20}\<yourCEO@yourDomain.com\>/ nocase

  condition:
    ($Reply and $FromNameEmail and not $ReplyNameEmail)
    or ($Reply and not $FromNameEmail and $ReplyNameEmail)
    or ($Reply and $FromEmail and not $ReplyEmail)
    or ($Reply and not $FromEmail and $ReplyEmail)
    or ($FromName and not $FromEmail)
    or ($ReplyName and not $ReplyNameEmail)
}


rule Attachments
{
  strings:
    $Attachment = "X-Attachment-Id"

  condition:
    $Attachment
}


rule Automated_SoftwareEmails
{
  strings:
    $ = /(\n|\r)From:.{0,200}Salesforce.{0,200}</ nocase
    $ = /(\n|\r)Subject:.{0,200}Salesforce/ nocase

    $ = /(\n|\r)From:.{0,200}HubSpot.{0,200}</ nocase
    $ = /(\n|\r)Subject:.{0,200}HubSpot/ nocase

  condition:
    any of them
}


rule KnowBe4_TrainingEmails
{
  strings:
  $ = /Return-Path:.{0,50}psm.knowbe4.com>/ nocase
  $ = /Received:.{0,50}(147.160.167.\d{1,3})/ nocase
  $ = /Received:.{0,50}(23.21.109.197)/ nocase
  $ = /Received:.{0,50}(23.21.109.212)/ nocase
  $ = /Received:.{0,50}psm.knowbe4.com/ nocase

  condition:
    any of them
}


rule InternalSender
{
  strings:
	$a = /from:.{0,60}@domain.com/ nocase
	$b = /Return-Path:.{0,60}@domain.com/ nocase
	$c = "header.from=domain.com"
	$d = /Authentication-Results:.{0,20}spf=pass/ nocase
	
  condition:
    all of them
}
