<# 
@Author: Brandon C. Poole
@Version: 1.0
@Dependencies:Active Directory Module, Windows PowerShell 4.0, AD Function Level Windows Server 2012 R2
@Modified By: 
@Date of Last Change: 12/9/2015
@Changes: New Script

Purpose: Mointors changes in Active Directory such as privileged groups & users, newly created users, groups, computers, OUs, & Managed Service Accounts, 
new or recently modified GPOs, changes to AD schema, inactive user & computers, recently deleted AD objects, & accounts that are not inline with the 
domain password policy. 



Legal: Copyright © 2015 by Brandon C. Poole

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above 
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND ISC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY 
AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF 
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
OF THIS SOFTWARE.
#>

Import-Module ActiveDirectory

<#####################################################
                        Variables
#######################################################>
    

#AD DC & domain information
$server = (Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName)         
$domain = (Get-ADDomain).DNSRoot  

#Dates for report
$timeStamp = Get-Date -Format o
$date =  Get-Date
$reportTimeFrame = $date.AddDays(-7)
$inactivityDate = $date.AddDays(-180)

#Email Settings for report
$fromAddress = "noreply@example.com"
$toAddress = "admins@example.com"
$subject = "AD Security Report"
$smtpServer = "smtp.example.com"


#HTML code array for report
$html = @()

$htmlDocCSS = "TABLE 		{
						TABLE-LAYOUT: fixed; 
						FONT-SIZE: 100%; 
						WIDTH: 100%
					}
		*
					{
						margin:0
					}

		.pageholder	{
						margin: 0px auto;
					}
					
		td 				{
						VERTICAL-ALIGN: TOP; 
						FONT-FAMILY: Tahoma
					}
					
		th 			{
						VERTICAL-ALIGN: TOP; 
						COLOR: #018AC0; 
						TEXT-ALIGN: left
					}
					"

$headingCSS = '"BORDER-RIGHT: #bbbbbb 1px solid;PADDING-RIGHT: 0px;BORDER-TOP: #bbbbbb 1px solid;DISPLAY: block;PADDING-LEFT: 0px;FONT-WEIGHT: bold;FONT-SIZE: 1.25em;MARGIN-BOTTOM: -1px;MARGIN-LEFT: 0px;BORDER-LEFT: #bbbbbb 1px solid;COLOR: #FFFFFF;
PADDING-TOP: 4px;BORDER-BOTTOM: #bbbbbb 1px solid;FONT-FAMILY: Tahoma;POSITION: relative;WIDTH: 95%;TEXT-INDENT: 10px;text-align: center;BACKGROUND-COLOR: #7BA7C7;"'

$commentCSS = "BORDER-RIGHT: #bbbbbb 1px solid;
	PADDING-RIGHT: 0px;
	BORDER-TOP: #bbbbbb 1px solid;
	DISPLAY: block;
	PADDING-LEFT: 0px;
	FONT-WEIGHT: bold;
	FONT-SIZE: 8pt;
	MARGIN-BOTTOM: -1px;
	MARGIN-LEFT: 0px;
	BORDER-LEFT: #bbbbbb 1px solid;
	COLOR: #FFFFFF;
	PADDING-TOP: 4px;
	BORDER-BOTTOM: #bbbbbb 1px solid;
	FONT-FAMILY: Tahoma;
	POSITION: relative;
	WIDTH: 95%;
	TEXT-INDENT: 10px;
	BACKGROUND-COLOR:#FFFFE1;
	COLOR: #000000;
	FONT-STYLE: ITALIC;
	FONT-WEIGHT: normal;
	FONT-SIZE: 8pt;
"

$divCSS = "	BORDER-RIGHT: #bbbbbb 1px solid;
	BORDER-TOP: #bbbbbb 1px solid;
	PADDING-LEFT: 0px;
	FONT-SIZE: 8pt;
	MARGIN-BOTTOM: -1px;
	PADDING-BOTTOM: 5px;
	MARGIN-LEFT: 0px;
	BORDER-LEFT: #bbbbbb 1px solid;
	WIDTH: 95%;
	COLOR: #000000;
	MARGIN-RIGHT: 0px;
	PADDING-TOP: 4px;
	BORDER-BOTTOM: #bbbbbb 1px solid;
	FONT-FAMILY: Tahoma;
	POSITION: relative;
	BACKGROUND-COLOR: #f9f9f9"

$tempsstrn = "style="+"$headingCSS"

<#####################################################
                        Functions
#######################################################>

Function New-HTMLDocument {

        [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String] $title,
        
        [Parameter(Mandatory=$false)][String] $docType = "html",
            
        [Parameter(Mandatory=$false)][string]$cssText
    )

    $doc = @"
    <!DOCTYPE $($docType)>
    <html><head><title>$($title)</title>
		<META http-equiv=Content-Type content='text/html; charset=windows-1252'>

		<style type="text/css">$($cssText)</style>
	</head>
    <body>
"@

Return $doc

}

Function Close-HTMLDocument {

        [cmdletbinding()]
        

	$doc = @"

</body>
</html>
"@
Return $doc

}

Function New-HTMLDivTag {

        [cmdletbinding()]
        
        param(
        [Parameter(Mandatory=$false)][String] $content,
        [Parameter(Mandatory=$false)][String] $style
        )

        $doc = ""

        If ($style -ne $null) {
	        $doc += @"
			<div style="$($style)">$($content)</div>
"@ } 

        else{
        $doc += @"
			<div>$($content)</div>
"@ }

Return $doc

}

Function New-HTMLTable {

        [cmdletbinding()]
        
        param(
        [Parameter(Mandatory=$true)][array] $content,
        [Parameter(Mandatory=$false)][string] $TableStyle,
        [Parameter(Mandatory=$false)][string] $HeaderStyle,
        [Parameter(Mandatory=$false)][string] $CellStyle
        )

	$htmlTable = $Content | ConvertTo-Html -Fragment
	$htmlTable = $htmlTable -Replace '<TABLE>', '<TABLE><style>tr:nth-child(even) { background-color: #e5e5e5; TABLE-LAYOUT: Fixed; FONT-SIZE: 100%; WIDTH: 100%}</style>' 
	$htmlTable = $htmlTable -Replace '<td>', '<td style= "FONT-FAMILY: Tahoma; FONT-SIZE: 8pt;">'
	$htmlTable = $htmlTable -Replace '<th>', '<th style= "COLOR: #$($Colour1); FONT-FAMILY: Tahoma; FONT-SIZE: 8pt;">'
	$htmlTable = $htmlTable -replace '&lt;', "<"
	$htmlTable = $htmlTable-replace '&gt;', ">"
	Return $htmlTable

}

Function New-HTMLCustomElement {

        [cmdletbinding()]
        
        param(
        [Parameter(Mandatory=$true)][String] $Element,
        [Parameter(Mandatory=$false)][String] $Content,
        [Parameter(Mandatory=$false)][Boolean] $OpenTag = $false,
        [Parameter(Mandatory=$false)][String] $ElementModifiers
        )

        $doc = ""

        If ({$ElementModifiers -ne $null} -and {$OpenTag -eq $false}) {
	        $doc += @"
			<$Element $ElementModifiers>$content</$Element>
"@ } 

        elseIf({$ElementModifiers -ne $null} -and {$OpenTag -eq $true}){
        $doc += @"
			<$Element $ElementModifiers>
"@ }

        else{
        $doc += @"
			<$Element>$content</$Element>
"@ }

Return $doc

}

<#####################################################
                        Script
#######################################################>

#Creating HTML header, report heading, & a report time stamp
$html += New-HTMLDocument -CSSText $htmlDocCSS -Title "$subject for $domain"
$html += New-HTMLCustomElement -Element "h1" -ElementModifiers 'style="TEXT-ALIGN: center"' -Content "Report for $domain"
$html += New-HTMLCustomElement -Element "h5" -ElementModifiers 'style="TEXT-ALIGN: center"' -Content "Report Time: $timeStamp"
$html +="</br>"

#Getting Privileged Groups & their membership
$html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Privileged Group Membership"
$html += New-HTMLDivTag -Content "List of all groups protected by AdminSDHolder & the members of these groups. More information can be found at $(New-HTMLCustomElement -Element "a" -ElementModifiers 'href="https://technet.microsoft.com/en-us/magazine/2009.09.sdadminholder.aspx"' -Content 'https://technet.microsoft.com/en-us/magazine/2009.09.sdadminholder.aspx')" -Style $commentCSS
$contentHolder = @()
Get-ADGroup -Filter {adminCount -eq 1} -Properties adminCount,Description,DistinguishedName,CanonicalName,SID,GroupScope,GroupCategory | ForEach-Object {

    #Check to see if privalged group has any members. No need to report on empty groups
    if($(Get-ADGroupMember -Identity $_).count -gt 0 ){

        #Group data
        $contentHolder += New-HTMLCustomElement -Element "h3" -Content "$($_.samAccountName)"
        $ch=@()
        $ch += "$(New-HTMLCustomElement -Element "u" -Content "Group Description:")" + "$($_.Description)<br>"
        $ch += "$(New-HTMLCustomElement -Element "u" -Content "Group DN:")" + "$($_.DistinguishedName)<br>"
        $ch += "$(New-HTMLCustomElement -Element "u" -Content "Group CN:")" + "$($_.CanonicalName)<br>"
        $ch += "$(New-HTMLCustomElement -Element "u" -Content "Group SID:")" + "$($_.SID)<br>"
        $ch += "$(New-HTMLCustomElement -Element "u" -Content "Scope/Category:")" + "$($_.GroupScope) / $($_.GroupCategory)<br>"
        $ch = $ch | Out-String
        $contentHolder += New-HTMLCustomElement -Element "p" -ElementModifiers 'style=background-color:#f9f9f9;;font-family:consolas;font-size:8pt' -Content $($ch)

        #Temp data arrays for data
        $results = @()
        $tempMemberList = @()
    
        #User data for groups 
        $tempMemberList += Get-ADReplicationAttributeMetadata -Server $server -Object $_ -ShowAllLinkedValues
        Get-ADGroupMember -Identity $_.DistinguishedName | ForEach-Object{
                $userDistinguishedName = $_.DistinguishedName
                $lastChange = ($tempMemberList | Where-Object {$_.LastOriginatingChangeTime -ge $reportTimeFrame} | Where-Object {$_.AttributeValue -eq $userDistinguishedName}).LastOriginatingChangeTime
                $results += $_ | Add-Member -NotePropertyName "DateAdded" -NotePropertyValue $lastChange -Force -PassThru | Select SamAccountName,Name,objectClass,DateAdded
        }#End of group membership foreach loop

        $contentHolder += New-HTMLTable -Content $results
        $contentHolder += "<br>"
        $contentHolder += New-HTMLDivTag -style "background-color: white; padding-bottom: 15px"

        }#end of membership count If statement
}#End of privileged group foreach loop
$html += New-HTMLDivTag -Content $($contentHolder | Out-String) -style $divCSS

#List of Privlaged Users
$prusers = Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount, whenCreated, PasswordLastSet, Enabled | Select SamAccountName, Name, PasswordLastSet, Enabled, whenCreated | Sort whenCreated -Descending
if($prusers.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Privileged Group Membership"
    $html += New-HTMLDivTag -Content "List of all users protected by AdminSDHolder. Removing a user from a privalge group will not remove the accounts AdminSDHolder protection status. Please see $(New-HTMLCustomElement -Element "a" -ElementModifiers 'href="http://blogs.technet.com/b/askds/archive/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop.aspx"' -Content 'http://blogs.technet.com/b/askds/archive/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop.aspx')" -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($prusers) | Out-String) -style $divCSS
}

#Recently Created Groups
$newGroups = Get-ADGroup -Filter {whenCreated -ge $reportTimeFrame} -Properties whenCreated | Select SamAccountName,Name,DistinguishedName,SID,GroupCategory,GroupScope,whenCreated| Sort whenCreated -Descending
if($newGroups.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created AD Groups"
    $html += New-HTMLDivTag -Content "List of AD groups created since $reportTimeFrame. These groups should be reviewed to ensure they where authorized and not created accidentally or by a malicious actor." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($newGroups) | Out-String) -style $divCSS
}

#Recently Created Users
$newUsers = Get-ADUser -Filter {whenCreated -ge $reportTimeFrame} -Properties whenCreated | Select SamAccountName,Name,DistinguishedName,SID,whenCreated | Sort whenCreated -Descending
if($newUsers.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created AD Users"
    $html += New-HTMLDivTag -Content "List of AD Users created since $reportTimeFrame. These users should be reviewed to ensure they where authorized and not created accidentally or by a malicious actor." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($newUsers) | Out-String) -style $divCSS
}

#Recently Created Managed Service Accounts
$svc = Get-ADServiceAccount -Filter {whenCreated -ge $reportTimeFrame} -Properties whenCreated,CanonicalName  | Select Name,DistinguishedName,CanonicalName,SID,whenCreated
if($svc.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created Managed Service Accounts"
    $html += New-HTMLDivTag -Content "List of managed service accounts that have been created since $reportTimeFrame. These accounts should be reviewed to ensure they where authorized and not being add by a rouge admin." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($svc) | Out-String) -style $divCSS
}

#Recently Created Computer Accounts
$comps = Get-ADComputer -Filter {whenCreated -ge $reportTimeFrame} -Properties whenCreated,OperatingSystem,CanonicalName  | Select Name,OperatingSystem,DistinguishedName,CanonicalName,SID,whenCreated
if($comps.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created Computer Accounts"
    $html += New-HTMLDivTag -Content "List of computer accounts that have been created since $reportTimeFrame. These accounts should be reviewed to ensure they where authorized and not being add by a rouge admin." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($comps) | Out-String) -style $divCSS
}

#Recently Created or Modified GPOs
$gpos = Get-GPO -All | Where-Object {($_.CreationTime -ge $reportTimeFrame) -or ($_.ModificationTime -ge $reportTimeFrame)} | Select Displayname,ID,GpoStatus,WmiFilter,CreationTime,ModificationTime
if($gpos.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created or Modified GPOs"
    $html += New-HTMLDivTag -Content "List of GPOs that have been created or modified since $reportTimeFrame. GPOs should be reviewed to ensure they where authorized as they may have unforeseen consequences in your environment." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($gpos) | Out-String) -style $divCSS
}

#Recently Created OUs
$ous = Get-ADOrganizationalUnit -Filter {created -ge $reportTimeFrame} -Properties Created,CanonicalName | Select Name,DistinguishedName,CanonicalName,ObjectGUID,Created
if($ous.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Created OUs"
    $html += New-HTMLDivTag -Content "List of OUs that have been created since $reportTimeFrame. OUs should be reviewed to ensure they where authorized as not all GPOs maybe be applied as needed to the objects with the new OUs." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($ous) | Out-String) -style $divCSS
}

#Recent Changes to AD Schema
$schema = Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter {whenChanged -ge $reportTimeFrame} -Property objectClass, name, whenChanged,whenCreated | Select-Object objectClass, name, whenCreated, whenChanged, @{name="event";expression={($_.whenCreated).Date.ToShortDateString()}}
if($schema.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recent Changes to AD Schema"
    $html += New-HTMLDivTag -Content "List of recent changes to AD schema since $reportTimeFrame. Changes should be reviewed to ensure they where authorized." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($schema) | Out-String) -style $divCSS
}

#Accounts That Are Security Concerns 
$pwdpolicy = Get-ADDefaultDomainPasswordPolicy
$accsec = Get-ADUser -Filter "*" -Properties PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,PasswordExpired  | Where-Object {((($_.PasswordLastSet -le (Get-Date).AddDays(-$pwdpolicy.maxpasswordage.days)) -and ($_.PasswordExpired -eq $false)) -or ($_.PasswordNeverExpires -eq $true) -or ($_.PasswordNotRequired -eq $true)) -and ($_.enabled -eq $true)} | Select Name,SamAccountName,DistinguishedName,SID,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired   
if($accsec.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Accounts Flagged For Security Reasons"
    $html += New-HTMLDivTag -Content "List of accounts that flagged for security reasons. These are account that are enabled & violate the current default password policy. All accounts should have passwords set to expire & require a password. For service account please look into $(New-HTMLCustomElement -Element "a" -ElementModifiers 'https://technet.microsoft.com/en-us/library/dd560633(v=ws.10).aspx"' -Content 'Managed Service Accounts')" -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($accsec) | Out-String) -style $divCSS
}

#Inactive Computer Accounts
$iComps = Search-ADAccount -AccountInactive -ComputersOnly | Get-ADComputer -Properties whenCreated,OperatingSystem,CanonicalName,LastLogonDate | Where-Object {$_.LastLogonDate -le $inactivityDate} | Select Name,OperatingSystem,DistinguishedName,CanonicalName,SID,Enabled,LastLogonDate
if($iComps.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Inactive Computer Accounts"
    $html += New-HTMLDivTag -Content "List of computer accounts that has not communicated with AD since $inactivityDate. These computers may have been decommissioned and need to be removed from AD, reclaimed to be used other purposes or stolen." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($iComps) | Out-String) -style $divCSS
}

#Inactive User Accounts
$iUsr = Search-ADAccount -AccountInactive -UsersOnly | Get-ADUser -Properties LastLogonDate,whenCreated,Enabled | Where-Object {$_.LastLogonDate -lt $inactivityDate} | Select SamAccountName,Name,DistinguishedName,SID,whenCreated,Enabled,LastLogonDate
if($iUsr.Count -gt 0){
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Inactive User Accounts"
    $html += New-HTMLDivTag -Content "List of computer accounts that has not communicated with AD since $inactivityDate. These computers may have been decommissioned and need to be removed from AD, reclaimed to be used other purposes or stolen." -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($iUsr) | Out-String) -style $divCSS
}

#Recently Deleted AD Objects
$adObjs = GGet-ADObject -Filter 'isdeleted -eq $true' -IncludeDeletedObjects -Properties whenChanged  | Where-Object {$_.whenChanged -ge $reportTimeFrame} | Select Name,ObjectClass,ObjectGUID,whenChanged  
if($adObjs.Count -gt 0){
    $tmbst =(Get-ADObject -Identity “CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)” -Partition $((Get-ADRootDSE).configurationNamingContext) -Properties *).tombstoneLifetime
    $html += New-HTMLCustomElement -Element "h2" -ElementModifiers $tempsstrn -Content "Recently Deleted AD Objects"
    $html += New-HTMLDivTag -Content "List of AD Objects that have been deleted since $reportTimeFrame. These objects should be reviewed to ensure they where authorized to be removed from AD and not deleted accidentally or malicious. All objects listed and have been tombstoned in AD. Your tombstone policy is currently $tmbst days.More information can be found at $(New-HTMLCustomElement -Element "a" -ElementModifiers 'href="http://blogs.technet.com/b/askds/archive/2009/08/27/the-ad-recycle-bin-understanding-implementing-best-practices-and-troubleshooting.aspx"' -Content 'http://blogs.technet.com/b/askds/archive/2009/08/27/the-ad-recycle-bin-understanding-implementing-best-practices-and-troubleshooting.aspx')" -Style $commentCSS
    $html += New-HTMLDivTag -Content $(New-HTMLTable -Content $($adObjs) | Out-String) -style $divCSS
}

#Closing HTML Doc
$html += Close-HTMLDocument

#Creating a string from the HTML array
$html = $html | Out-String

#Emailing report
Send-MailMessage -From $fromAddress -Subject $subject -To $toAddress -Body $html -SmtpServer $smtpServer -BodyAsHtml