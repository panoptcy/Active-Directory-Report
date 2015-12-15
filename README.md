# Active Directory Report

A library of AD reports written in Powershell

License
----

All functions are license under the [ISC License](http://www.isc.org/downloads/software-support-policy/isc-license/).

Copyright © 2015 by Brandon C. Poole

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above 
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND ISC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY 
AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF 
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
OF THIS SOFTWARE.

Weekly AD Report
----

This is a Powershell script designed to help AD change managment. The report generates an HTML email of change to privileged groups & users, standard users, 
groups, computers, OUs, & Managed Service Accounts, GPOs, and AD schema. The report also reports on inactive user & computers, recently deleted AD objects, & accounts that are not inline with the 
domain password policy. 

##### Configuration
To tailor the look under the variable around line 29 of the script. There you will see the following variables that you can customize to your environment:

* **reportTimeFrame** - this variable sets the time frame of the report. It is set to 7 days (weekly) as the default, however, you may change it to bi-weekly, monthly or an other reporting interval you wish by adjusting this field. 
* **inactivityDate** - this variable sets the threshold of inactivity reporting. It is set to 180 days  as the default. If you wish to change from the default please keep in mind that numbers lower than 90 may be inaccurate due to AD not alway replicating data but every 15-60 days, depending on you AD config, to prevent replication storms.
* **fromAddress** - this variable sets from address for the email report
* **toAddress** - this variable sets to address(es) for the email report
* **subject** - this variable sets the email's subject line for the report
* **smtpServer** - this variable sets the SMTP server that is to be used to send the email
