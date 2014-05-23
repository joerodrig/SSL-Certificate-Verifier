<h1>SSL Certificate Verifier</h1>
This SSL Certificate Verifier was created to quickly and easily search given ranges of IP addresses quickly and 
easily to grab specific certificate information and return the information to a spreadsheet for later viewing.

The information gathered is as follows:<br />
IP Address  <br />
Company Name (That the certificate is assigned to) <br />
Certificate Expiration Date <br />
Time Left(In Days) Before the Certificate Expires <br />
Common Name assigned to certificate<br />
Issuer of the certificate<br />
Certificate Serial #<br />
Public Key	<br />
Public Key Size	<br />
Error Code	<br />
Description<br />

Python libraries required to run this script:
M2Crypto < Dependencies: Swig & PCRE
pyOpenSSL

If you have pip installed, you may install these libraries through terminal:
<code>pip install libraryname</code><br />

If you are running this file through a virtual environment, you can activate it and install the libraries through terminal
as well:
<pre>cd myVirtualEnvDirectory
. bin/activate
pip install libraryname</pre>

<p><b>Note:</b>Certificate information isn't appended to the spreadsheet until the script has finished checking every IP address</p>
--------------

<h2>Using the script locally:<h2>
<p><b>Note:</b> If you wish to run the SSL Verifier on your computer, I would recommend the "checkSSLCert.py" script because
all of the steps you need to take to run the script are done on that script alone. "checkSSLCert_nohup.py" requires
extra steps that I will go into further about in "Using the script on a server".</p>

<p><b>1)</b> If you are using a virtual env for the python script, activate it first:</p>
<pre>cd sslChecker
. bin/activate</pre>

<p><b>2)</b>Initialize the script:</p>
<pre>python checkSSLCert.py</pre>

<p><b>3)</b>Enter a from/to range when prompted:</p>
<pre>From: 173.252.110.0
To: 173.252.110.255</pre>

<p><b>4)</b>You may choose to enter more ranges when prompted:</p>
<pre>Do you want to add another range?: No</pre>

<p><b>5)</b>After Adding ranges, the script will begin gathering certificate information from each IP address.
When the script is complete, all of the information will be outputted to a spreadsheet(.csv) file with a datetime name:</p>
<pre>ex) 2013-07-25_10-47-18_Log.csv</pre>



<h2>Using the script on a server</h2>
<p><b>Note:</b> These instructions utilize the "createIPRange.py" and "checkSSLCert_nohup.py" script to take advantage
of the nohup command which allows you to run a script on a server and be able to disconnect from the server safely while
still having the script run in the background.<p>

<p><b>1)</b>Connect to the server you'd like to run the script on:</p>
<pre> ssh username@servername.org</pre>

<p><b>2)</b>If you are using a virtual env for the python script, activate it first</p>
<pre>cd sslChecker_Server
. bin/activate</pre>

<p><b>3)</b>Create an IP Range list:</p>
<pre>python createIPRange.py
From: 173.252.100.0
To:173.252.255.255
</pre>

<p><b>4)</b>Initialize the SSL Checker Script using nohup:</p>
<pre>nohup python checkSSLCert_nohup.py &</pre>

<p><b>5)</b>Check the nohup output file to monitor the scripts activity:</p>
<pre>tail -f nohup.out</pre>

<p>You can now disconnect from the server at any time while the script is running</p>
<p>The certificate information will be stored in a spreadsheet file with a name similar to:</p>
<pre>2013-07-25_10-47-18_Log.csv</pre>

