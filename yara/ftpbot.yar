rule FTP_bot {
strings:
	$a= {4D 5A 90}
	$b= {66 74 70 00 46 54 50 2E} //FTP call
	$c= {54 46 54 50 3A 20 55} // TFTP:
	$d= {52 45 54 52 20} //RETR
	$e= {66 74 70 3A  2F 2F} //FTP_url
condition:
	all of them
}