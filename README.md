# agentFox
This is a program does support to scan file based on yara rule.
Im going to add more yara rule and IOC scanning function in future.

How to use:
Change the path on agentFox.ini to the path is going to be scanned.
Copy yara rule into folder yara. You can change to different folder but by default yara folder is fine enough.


[YaraRulesPath]
value=True
path=yara\ (keep it default)
[ProcessScan]
value=True
[IOC]
value=True
path=ioc
[ScaningPath]
path=path\to\your\directory\to\scan\ (remember add "\" at the end of path)
