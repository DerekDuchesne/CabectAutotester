CabectAutotester
================

Penetration testing tool that combines web app and server-side vulnerability checking.

Requirements:
1) The program must be run on Linux.
2) Python must be installed.

*Important Note*
This program uses the Zed Attack Proxy API which requires that the ZAP GUI be open as the program is running.
CabectAutotester will automatically open this window, but if you are connecting to another machine that's running the program
remotely, you need to enable X11 forwarding to be able to display the ZAP window.
On Mac and Linux, this can be done by setting the -X flag when using ssh.
Ex. ssh -X myHost
On Windows, installing and running Xming will help you enable X11 forwarding.

Instructions:
1) Run the setup.py file by typing 'python setup.py'. This will install all necessary dependencies.
2) Run the actual tool (cabect_autotest.py) by typing 'python cabect_autotest.py'.
3) Enter in the URL of a website to begin testing the web application and web server.

