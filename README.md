# MITM
Makes a MITM (man-in-the-middle) attack. Do not forget to enter the IP value of the target computer with "-t", the IP value of the modem with "-g" and the interface parameters you connect to the internet with "-i". Before the attack starts, it automatically determines a random mac address for the device you connect to. I set the filters on getting the username and password directly. It makes the necessary port forwarding and tries to reduce the https connection to http with sslstrip. When the program is terminated with ctrl+c it automatically fixes the toxic arp tables and then randomly changes the auto mac address again.
By the way, I recommend using dns2proxy and keeping sslstrip up to date.
