# we need visiblity on both sides of an aurp tunnel to make it functional. 

# setup Apple software on vintage hardware in my netjibbing network segment
Centris 650 with Apple Internet Router 3.0
phsically connected to my lab network switch on 192.168.0.0/24
G4 Cube test system with chooser and talk scanner software

This is a known good configuration and can act as a reference. 

My lab switch supports port mirroring I think. Setup a 3 port mirror and connect the G4 cube, Centris 650 & a system that can do packet captures. Likely another linux vm that we can access via ssh.

# reconfigure the throwback vm
The netjibbing network will be handled by the Apple hardware and software. the throwback VM will be configured by VM fusion to live on another network segment I have for IOT system. I should be able to configure my home router to port forward from the default gateway IP of the IOT network to the throwback VM. 
