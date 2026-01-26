#!/bin/bash
# Script to compare NBP packet handling between netatalk and jrouter

echo "===== Testing netatalk ====="
echo "1. Starting atalkd..."
sudo systemctl start atalkd
sleep 10

echo "2. Starting AURP packet capture..."
sudo tcpdump -i any port 387 -w /home/blake/code/netatalk/tmp_packetcaptures/netatalk_aurp.pcap -G 60 -W 1 &
TCPDUMP_PID=$!
sleep 2

echo "3. Waiting for AURP connections to establish (60 seconds)..."
sleep 60

echo "4. Now open Mac Chooser and browse for 60 seconds, then press Enter"
read -p "Press Enter when done browsing..."

echo "5. Stopping capture..."
sudo pkill tcpdump
wait $TCPDUMP_PID 2>/dev/null

echo "6. Analyzing netatalk AURP packets..."
python3 /home/blake/code/netatalk/tools/aurp_pcap_analyze.py /home/blake/code/netatalk/tmp_packetcaptures/netatalk_aurp.pcap > /home/blake/code/netatalk/tmp_packetcaptures/netatalk_analysis.txt

echo ""
echo "===== Testing jrouter ====="
echo "1. Stopping atalkd..."
sudo systemctl stop atalkd
echo "   Waiting for Mac to detect network change (30 seconds)..."
sleep 30

echo "2. Starting jrouter..."
cd ~/code/jrouter_orig
sudo ./jrouter -config ~/code/machine-cfg/macpro2013/jrouter.yaml > /home/blake/code/netatalk/tmp_packetcaptures/jrouter.log 2>&1 &
JROUTER_PID=$!
echo "   Waiting for jrouter connections to establish (60 seconds)..."
sleep 60

echo "3. Take screenshot of jrouter status page:"
echo "   http://192.168.0.214:9459/status"
read -p "Press Enter when screenshot is captured..."

echo "4. Starting AURP packet capture..."
sudo tcpdump -i any port 387 -w /home/blake/code/netatalk/tmp_packetcaptures/jrouter_aurp.pcap -G 90 -W 1 &
TCPDUMP_PID=$!
sleep 2

echo "5. Now open Mac Chooser and browse for 60 seconds, then press Enter"
read -p "Press Enter when done browsing..."

echo "6. Stopping capture..."
sudo pkill tcpdump
wait $TCPDUMP_PID 2>/dev/null

echo "7. Analyzing jrouter AURP packets..."
python3 /home/blake/code/netatalk/tools/aurp_pcap_analyze.py /home/blake/code/netatalk/tmp_packetcaptures/jrouter_aurp.pcap > /home/blake/code/netatalk/tmp_packetcaptures/jrouter_analysis.txt

echo "7. Stopping jrouter..."
sudo pkill -f jrouter
wait $JROUTER_PID 2>/dev/null

echo ""
echo "===== Comparison ====="
echo "Netatalk results:"
cat /home/blake/code/netatalk/tmp_packetcaptures/netatalk_analysis.txt
echo ""
echo "jrouter results:"
cat /home/blake/code/netatalk/tmp_packetcaptures/jrouter_analysis.txt

echo ""
echo "Done! Check the .pcap files and analysis in /home/blake/code/netatalk/tmp_packetcaptures/"
