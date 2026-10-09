# Looking through the PEAPhole: Security Analysis of PEAP in Eduroam and Enterprise Wi-Fi

This repository contains all the code used to perform experiments in the paper *Looking through the PEAPhole: Security Analysis of PEAP in Eduroam and Enterprise Wi-Fi* to be published at NDSS 2027.

## Datasets

The results of our state machine learning are in the repository *learnedmodels*. In particular, the ten learned state machines are in the repository *learnedmodels/rawresults*.

## Eduroam profile statistics

**Experiment:** crawling Eduroam profiles to find how many use anonymous identities, retrieve realms, and find which EAP types are most frequently used.

    cd eduroamcrawler
    python3 cattenbak.py
    python3 profilecrawler.py
    python3 anonymousidentityfinder.py
    python3 retrieve_realms.py
    python3 eap_statistics.py

## Anonymous Identities through Configurations

**Experiment:** Testing whether devices enforce anonymous identities by default, and whether inner tunnel identities are padded. <br>
**Requirements:** Two Wi-Fi dongles, a test device, and hostapd installed (usually the case in standard Linux distributions).

    cd experimentalcerts/certs
    sudo hostapd hostapd.conf -i your-first-dongle-id
    
Observe the handshakes with your second dongle in monitor mode on tshark:

    sudo ifconfig your-second-dongle-id down
    sudo iw your-second-dongle-id set type monitor
    sudo ifconfig your-second-dongle-id up
    sudo iw your-second-dongle-id set channel 1
    tshark -i your-second-dongle-id -f "eapol.type == 0" -w capture.pcap -a duration:180

Finally, perform multiple connections with the network *"testnetwork"* using your tested device: with the identities "abc", "abcd", and "abcde", and always with the password "password". If the outer tunnel capture contains the real identity, then the network does not use anonymous identities by default. Moreover, if the length of the second packet inside the TLS tunnel always increases with exactly one byte, then the client is assumed not to pad inner tunnel identities.


## Support for UOSC and TOD-Policies

**Experiment:** Testing device's support for UOSC. <br>
**Requirements:** A Wi-Fi dongle, a test device, and hostapd installed (usually the case in standard Linux distributions).

    cd experimentalcerts/certs
    sudo hostapd hostapd.conf -i your-dongle-id

Make your device connect to "testnetwork" with username "user" and password "password". Now stop hostapd.

    cd ../differentcerts
    sudo hostapd hostapd.conf -i your-dongle-id

Your device supports UOSC if it gives the user the option of connecting. Remove testnetwork from the known networks on your device.

**Experiment:** Testing device's support for TOD-policies. <br>
**Requirements:** A Wi-Fi dongle, a test device, and hostapd installed (usually the case in standard Linux distributions).

    cd experimentalcerts/todtofucerts
    sudo hostapd hostapd.conf -i your-dongle-id

Make your device connect to "testnetwork" with username "user" and password "password".
Now stop hostapd.

    cd ../certs
    sudo hostapd hostapd.conf -i your-dongle-id

Your device does not support TOD-TOFU if it gives the user the option of connecting.

## Certificate validity crawler

**Experiment:** Collecting Eduroam certificates to check their validity periods. <br>
**Requirements:** A Wi-Fi dongle, being in proximity of an Eduroam network.

Start by retrieving Eduroam institution domain names, if you have not already done so:

    cd eduroamcrawler
    python3 cattenbak.py
    python3 profilecrawler.py
    python3 retrieve_realms.py

Then, compile a modified version of wpa_supplicant, that will save certificates:

    cd eduroamcertsaver/wpa_supplicant
    make clean
    make -j 4

Finally, we save the certificates:

    cd ../eduroamcertsaver
    sudo ./scraper.py your-dongle-id

The certificates we saved are in the directory *scrapedcerts*. We can plot the collected data:
    
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install -r requirements.txt
    python3 validity.py


## Protocol state fuzzer

**Experiment:** Testing inner tunnel PEAP implementations with protocol state fuzzing.

Start up LearnLib:

    cd peapfuzzer/stateleaner
    mvn package
    java -jar target/stateLearner-0.0.1-SNAPSHOT.jar socket.properties

Start virtual Wi-Fi interfaces:
    
    sudo modprobe mac80211_hwsim radios=4

In a new terminal, start up the client restarter:
    
    cd eapfuzzer/research
    sudo ./client_restart.py wpa_supplicant

Finally, compile and start the test harness:

    ./build.sh
	./pysetup.sh
    sudo su
    source venv/bin/activate
    ./ap_harness.py

Specific parameters can be changed in research/harness.properties.

## Anonymous Identity TLV support

**Experiment:** Testing that clients can perform successful PEAPv0 handshakes with optional anonymous identity TLV.

We perform a modified PEAP handshake using our test harness. Then connect your client using username 'user' and password 'password'

    cd anonymous_tlv/hostapd-2.11/hostapd
    make -j 4
    cd ../..
    sudo ./hostapd-2.11/hostapd/hostapd hostapd.conf

The experiment succeeded if the client is willing to perform the 4-way handshake.

**Experiment:** Testing that we can modify wpa_supplicant to process the optional anonymous identity TLV. 
First, we compile the modified version of wpa_supplicant.
    
    cd anonymous_tlv/anonymouswpasupplicant/wpasupplicant
    make -j 4
    cd ..
    sudo ./wpa_supplicant/wpa_supplicant -D nl80211 -i wlan2 -c peapv0.conf



Finally, in a different terminal, we start a modified version of hostapd which will send the anonymous identity TLV.

    cd hostapd-2.11/hostapd
    make -j 4
    cd ../..
    sudo ./hostapd-2.11/hostapd/hostapd hostapd.conf


The experiment succeeded if the wpa_supplicant configuration file now contains the line *anonymous_identity="thisisananonymousid"*

Alternatively, you can download wpa_supplicant v2.10, then apply the patch *anonymous_tlv_changes.patch*:

    wget https://w1.fi/releases/wpa_supplicant-2.10.tar.gz
    tar -xvf wpa_supplicant-2.10.tar.gz
    cd wpa_supplicant-2.10
    patch -p1 < ../anonymous_tlv/anonymous_tlv_changes.patch
    cd wpa_supplicant/
    make -j 4

Now run wpa_supplicant:

    sudo wpa_supplicant-2.10/wpa_supplicant/wpa_supplicant -D nl80211 -i wlan2 -c anonymous_tlv/anonymouswpasupplicant/peapv0.conf

You can also use your own configuration file, but make sure it contains the line "update_config=1", otherwise wpa_supplicant will not update its anonymous identity.

