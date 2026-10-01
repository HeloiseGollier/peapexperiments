# Quick set-up

Clone this repository including it's submodules:

	git clone --recurse-submodules git@github.com:vanhoefm/eapfuzzer.git

Before running our scripts, you need to compile hostapd and initialize the python
virtual environment. This only needs to be done once:

	cd research
	./build.sh
	./pysetup.sh

To test the scripts, first edit `hostapd.conf` and configure the wireless interface to use in the `interface=` line.
Then start the script:

	cd research
	sudo su
	source venv/bin/activate
	rfkill unblock wifi
	./ap_harness.py

After this you can **try connecting to the network `eapfuzzer` using either EAP-pwd or PEAP/MSCHAPv2 with as username `user` and password `password`**.
When using EAP-pwd, the script will show "confirm is correct" if handshake completed successfully.
When using PEAP/MSCHAPv2, the script will show "phase2 inside the PEAP tunnel completed successfully".

## Virtual Interface

You can try the above using virtual interfaces. First enable them:

	modprobe mac80211_hwsim radios=4

Then start `./ap_harness.py` as explained above.
Now connect using `wpa_supplicant` as follows:

	cd research
	sudo wpa_supplicant -D nl80211 -i wlan1 -c client.conf

# Fuzzer Design

Our goal is to fuzz the client-side of EAP-based handshakes.
We use Hostapd to provide all normal AP functionality,
and use Python scripts to handle the EAP handshakes.

## Hostap Modifications

Hostapd has been modified to allow an external application to handle all EAPOL frames.
This is done using the control interface provided by Hostapd.
For Python there is a small `wpaspy.py` library to access this control interface.
The following commands enable control over EAPOL frames:

- Enabled interception of EAPOL frames by setting `ext_eapol_frame_io` to 1 using the command `SET ext_eapol_frame_io 1`.
- The `EAPOL-RX` event is sent over the control interface when an EAPOL frame was received.
  The event contains the client MAC address, and the payload of the EAPOL frame.
  The received EAPOL frame is not processed by Hostapd.
- The external application can send EAPOL frames using the `EAPOL_TX` command.
  It has two parameters: the MAC address of the destination (client), and the payload of the EAPOL frame.

The advantage of this approach is that injected EAPOL frames now get retransmitted by the Wi-Fi radio,
and that the script doesn't have to handle the association stage itself (and any other Wi-Fi management).
Additionally, frames sent towards the AP are acknowledged (which isn't always the case when working in monitor mode).

## Python Script

The script `./ap_harness.py` starts a Hostapd instance in the background,
and connects to the control socket of Hostapd using `wpaspy.py`.
At this point it sets `ext_eapol_frame_io` such that this Python script can handle all EAPOL frames.

Any extra parameters passed to `./ap_harness.py` are passed on to Hostapd.
