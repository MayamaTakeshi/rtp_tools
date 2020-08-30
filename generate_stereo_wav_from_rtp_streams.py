#!/usr/bin/python

import sys
import os

def usage():
    print("""
Usage: %(app)s pcap_file ip_a port_a ip_b port_b payload_type codec start_stamp end_stamp temp_folder out_file
Ex:    %(app)s test.pcap 192.168.2.1 10000 192.168.2.2 20000 0 pcmu 1598247069756 1598247821156 temp res.wav
""" % {"app": sys.argv[0]})


if len(sys.argv) != 12:
    usage()
    sys.exit(1)

app, pcap_file, ip_a, port_a, ip_b, port_b, payload_type, codec, start_stamp, end_stamp, temp_folder, out_file = sys.argv

conversion_templates = {
	'0': "sox -t ul -r 8000 -c 1 %(payload_file)s %(wav_file)s", # pcmu
	'3': "sox -t gsm -r 8000 -c 1 %(payload_file)s %(wav_file)s", # gsm
	'8': "sox -t al -r 8000 -c 1 %(payload_file)s %(wav_file)s", # pcma
	'18': "wine /opt/codecProG729_Experimental/cp_g729_decoder.exe %(payload_file)s %(payload_file)s.raw 2>&1 > /dev/null && sox -r 8000 -e signed -b 16 -c 1 %(payload_file)s.raw %(wav_file)s", # g729
}

extract_template = "extract_rtp_stream_payload %(pcap_file)s %(src_ip)s %(src_port)s %(dst_ip)s %(dst_port)s %(payload_type)s %(codec)s %(start_stamp)s %(end_stamp)s %(payload_file)s"

gen_stereo_wav_template = "sox -M %(wav1)s %(wav2)s -e u-law %(out_file)s"

d = {
    "pcap_file": pcap_file, 
    "start_stamp": start_stamp,
    "end_stamp": end_stamp,
    "payload_type": payload_type,
    "codec": codec,
    "out_file": out_file,
}

cmds = [
    "mkdir -p " + temp_folder,
    extract_template % dict(d, **{"src_ip": ip_a, "src_port": port_a, "dst_ip": ip_b, "dst_port": port_b, "payload_file": temp_folder + '/side1.raw'}),
    extract_template % dict(d, **{"src_ip": ip_b, "src_port": port_b, "dst_ip": ip_a, "dst_port": port_a, "payload_file": temp_folder + '/side2.raw'}),
    conversion_templates[payload_type] % dict(d, **{"payload_file": temp_folder + '/side1.raw', "wav_file": temp_folder + '/side1.wav'}),
    conversion_templates[payload_type] % dict(d, **{"payload_file": temp_folder + '/side2.raw', "wav_file": temp_folder + '/side2.wav'}),
    gen_stereo_wav_template % dict(d, **{"wav1": temp_folder + '/side1.wav', "wav2": temp_folder + '/side2.wav'})
]

for cmd in cmds:
    print("Executing cmd '" + cmd + "'")
    res = os.system(cmd)
    if res != 0:
        print("cmd '" + cmd + "' failed")
        sys.exit(1)

print("Success: " + out_file + " created")
    




