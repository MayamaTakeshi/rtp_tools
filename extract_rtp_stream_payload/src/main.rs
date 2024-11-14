extern crate pcap;
use pcap::*;

extern crate pktparse;

use pktparse::{ethernet, ipv4, udp};

use std::env;

use std::fs::File;

extern crate rurtp;

use rurtp::rtp::header::Header;

use std::io::Write;


fn usage(app: &str) {
    println!(" \
Usage: {} pcap_file src_ip src_port dst_ip dst_port payload_type codec start_stamp end_stamp stream.raw \
Ex:    {} test.pcap 192.168.2.1 10000 192.168.2.2 20000 0 pcmu 1597619570222 1597619590487 out_file \
 \
Details:
      - start_stamp and end_stamp should be epoch in milliseconds \
      - codec: pcmu | pcma | gsm | g.729 \
", app, app);
}


const DELAY_THRESHOLD : i64 = 50;
const TIME_SPAN_LIMIT : i64 = 24 * 60 * 60 * 1000;

const SILENCE_PAYLOAD_SIZE_ULAW : usize = 160;
const SILENCE_PAYLOAD_SIZE_ALAW : usize = 160;
const SILENCE_PAYLOAD_SIZE_GSM : usize = 33;
const SILENCE_PAYLOAD_SIZE_G729 : usize = 10;
const SILENCE_PAYLOAD_SIZE_OPUS : usize = 80;


static silence_ulaw : [u8; SILENCE_PAYLOAD_SIZE_ULAW] = [0xff; SILENCE_PAYLOAD_SIZE_ULAW];
static silence_alaw : [u8; SILENCE_PAYLOAD_SIZE_ULAW] = [0xd5; SILENCE_PAYLOAD_SIZE_ULAW];
//static silence_gsm : [u8; SILENCE_PAYLOAD_SIZE_GSM] = [0xdb, 0x6d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]; // this generates some tones
static silence_gsm : [u8; SILENCE_PAYLOAD_SIZE_GSM] = [0xd8, 0x20, 0xa2, 0xe1, 0x5a, 0x50, 0x00, 0x49, 0x24, 0x92, 0x49, 0x24, 0x50, 0x00, 0x49, 0x24, 0x92, 0x49, 0x24, 0x50, 0x00, 0x49, 0x24, 0x92, 0x49, 0x24, 0x50, 0x00, 0x49, 0x24, 0x92, 0x49, 0x24]; // copied from wireshark capture when there was silence in a call 
static silence_g729 : [u8; SILENCE_PAYLOAD_SIZE_G729] = [0x78, 0x52, 0x80, 0xa0, 0x00, 0xfa, 0xc2, 0x00, 0x07, 0xd6];
static silence_opus : [u8; SILENCE_PAYLOAD_SIZE_OPUS] = [
    0xf8, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]; // copied from https://github.com/meetecho/janus-gateway/blob/230f6e7196dcae6491dee3ae76a3136821b03e21/src/postprocessing/pp-opus-silence.h#L4


fn write_silence(mut out: &File, payload_type: u8) {
    println!("payload_type: {}", payload_type);
    match payload_type {
        0 => out.write(&silence_ulaw),
        8 => out.write(&silence_alaw),
        3 => out.write(&silence_gsm),
        18 => out.write(&silence_g729),
        _ => panic!("unexpected payload_type"),
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 11 {
        eprintln!("Invalid number of arguments. Expected: 10, Received: {}", args.len()-1);
        usage(&args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
	let src_ip = &args[2];
	let src_port = &args[3];
	let dst_ip = &args[4];
	let dst_port = &args[5];
	let payload_type = args[6].parse::<u8>().unwrap();
	let codec = &args[7];
    let start_stamp = args[8].parse::<i64>().unwrap();
    let end_stamp = args[9].parse::<i64>().unwrap();
	let out_file = &args[10];

    if start_stamp > end_stamp {
        eprintln!("start_stamp={} is older than end_stamp={}. Aborting.", start_stamp, end_stamp);
        std::process::exit(1);
    }

    if end_stamp - start_stamp > TIME_SPAN_LIMIT {
        eprintln!("end_stamp - start_stamp = {}. Too large time span (TIME_SPAN_LIMIT={}). Aborting.", end_stamp - start_stamp, TIME_SPAN_LIMIT);
        std::process::exit(1);
    }

    let mut cap = Capture::from_file(file_path).unwrap();

    let dl = cap.get_datalink();

    if dl != Linktype(1) && dl != Linktype(113) {
        eprintln!("datalink isn't either Ethernet or Linux cooked SLL. Aborting.");
        std::process::exit(1);
    }

    cap.filter(&["src host ", src_ip, " and src port ", src_port, " and dst host ", dst_ip, " and dst port ", dst_port ].concat(), true).unwrap();

    let mut out = File::create(out_file).unwrap();

    let mut last_ts = start_stamp;

    let mut count = 0;

    let mut last_seq_num = 0;

    loop {
        let mut p = match cap.next_packet() {
            Ok(v) => v,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => panic!("cap.next failed: {:?}", e),
        };

        let ts : i64 = p.header.ts.tv_sec * 1000 + p.header.ts.tv_usec / 1000;
        //println!("ts={}", ts);

        if ts < start_stamp {
            continue;
        }

        if ts > end_stamp {
            break;
        }

        let mut d;

        if dl == Linktype(1) {
            d = p.data;

            let (eth_data, eth) = ethernet::parse_ethernet_frame(d).unwrap();
            d = eth_data;
        } else {
            // See LINKTYPE_LINUX_SLL=113 at https://linux.die.net/man/7/pcap-linktype
            d = &p.data[16 ..];
        }

        let (ip_data, ip) = ipv4::parse_ipv4_header(d).unwrap();

        let (udp_data, udp) = udp::parse_udp_header(ip_data).unwrap();

        let h = Header::from_buf(udp_data).unwrap();

        let hi = h.info();

        if hi.version() != 2 {
            eprintln!("Ignoring non-RTP packet.");
            continue;
        }

        if hi.payload_type() != payload_type {
            eprintln!("Ignoring packet with unpexected payload_type={}.", hi.payload_type());
            continue;
        }

        if h.sequence() == last_seq_num {
            eprintln!("Ignoring packet with seq_num={} already seen.", h.sequence());
            continue;
        }

        last_seq_num = h.sequence();

        let diff = ts - last_ts;

        if diff > DELAY_THRESHOLD {
            let silence_packets = diff / 20;
            //println!("{} {} {}", ts, diff, silence_packets);

            for i in 0..silence_packets {
                println!("adding silence for {} {}", last_ts, h.sequence());
                write_silence(&out, payload_type);
                count += 1;
            } 
        }

        // rtp header without extensions is 12 bytes
        println!("writing audio");
        out.write(&udp_data[12..]);

        count += 1;

        last_ts = ts;
    }

    // write silence at the end if necessary
    let expected = (end_stamp - start_stamp) / 20;
    println!("expected={} count={}", expected, count);
    for i in 0..(expected - count) {
        println!("adding post silence");
        write_silence(&out, payload_type);
    }
}
