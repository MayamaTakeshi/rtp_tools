#!/usr/local/bin/lua


local function hexdump(s)
	local sz = string.len(s)
	for l = 1,sz,16 do
		io.write (string.format ("%04X: ", l-1))
		for l2 = l, math.min(sz,l+15) do
			if (l2-l)==8 then io.write ' ' end
			io.write (string.format ('%02X ', string.byte(s,l2)))
		end
		io.write ('   ')
		for l2 = l, math.min(sz,l+15) do
			if (l2-l)==8 then io.write ' ' end
			local b = string.byte(s,l2)
			if not b or b < 32 or b > 127 then b = string.byte('.') end
			io.write (string.format ('%c', b))
		end
		io.write ('\n')
	end
end

local pcaplua = require('pcaplua')
local bit = require('bit')

local DLT_EN10MB = 1
local DLT_LINUX_SLL = 113

local DELAY_THRESHOLD = 50
local TIME_SPAN_LIMIT = 24 * 60 * 60 * 1000

local SILENCE_PAYLOAD_SIZE_ULAW = 160
local SILENCE_PAYLOAD_SIZE_ALAW = 160
local SILENCE_PAYLOAD_SIZE_GSM = 33
local SILENCE_PAYLOAD_SIZE_G729 = 10


local silence_ulaw = ""
local silence_alaw = ""
local silence_gsm = ""
local silence_g729 = ""


local function prepare_silence() 
	local t = {}
	for i=1,SILENCE_PAYLOAD_SIZE_ULAW do
		t[i] = 0xff
		silence_ulaw = string.char(unpack(t))
	end

	t = {}
	for i=1,SILENCE_PAYLOAD_SIZE_ALAW do
		t[i] = 0xd5
		silence_alaw = string.char(unpack(t))
	end

	t = {0xdb, 0x6c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	silence_gsm = string.char(unpack(t))

	t = {0x78, 0x52, 0x80, 0xa0, 0x00, 0xfa, 0xc2, 0x00, 0x07, 0xd6}
	silence_g729 = string.char(unpack(t))
end


local function write_silence(out, payload_type)
	if payload_type == 0 then
		out:write(silence_ulaw)
	elseif payload_type == 8 then
		out:write(silence_alaw)
	elseif payload_type == 3 then
		out:write(silence_gsm)
	elseif payload_type == 18 then
		out:write(silence_g729)
	else
		print("Cannot generate silence payload. Unsupported payload_type " .. payload_type)
		os.exit(1)
	end
end


local function usage(app_name)
	print(string.format([[
Usage: %s pcap_file src_ip src_port dst_ip dst_port payload_type codec start_stamp end_stamp stream.raw
Ex:    %s test.pcap 192.168.2.1 10000 192.168.2.2 20000 0 pcmu 1597619570222 1597619590487 out_file

Details:
      - start_stamp and end_stamp should be epoch in milliseconds
      - codec: pcmu | pcma | gsm | g.729
]], app_name, app_name))
end



if #arg ~= 10 then
	print("Invalid number of arguments. Expected: 10, Received: " .. #arg)
	usage(arg[0])
	os.exit(1)
end

pcap_file, src_ip, src_port, dst_ip, dst_port, payload_type, codec, start_stamp, end_stamp, out_file = unpack(arg)

payload_type = tonumber(payload_type)
start_stamp = tonumber(start_stamp)
end_stamp = tonumber(end_stamp)

if start_stamp > end_stamp then
	print(string.format("start_stamp=%i is older than end_stamp=%i. Aborting.", start_stamp, end_stamp))
	os.exit(1)
end	

if end_stamp - start_stamp > TIME_SPAN_LIMIT then
	print(string.format("end_stamp - start_stamp = %i. Too large time span (TIME_SPAN_LIMIT=%i). Aborting.", end_stamp - start_stamp, TIME_SPAN_LIMIT))
	os.exit(1)
end

local cap, err = pcaplua.open_offline(pcap_file)

if not cap then
	print("open_offline() failed with " ..  err)
	os.exit(1)
end

local dl = cap:get_datalink()

if DLT_EN10MB ~= dl and DLT_LINUX_SLL ~= dl then
	print("datalink isn't either Ethernet or Linux coonked SLL. Aborting.")
	os.exit(1)
end	

local filter = string.format("src host %s and src port %s and dst host %s and dst port %s", src_ip, src_port, dst_ip, dst_port)
-- print("filter=" .. filter)

local res, err = cap:set_filter(filter)
if not res then
	printf(string.format("Couldn't install filter %s: %s", filter, err))
	os.exit(1)
end

prepare_silence()

local out = io.open(out_file, "wb")

local last_ts = start_stamp

local count = 0

local last_seqnum = -1

local function process_packet(data, ts, len)
	ts = ts * 1000
	--print("ts=" .. ts)

	if ts < start_stamp then
		--print("ts < start_stamp")
		return
	end

	if ts > end_stamp then
		--print("ts > end_stamp")
		return
	end

	local ip;

	if DLT_EN10MB == dl then
		local eth = pcaplua.decode_ethernet(data)
		-- print (hexval(eth.src), hexval(eth.dst), eth.type)

		if eth.type ~= 8 then
			--print("not ip packet")
			return
		end
		
		ip = pcaplua.decode_ip (eth.content)
	else
		-- Linux SLL cooked (header of 16 bytes)
		ip = pcaplua.decode_ip(unpack(data, 16))
	end

	if ip.proto ~= 17 then
		--print("not udp packet")
		return
	end

	local udp = pcaplua.decode_udp (ip.content)

	local rtp = udp.content

	local ver = bit.band(bit.rshift(rtp:byte(1), 6), 0x02)
	if ver ~= 2 then
		-- not RTP packet
		print("Ignoring non-RTP packet.")
		return
	end

	local pt = bit.band(rtp:byte(2), 0x7F)
	if pt ~= payload_type then
		--print("Ignoring packet with unexpected payload_type=" .. pt)
		return
	end	

	local seqnum = rtp:byte(3) * 256 + rtp:byte(4)
	-- printf("seqnum: ", seqnum)

	if seqnum == last_seqnum then
		--print("Ignoring packet with repeated seqnum=" .. seqnum)
		return
	end

	last_seqnum = seqnum

	local marker = bit.band(bit.rshift(rtp:byte(2), 7), 0x1)
	if marker == 1 then
		print("marker_bit set")
	end	

	local diff = ts - last_ts

	if diff > DELAY_THRESHOLD then
		local silence_packets = diff / 20

		for i=1,silence_packets do
			--print(string.format("adding silence pt=%u for %u %u\n", pt, last_ts, seqnum))
			write_silence(out, payload_type)
			count = count + 1
		end
	end 

	local size = len - 54;
	-- rtp header without extensions is 12 bytes
	local payload = rtp:sub(12+1)
	--hexdump(payload)
	out:write(payload)

	count = count + 1

	last_ts = ts
end	



while true do
	local data, ts, len = cap:next()
	if not data then
		-- no more packets
		break
	end	
	process_packet(data, ts, len)
end


-- write silence at the end if necessary
local expected = (end_stamp - start_stamp) / 20
print(string.format("expected=%i count=%i", expected, count))
for i=0,(expected - count) do
	--print("adding post silence for payload_type=" .. payload_type)
	write_silence(out, payload_type)
end

out:close()



