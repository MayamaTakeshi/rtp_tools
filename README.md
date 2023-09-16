### Some tools to help work with RTP (VoIP)

We will use pypacker so do:
```
  pip3 install pypacker
```

We have different versions of extract_rtp_stream_payload because originally it was written in rust.
But I need this tool available in old machines where rust is not installable. So I added implementations in c and lua.


