# No Shark?

**Challenge**: *From [IrisCTF 2025](https://ctftime.org/event/2503) in the "Networks" category, tagged as "baby".*

## Challenge Description

> Where's baby shark at?

We're given an archive containing a text file name `noshark.txt`.

## Solution

The file contains multiple lines of hexadecimal strings, here are a few first lines:
```
Data:
00000000000000000000000008004500003c7d1540004006bfa47f0000017f000001815e1a6f049536f500000000a002ffd7fe3000000204ffd70402080a0fddf1d40000000001030307
00000000000000000000000008004500003c0000400040063cba7f0000017f0000011a6f815ee579bd34049536f6a012ffcbfe3000000204ffd70402080a0fddf1d40fddf1d401030307
0000000000000000000000000800450000347d1640004006bfab7f0000017f000001815e1a6f049536f6e579bd3580100200fe2800000101080a0fddf1d40fddf1d4
000000000000000000000000080045000434505f40004006e8627f0000017f0000011a6f815ee579bd35049536f680180200022900000101080a0fddf1d50fddf1d4ffd8ffe000104a46494600010100000100010000ffdb004300030202020202030202020303030304060404040404080606050609080a0a090809090a0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ffdb00430103030304030408040408100b090b1010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010ffc200110801f401f403011100021101031101ffc4001d000001050101010100000000000000000002010304050600070809ffc400190101010101010100000000000000000000000102030405ffda000c03010002100310000001f9b87aa4d8fea49a91a3c865cd4a13706e5eb106106c2b983945cecac5444819dda6f13f78899d5373dbd64cdc852b9628f590f1a9bbcb72c5cd91a48d660674f82aed95dcf563ac586e14d14a48535caa8ee752f9e9fc6a473d3243d487646a871471a93cef3a7ea4d8fe9229eb0336459a2dc7e9bd664d8d58dd88cb94965f78fbfbb73df9914f5e867ae4be1773e1bebf36dfcde8fa9f1baa3e52d67eb8cebc612eabcfacfa373af9f759ba97d9a5a44f98753ebccebc212fcadaf6e97c96cf9e7d9e6b3d960c39a3851cc6a5e35231a3e7a0b227490ec8f94220cba73cc71a915229fa7105452d358d0f59da3f0b647b95b1f64da8f73a4f1fa3ebec6fc94f384fa857e7c3dc4fcfcf4f0fa5bcfdafa5a93cc2cfb1a5f102cccca7b72f912432c57d80f97d3eac5c51f3659ebd18a3e9d5fcebf4f0d2f7e6814ae4af4d392398dccc69cce8650b98da9191acd6b4892dde6f99e2bda481cb5cc82c6d2f3a62e7ac9092889a8170f92a691616b9e8fc7e8faf31b64f9b13e9a5f9e8f783f3f3d3e7d5f2e9f65f3e98c4f9a6bee3978f224754cb33049ed8bc7c6c9f6e2f1f9fdd31e8f9b759bf4fafe767a7cfa5f4721ae94e5919d4bcd771b3cd7553363dc3363206686b50f36e737cc39d2a72d55747b596a4d274e76fda4d1b46359792742ce8ce90af2d178fd1f40e37bb3e633e9d3e7a3dd8fcfcf4f9fd87875b7cefe8a3e7d3e923c10bd36234684f102ccf603e614faad72e7cd567b2cbc636e7c1bd9e6b6eb9e448269ecd9d8dccc740cb9388ecb56356a668b75f9b739be65c7454e53839a376759acebc6dba9c18b934b1cd7a56b5b8bacc5bcf49e2f47ae637a33c553db96c4c9a7ca5ebf37a679fbfd1d8ddd1f2c27d64be0e5f9ea67851ef679010cf5d3e644faa57c2cb51c3c23a6331ecf3ccb95a2160a6dccd952cee7d13306806596f401726674aecdbacbcd78ecc3aeb041d9dd6761df959e80c2b33e6a76762dc6da174e6cde757c76de34015312de62d274e779d79d6674f71eac233d31271b8a1c3f513525e6b00549216a4bcd8563f2a05d7137ae5294587735fc69d9a22666a64
... more lines below
```

CyberChef's Magic mode suggests that it's a `File type: application/tcp (tcp)`, meaning it's weirdly encoded network communication. I googled for a random hex packet decoder and found [HPD](https://hpd.gasmi.net/) which proved that idea to be true.

A bit more googling and asking the oracle later, I found out that the `text2pcap` binary distributed with Wireshark allows for converting the hex data to pcap file. However, it requires the data to be formatted in a specific way, so here's the script to do it for us.

```python
input_file = "noshark2.txt" # noshark.txt with `Data:` line removed
output_file = "packets.txt"

with open(input_file, "r") as infile, open(output_file, "w") as outfile:
    for line in infile:
        line = line.strip()
        if line:
            hexes = [line[j:j+2] for j in range(0, len(line), 2)]
            subline = '000000'
            for i, hx in enumerate(hexes):
                     subline += ' ' + hx 
                     k = i + 1
                     if k % 16 == 0:
                        subline += '\n'
                        subline += f'{k:06x}'
            subline += '\n'
            outfile.write(subline)
```

The `packets.txt` file now contains those hex-encoded network packets in a format that `text2pcap` will gladly accept:

```
000000 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
000010 00 3c 7d 15 40 00 40 06 bf a4 7f 00 00 01 7f 00
000020 00 01 81 5e 1a 6f 04 95 36 f5 00 00 00 00 a0 02
000030 ff d7 fe 30 00 00 02 04 ff d7 04 02 08 0a 0f dd
000040 f1 d4 00 00 00 00 01 03 03 07
000000 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
000010 00 3c 00 00 40 00 40 06 3c ba 7f 00 00 01 7f 00
000020 00 01 1a 6f 81 5e e5 79 bd 34 04 95 36 f6 a0 12
000030 ff cb fe 30 00 00 02 04 ff d7 04 02 08 0a 0f dd
000040 f1 d4 0f dd f1 d4 01 03 03 07
000000 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
000010 00 34 7d 16 40 00 40 06 bf ab 7f 00 00 01 7f 00
000020 00 01 81 5e 1a 6f 04 95 36 f6 e5 79 bd 35 80 10
000030 02 00 fe 28 00 00 01 01 08 0a 0f dd f1 d4 0f dd
000040 f1 d4
... more lines below
```

We can now convert it to pcap file: `text2pcap packets.txt output.pcap`. Once I opened it in Wireshark, I saw it contains a single raw TCP stream. To play with that data, I extracted the first (and only) stream data  with `tshark` in raw format: `tshark -r output.pcap -q -z follow,tcp,raw,0 > stream_data_raw.txt`. The created file looked like this:

```
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 127.0.0.1:33118
Node 1: 127.0.0.1:6767
	ffd8ffe000104a46494600010100000100010000ffdb004300030202020202030202020303030304060404040404080606050609080a0a090809090a0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ffdb00430103030304030408040408100b090b1010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010ffc200110801f401f403011100021101031101ffc4001d000001050101010100000000000000000002010304050600070809ffc400190101010101010100000000000000000000000102030405ffda000c03010002100310000001f9b87aa4d8fea49a91a3c865cd4a13706e5eb106106c2b983945cecac5444819dda6f13f78899d5373dbd64cdc852b9628f590f1a9bbcb72c5cd91a48d660674f82aed95dcf563ac586e14d14a48535caa8ee752f9e9fc6a473d3243d487646a871471a93cef3a7ea4d8fe9229eb0336459a2dc7e9bd664d8d58dd88cb94965f78fbfbb73df9914f5e867ae4be1773e1bebf36dfcde8fa9f1baa3e52d67eb8cebc612eabcfacfa373af9f759ba97d9a5a44f98753ebccebc212fcadaf6e97c96cf9e7d9e6b3d960c39a3851cc6a5e35231a3e7a0b227490ec8f94220cba73cc71a915229fa7105452d358d0f59da3f0b647b95b1f64da8f73a4f1fa3ebec6fc94f384fa857e7c3dc4fcfcf4f0fa5bcfdafa5a93cc2cfb1a5f102cccca7b72f912432c57d80f97d3eac5c51f3659ebd18a3e9d5fcebf4f0d2f7e6814ae4af4d392398dccc69cce8650b98da9191acd6b4892dde6f99e2bda481cb5cc82c6d2f3a62e7ac9092889a8170f92a691616b9e8fc7e8faf31b64f9b13e9a5f9e8f783f3f3d3e7d5f2e9f65f3e98c4f9a6bee3978f224754cb33049ed8bc7c6c9f6e2f1f9fdd31e8f9b759bf4fafe767a7cfa5f4721ae94e5919d4bcd771b3cd7553363dc3363206686b50f36e737cc39d2a72d55747b596a4d274e76fda4d1b46359792742ce8ce90af2d178fd1f40e37bb3e633e9d3e7a3dd8fcfcf4f9fd87875b7cefe8a3e7d3e923c10bd36234684f102ccf603e614faad72e7cd567b2cbc636e7c1bd9e6b6eb9e448269ecd9d8dccc740cb9388ecb56356a668b75f9b739be65c7454e53839a376759acebc6dba9c18b934b1cd7a56b5b8bacc5bcf49e2f47ae637a33c553db96c4c9a7ca5ebf37a679fbfd1d8ddd1f2c27d64be0e5f9ea67851ef679010cf5d3e644faa57c2cb51c3c23a6331ecf3ccb95a2160a6dccd952cee7d13306806596f401726674aecdbacbcd78ecc3aeb041d9dd6761df959e80c2b33e6a76762dc6da174e6cde757c76de34015312de62d274e779d79d6674f71eac233d31271b8a1c3f513525e6b00549216a4bcd8563f2a05d7137ae5294587735fc69d9a22666a64
... more hex lines below
```

As it still wasn't exactly what I wanted, I converted that data back to binary format: `xxd -r -p stream_data_raw.txt > stream_data.bin`. With a binary file ready, I used `binwalk` to scan the file for any interesting data: `binwalk stream_data.bin` and it found a JPEG file:

```
----------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
----------------------------------------------------------------------------------------------------------
8                                  0x8                                JPEG image, total size: 47407 bytes
----------------------------------------------------------------------------------------------------------

Analyzed 1 file for 85 file signatures (187 magic patterns) in 3.0 milliseconds
```

Once I added the `-e` flag to `binwalk`, it extracted the file for me and it ended up being a meme with a flag!

![Meme with a flag](flag.jpg)

### Final flag

```
irisctf{welcome_to_net_its_still_ez_to_read_caps_without_wireshark}
```
