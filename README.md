`picap` is an example use case which collects network traffic and indexes it in
Pilosa. It uses tools from the [PDK](https://github.com/pilosa/pdk) to do this,
and so might be a nice example if you want to use the PDK in your own
architecture.

Note: a version of this functionality used to be included in the PDK and invoked
as `pdk net`. It has been separated because of dependencies which made use of
the PDK as a whole somewhat cumbersome. Namely, it requires libpcap development
headers and doesn't cross-compile easily due to reliance on the gopacket
library.

### Pre-requisites
Install [Go](https://golang.org/doc/install), [dep](https://github.com/golang/dep#setup), and [Pilosa](https://www.pilosa.com/docs/latest/installation/).

### Install
`go get github.com/pilosa/picap`
`cd $GOPATH/src/github.com/pilosa/picap`
`dep ensure`
`go install ./cmd/picap`

### Use
You must be running a Pilosa cluster.

See `picap -h` for command line usage.


### Functionality
When invoked, `picap` reads network packet data, either from an interface, or a
pcap file. It extracts information from each packet and indexes that information
in Pilosa. Each packet is assigned a new column in Pilosa, and picap extracts a
variety of fields, not all of which are necessarily present. See the
`picap.Packet` struct for the most up to date description of what data is
extracted.

Picap uses a PDK Translator to maintain mappings between values and their Pilosa
IDs. It also starts a proxy server which may be queried in place of Pilosa and
will map back and forth between values and Pilosa IDs. For example:

```
12:52:04~$ curl -XPOST localhost:11000/index/net/query -d'TopN(frame=http-hostname, n=3)' | jq
{
  "results": [
    [
      {
        "Key": "pilosa.com",
        "Count": 1
      },
      {
        "Key": "example.com",
        "Count": 1
      },
      {
        "Key": "readthedocs.org",
        "Count": 1
      }
    ]
  ]
}
```

Normally the "Key" values in a TopN response are integers, but the proxy has mapped them back to the hostnames that they represent. Similarly on the query side:
```
curl -XPOST localhost:11000/index/net/query -d'Count(Bitmap(frame=http-hostname, rowID="pilosa.com"))' | jq
{
  "results": [
    1
  ]
}

```
