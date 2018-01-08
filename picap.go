package picap

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pilosa/pdk"
	"github.com/pkg/errors"
)

type Main struct {
	Iface       string        `help:"Interface on which to listen."`
	Filename    string        `help:"File containing pcap data to read."`
	Snaplen     int32         `help:"Maximum number of bytes to capture per packet."`
	Promisc     bool          `help:"Put capture interface into promiscuous mode."`
	Timeout     time.Duration `help:"Timeout for capturing packets."`
	Concurrency int           `help:"Number of goroutines parsing packets."`
	PilosaHosts []string      `help:"Comma separated list of pilosa host:port"`
	Filter      string        `help:"BPF style filter for packet capture."`
	Index       string        `help:"Pilosa index name."`
	BindAddr    string        `help:"Local address for mapping proxy to bind."`
	BufSize     int           `help:"Buffer size for Pilosa importer."`
	MappingDir  string        `help:"Directory to store mapping data. Empty string uses a temp dir."`
	Debug       bool          `help:"Turn on debug logging."`
	Translator  string        `help:"How to store mappings. In memory(mem) or LevelDB(level)."`
}

// NewMain constructs a Main with default values.
func NewMain() *Main {
	return &Main{
		Iface:       "en0",
		Snaplen:     1500,
		Timeout:     time.Millisecond,
		Concurrency: 1,
		PilosaHosts: []string{"localhost:10101"},
		Index:       "net",
		BindAddr:    "localhost:11000",
		BufSize:     100000,
		Translator:  "mem",
	}
}

func (m *Main) Run() error {
	src, err := m.NewNetSource()
	if err != nil {
		return errors.Wrap(err, "getting new net source")
	}
	src.debug = m.Debug
	np := pdk.NewDefaultGenericParser()
	// np.IncludeMethods = true
	// np.SkipMethods["Reverse"] = struct{}{}
	// np.SkipMethods["UTC"] = struct{}{}
	// np.SkipMethods["Local"] = struct{}{}
	nm := pdk.NewCollapsingMapper()

	if m.MappingDir == "" {
		m.MappingDir, err = ioutil.TempDir("", "")
		if err != nil {
			return errors.Wrap(err, "getting temp dir for mapping")
		}
		log.Printf("storing mapping data in %v", m.MappingDir)
	}
	if m.Translator == "level" {
		lt, err := pdk.NewLevelTranslator(m.MappingDir)
		if err != nil {
			return errors.Wrap(err, "getting level translator")
		}
		nm.Translator = lt
	} else if m.Translator != "mem" {
		return errors.Errorf("unknown translator type: '%s'", m.Translator)
	}

	index, err := pdk.SetupPilosa(m.PilosaHosts, m.Index, nil, uint(m.BufSize))
	if err != nil {
		return errors.Wrap(err, "setting up pilosa")
	}
	go func() {
		err := pdk.StartMappingProxy(m.BindAddr, pdk.NewPilosaForwarder(m.PilosaHosts[0], nm.Translator))
		log.Printf("starting mapping proxy: %v", err)
	}()

	ingester := pdk.NewIngester(src, np, nm, index)
	return ingester.Run()
}

func (m *Main) NewNetSource() (*NetSource, error) {
	var h *pcap.Handle
	var err error
	if m.Filename != "" {
		h, err = pcap.OpenOffline(m.Filename)
	} else {
		h, err = pcap.OpenLive(m.Iface, m.Snaplen, m.Promisc, m.Timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("open error: %v", err)
	}

	err = h.SetBPFFilter(m.Filter)
	if err != nil {
		return nil, fmt.Errorf("error setting bpf filter: %v", err)
	}
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	packets := packetSource.Packets()
	num := uint64(0)
	np := &NetSource{
		num:     &num,
		packets: packets,
	}
	return np, nil
}

type NetSource struct {
	num     *uint64
	debug   bool
	packets chan gopacket.Packet
}

func (n *NetSource) Record() (interface{}, error) {
	atomic.AddUint64(n.num, 1)
	num := atomic.LoadUint64(n.num)
	if n.debug && num%1000 == 20 {
		log.Println("Record has reported", num, "packets")
	}
	return reifyPacket(<-n.packets)
}

type Packet struct {
	Length   int
	NetProto string
	NetSrc   string
	NetDst   string

	TransProto string
	TransSrc   string
	TransDst   string

	TCP struct {
		FIN bool
		SYN bool
		RST bool
		PSH bool
		ACK bool
		URG bool
		ECE bool
		CWR bool
		NS  bool
	}

	AppProto string

	HTTP struct {
		Hostname  string
		UserAgent string
		Method    string
	}
}

func reifyPacket(pkt gopacket.Packet) (*Packet, error) {
	pr := &Packet{}
	if errl := pkt.ErrorLayer(); errl != nil && errl.Error() != nil {
		return pr, errors.Wrap(errl.Error(), "decoding packet")
	}
	pr.Length = pkt.Metadata().Length

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return pr, nil
	}
	netProto := netLayer.LayerType()
	pr.NetProto = netProto.String()
	netFlow := netLayer.NetworkFlow()
	netSrc, netDst := netFlow.Endpoints()
	pr.NetSrc = netSrc.String()
	pr.NetDst = netDst.String()

	transLayer := pkt.TransportLayer()
	if transLayer == nil {
		return pr, nil
	}
	transProto := transLayer.LayerType()
	pr.TransProto = transProto.String()
	transFlow := transLayer.TransportFlow()
	transSrc, transDst := transFlow.Endpoints()
	pr.TransSrc = transSrc.String()
	pr.TransDst = transDst.String()

	if tcpLayer, ok := transLayer.(*layers.TCP); ok {
		pr.TCP.FIN = tcpLayer.FIN
		pr.TCP.SYN = tcpLayer.SYN
		pr.TCP.RST = tcpLayer.RST
		pr.TCP.PSH = tcpLayer.PSH
		pr.TCP.ACK = tcpLayer.ACK
		pr.TCP.URG = tcpLayer.URG
		pr.TCP.ECE = tcpLayer.ECE
		pr.TCP.CWR = tcpLayer.CWR
		pr.TCP.NS = tcpLayer.NS
	}
	appLayer := pkt.ApplicationLayer()
	if appLayer != nil {
		appProto := appLayer.LayerType()
		pr.AppProto = appProto.String()
		appBytes := appLayer.Payload()
		buf := bytes.NewBuffer(appBytes)
		req, err := http.ReadRequest(bufio.NewReader(buf))
		if err == nil {
			pr.HTTP.UserAgent = req.UserAgent()
			pr.HTTP.Method = req.Method
			pr.HTTP.Hostname = req.Host
		} else {
			// try HTTP response?
			// resp, err := http.ReadResponse(bufio.NewReader(buf))
			// 	if err == nil {
			// 	}
		}
	}
	return pr, nil

}
