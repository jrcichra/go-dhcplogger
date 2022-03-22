package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/namsral/flag"

	// add profiler
	"net/http"
	_ "net/http/pprof"
)

func main() {
	iface := flag.String("interface", "", "Interface to capture packets on")
	dbType := flag.String("dbtype", "postgres", "Database type")
	dbDSN := flag.String("dsn", "", "Database DSN")
	workers := flag.Int("workers", 4, "Number of goroutines handling packets")
	retries := flag.Int("retries", 30, "Retry count for sql operations")
	maxQueueLength := flag.Int("max-queue-length", 1000, "Maximum number of dhcp packets to hold in queue")

	flag.Parse()

	if *iface == "" {
		panic(fmt.Errorf("No interface specified"))
	}

	// start profiler
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	feeder, err := newFeeder(*dbType, *dbDSN, *maxQueueLength, *retries)
	if err != nil {
		panic(err)
	}

	feeder.Run(*workers)

	handle, err := pcap.OpenLive(*iface, 1600, true, time.Second)
	if err != nil {
		panic(err)
	}

	// Filter for bootp reply packets
	if err := handle.SetBPFFilter("udp and (src port 67 or src port 68)"); err != nil {
		panic(err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := ps.Packets()

	termsig := make(chan os.Signal)
	signal.Notify(termsig, syscall.SIGTERM, syscall.SIGINT)

LOOP:
	for {
		select {
		case raw := <-pchan:
			select {
			case feeder.queue <- raw:
			default:
				log.Println("Queue overflow")
			}
		case <-termsig:
			break LOOP
		}
	}

	fmt.Println("Exiting...")
	handle.Close()
	feeder.Close()
}
