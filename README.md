# VNC Slideshow

This tools uses the shodan streaming API to discover new hosts with open port `tcp/5901`.
Hosts are then probed for unauthenticated VNC access and a screenshot is created.

## Prerequisites

You require a Shodan API key which has to be provided via the environment variable `SHODAN_KEY`.

## Usage

```text
Usage of ./shodan-slideshow:
  -dumpdir string
    	screenshots will be dumped to this directory (default "/tmp/vncdumps")
  -logfile string
    	logfile location (default "slideshow.log")
```