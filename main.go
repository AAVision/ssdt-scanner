package main

import (
	"os"

	"github.com/AAVision/ssdt-scanner/linux"
	"github.com/gookit/color"
)

func printBanner() {
	banner := `
███████╗███████╗██████╗ ████████╗    ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
███████╗███████╗██║  ██║   ██║       ███████║██║   ██║██║   ██║█████╔╝ 
╚════██║╚════██║██║  ██║   ██║       ██╔══██║██║   ██║██║   ██║██╔═██╗ 
███████║███████║██████╔╝   ██║       ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
╚══════╝╚══════╝╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                                                                        
                  System Call Hook Detector
                      Created By AAVision :)
	`
	color.Cyanf(banner + "\n")
}

func main() {
	printBanner()

	if os.Geteuid() != 0 {
		color.Red.Printf("[-] This tool requires root privileges\n")
		return
	}

	linux.RunScanner()

}
