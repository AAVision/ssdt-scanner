package main

import (
	"fmt"
	"os"
	"strings"
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
	printCyan(banner + "\n")
}

func main() {
	printBanner()

	if os.Geteuid() != 0 {
		printDanger("[-] This tool requires root privileges\n")
		return
	}

	if err := analyzeSyscallHooks(); err != nil {
		printDanger("[-] Error: %v\n", err)
	}

	analyzeSuspiciousCalls()
	checkBPFPrograms()
	checkSystemInfo()
	runSecurityChecks()

	scanMaliciousPaths()

	printHeader("\n[+] Optional: Full System Scan\n")
	printHeader("=============================\n")
	printWarning("Do you want to perform a full system scan with ClamAV? (y/N): ")

	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		scanFullSystem()
	}

	printSuccess("\n[+] All checks completed\n")

	if len(maliciousFindings) > 0 {
		printDanger("\n🚨 SECURITY WARNING: Suspicious system call hooks detected!\n")
		printDanger("   Review the findings above and take appropriate action.\n")
	}
}
