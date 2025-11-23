package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
)

var syscalls = map[int]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	21:  "access",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	89:  "readlink",
	158: "arch_prctl",
	218: "set_tid_address",
	231: "exit_group",
	464: "syscall_464",
	468: "syscall_468",
	472: "syscall_472",
	478: "syscall_478",
	479: "syscall_479",
	480: "syscall_480",
	481: "syscall_481",
	483: "syscall_483",
	484: "syscall_484",
	485: "syscall_485",
	486: "syscall_486",
	487: "syscall_487",
	495: "syscall_495",
	498: "syscall_498",
	499: "syscall_499",
	503: "syscall_503",
	504: "syscall_504",
	505: "syscall_505",
	506: "syscall_506",
	507: "syscall_507",
	509: "syscall_509",
	510: "syscall_510",
	511: "syscall_511",
}

type KernelSymbol struct {
	Address uint64
	Type    string
	Name    string
}

type ModuleInfo struct {
	Name    string
	Address uint64
	Size    uint64
	Path    string
}

type MaliciousFinding struct {
	SyscallNumber int
	SyscallName   string
	Address       uint64
	ModuleName    string
	ModulePath    string
	Severity      string
}

var maliciousFindings []MaliciousFinding

func printGreen(format string, a ...interface{}) {
	fmt.Printf(ColorGreen+format+ColorReset, a...)
}

func printRed(format string, a ...interface{}) {
	fmt.Printf(ColorRed+format+ColorReset, a...)
}

func printYellow(format string, a ...interface{}) {
	fmt.Printf(ColorYellow+format+ColorReset, a...)
}

func printBlue(format string, a ...interface{}) {
	fmt.Printf(ColorBlue+format+ColorReset, a...)
}

func printCyan(format string, a ...interface{}) {
	fmt.Printf(ColorCyan+format+ColorReset, a...)
}

func printBold(format string, a ...interface{}) {
	fmt.Printf(ColorBold+format+ColorReset, a...)
}

func printHeader(format string, a ...interface{}) {
	fmt.Printf(ColorBold+ColorCyan+format+ColorReset, a...)
}

func printWarning(format string, a ...interface{}) {
	fmt.Printf(ColorBold+ColorYellow+format+ColorReset, a...)
}

func printDanger(format string, a ...interface{}) {
	fmt.Printf(ColorBold+ColorRed+format+ColorReset, a...)
}

func printSuccess(format string, a ...interface{}) {
	fmt.Printf(ColorBold+ColorGreen+format+ColorReset, a...)
}

func readKernelSymbols() ([]KernelSymbol, error) {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/kallsyms: %v", err)
	}

	var symbols []KernelSymbol
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		addr, err := parseHex(fields[0])
		if err != nil {
			continue
		}

		symbols = append(symbols, KernelSymbol{
			Address: addr,
			Type:    fields[1],
			Name:    fields[2],
		})
	}

	return symbols, nil
}

func getLoadedModules() ([]ModuleInfo, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}

	var modules []ModuleInfo
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		size, _ := strconv.ParseUint(fields[1], 10, 64)
		address, err := parseHex(fields[5])
		if err != nil {
			continue
		}

		modulePath := findModulePath(fields[0])

		modules = append(modules, ModuleInfo{
			Name:    fields[0],
			Size:    size,
			Address: address,
			Path:    modulePath,
		})
	}

	return modules, nil
}

func findModulePath(moduleName string) string {
	paths := []string{
		"/lib/modules/%s/kernel/%s",
		"/lib/modules/%s/kernel/drivers/%s",
		"/lib/modules/%s/extra/%s",
		"/usr/lib/modules/%s/kernel/%s",
	}

	kernelRelease, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	release := strings.TrimSpace(string(kernelRelease))

	for _, pattern := range paths {

		path := fmt.Sprintf(pattern, release, moduleName)
		if _, err := os.Stat(path); err == nil {
			return path
		}

		path = fmt.Sprintf(pattern, release, moduleName+".ko")
		if _, err := os.Stat(path); err == nil {
			return path
		}

		path = fmt.Sprintf(pattern, release, moduleName+".ko.xz")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func parseHex(s string) (uint64, error) {

	clean := strings.TrimPrefix(s, "0x")
	var n uint64
	_, err := fmt.Sscanf(clean, "%x", &n)
	return n, err
}

func getKernelBase() (uint64, error) {
	symbols, err := readKernelSymbols()
	if err != nil {
		return 0, err
	}

	for _, sym := range symbols {
		if sym.Name == "_text" || sym.Name == "startup_64" {
			return sym.Address, nil
		}
	}

	return 0, fmt.Errorf("could not find kernel base symbol")
}

func getKernelTextRange() (uint64, uint64, error) {
	symbols, err := readKernelSymbols()
	if err != nil {
		return 0, 0, err
	}

	var textStart, textEnd uint64
	for _, sym := range symbols {
		if sym.Name == "_text" {
			textStart = sym.Address
		}
		if sym.Name == "_etext" {
			textEnd = sym.Address
		}
	}

	if textStart == 0 || textEnd == 0 {
		return 0, 0, fmt.Errorf("could not find kernel text range")
	}

	return textStart, textEnd, nil
}

func getSysCallTableAddress() (uint64, error) {
	symbols, err := readKernelSymbols()
	if err != nil {
		return 0, err
	}

	for _, sym := range symbols {
		if sym.Name == "sys_call_table" {
			return sym.Address, nil
		}
	}

	return 0, fmt.Errorf("sys_call_table not found")
}

func findSymbolByAddress(symbols []KernelSymbol, addr uint64) *KernelSymbol {
	for _, sym := range symbols {
		if sym.Address == addr {
			return &sym
		}
	}
	return nil
}

func isAddressInModule(addr uint64, modules []ModuleInfo) (bool, string, string) {
	for _, mod := range modules {
		if addr >= mod.Address && addr < mod.Address+mod.Size {
			return true, mod.Name, mod.Path
		}
	}
	return false, "", ""
}

func isLikelyFalsePositive(addr uint64) bool {

	if addr == 0 {
		return true
	}

	if addr < 0x1000 {
		return true
	}

	if addr < 0xffff000000000000 {
		return true
	}

	falsePositivePatterns := []uint64{
		0xffffffffffffc000,
		0xffffffffffffd000,
		0xffffffffffffe000,
		0xfffffffffffff000,
	}

	for _, pattern := range falsePositivePatterns {
		if addr == pattern {
			return true
		}
	}

	return false
}

func isHighlySuspicious(addr uint64) bool {

	suspiciousPatterns := []uint64{
		0xfffffeb1fffffe8f,
	}

	for _, pattern := range suspiciousPatterns {
		if addr == pattern {
			return true
		}
	}

	if (addr & 0xFFFF000000000000) == 0xFFFF000000000000 {
		if (addr >> 48) != 0xFFFF {
			return true
		}
	}

	return false
}

func readKernelMemory(addr uint64, size int) ([]byte, error) {
	file, err := os.Open("/proc/kcore")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/kcore: %v", err)
	}
	defer file.Close()

	f, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse /proc/kcore as ELF: %v", err)
	}

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			if addr >= prog.Vaddr && addr < prog.Vaddr+prog.Memsz {
				offset := addr - prog.Vaddr
				data := make([]byte, size)

				_, err := prog.ReadAt(data, int64(offset))
				if err != nil {
					return nil, err
				}

				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("address 0x%x not found in /proc/kcore", addr)
}

func analyzeSyscallHooks() error {
	printHeader("[+] Reading kernel symbols...\n")
	symbols, err := readKernelSymbols()
	if err != nil {
		return err
	}

	printHeader("[+] Getting loaded modules...\n")
	modules, err := getLoadedModules()
	if err != nil {
		printWarning("[-] Warning: Could not get module info: %v\n", err)
	}

	kernelBase, err := getKernelBase()
	if err != nil {
		return err
	}
	printSuccess("[+] Kernel base: 0x%016x\n", kernelBase)

	textStart, textEnd, err := getKernelTextRange()
	if err != nil {
		printWarning("[-] Warning: Could not get kernel text range: %v\n", err)
	} else {
		printSuccess("[+] Kernel text: 0x%016x - 0x%016x\n", textStart, textEnd)
	}

	syscallTableAddr, err := getSysCallTableAddress()
	if err != nil {
		return err
	}
	printSuccess("[+] sys_call_table @ 0x%016x\n", syscallTableAddr)

	tableData, err := readKernelMemory(syscallTableAddr, 512*8)
	if err != nil {
		return fmt.Errorf("failed to read sys_call_table: %v", err)
	}

	printHeader("\n[+] Analyzing system call table for hooks...\n")
	printHeader("=============================================\n")

	suspiciousCount := 0
	highlySuspiciousCount := 0
	validCount := 0

	for i := 0; i < len(tableData); i += 8 {
		if i+8 > len(tableData) {
			break
		}

		syscallAddr := binary.LittleEndian.Uint64(tableData[i : i+8])
		if syscallAddr == 0 {
			continue
		}

		syscallNum := i / 8
		syscallName, exists := syscalls[syscallNum]
		if !exists {
			syscallName = fmt.Sprintf("syscall_%d", syscallNum)
		}

		if isLikelyFalsePositive(syscallAddr) {
			continue
		}

		isInKernelText := (textStart != 0 && textEnd != 0 && syscallAddr >= textStart && syscallAddr < textEnd)

		symbol := findSymbolByAddress(symbols, syscallAddr)

		inModule, moduleName, modulePath := isAddressInModule(syscallAddr, modules)

		if isInKernelText || symbol != nil || inModule {
			validCount++
			if symbol != nil {
				printGreen("[✓] %s -> 0x%016x (%s)\n", syscallName, syscallAddr, symbol.Name)
			} else if inModule {
				printGreen("[✓] %s -> 0x%016x (module: %s)\n", syscallName, syscallAddr, moduleName)
			} else {
				printGreen("[✓] %s -> 0x%016x (kernel text)\n", syscallName, syscallAddr)
			}
		} else {

			if isHighlySuspicious(syscallAddr) {
				highlySuspiciousCount++
				printDanger("[!] HIGHLY SUSPICIOUS/MALICIOUS: %s -> 0x%016x\n", syscallName, syscallAddr)

				maliciousFindings = append(maliciousFindings, MaliciousFinding{
					SyscallNumber: syscallNum,
					SyscallName:   syscallName,
					Address:       syscallAddr,
					ModuleName:    moduleName,
					ModulePath:    modulePath,
					Severity:      "HIGH",
				})
			} else {
				suspiciousCount++
				printYellow("[!] SUSPICIOUS: %s -> 0x%016x\n", syscallName, syscallAddr)

				maliciousFindings = append(maliciousFindings, MaliciousFinding{
					SyscallNumber: syscallNum,
					SyscallName:   syscallName,
					Address:       syscallAddr,
					ModuleName:    moduleName,
					ModulePath:    modulePath,
					Severity:      "MEDIUM",
				})
			}

			printBlue("    Nearby symbols:\n")
			foundNearby := false
			for _, sym := range symbols {
				if sym.Address > syscallAddr && sym.Address < syscallAddr+0x1000 {
					printCyan("      +0x%04x: %s %s\n", sym.Address-syscallAddr, sym.Type, sym.Name)
					foundNearby = true
				}
			}
			if !foundNearby {
				printYellow("      No nearby symbols found\n")
			}
			fmt.Println()
		}
	}

	printHeader("\n[+] Analysis complete:\n")
	printSuccess("    Valid entries: %d\n", validCount)
	if suspiciousCount > 0 {
		printWarning("    Suspicious entries: %d\n", suspiciousCount)
	}
	if highlySuspiciousCount > 0 {
		printDanger("    HIGHLY SUSPICIOUS/MALICIOUS entries: %d\n", highlySuspiciousCount)
	}

	return nil
}

func isClamAVInstalled() bool {
	_, err := exec.LookPath("clamscan")
	return err == nil
}

func updateClamAV() error {
	printHeader("[+] Updating ClamAV virus definitions...\n")

	if _, err := exec.LookPath("freshclam"); err == nil {
		cmd := exec.Command("freshclam")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			printWarning("[-] freshclam failed: %v\n", err)
			printWarning("    Continuing with existing definitions...\n")
		} else {
			printSuccess("[+] ClamAV definitions updated successfully\n")
		}
	} else {
		printWarning("[-] freshclam not found, using existing definitions\n")
	}
	return nil
}

func scanWithClamAV(path string) (bool, string, error) {
	if path == "" {
		return false, "", fmt.Errorf("empty path")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, "", fmt.Errorf("path does not exist: %s", path)
	}

	cmd := exec.Command("clamscan", "--infected", "--no-summary", path)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if cmd.ProcessState.ExitCode() == 1 {
			return true, string(output), nil
		}
		return false, "", fmt.Errorf("clamscan failed: %v, output: %s", err, output)
	}

	return false, string(output), nil
}

func scanMaliciousPaths() {
	if len(maliciousFindings) == 0 {
		return
	}

	printHeader("\n[+] Scanning malicious paths with ClamAV\n")
	printHeader("======================================\n")

	if !isClamAVInstalled() {
		printDanger("[-] ClamAV is not installed. Cannot scan for malware.\n")
		printWarning("[!] Install ClamAV with: sudo apt-get install clamav clamav-daemon\n")
		return
	}

	if err := updateClamAV(); err != nil {
		printWarning("[-] Failed to update ClamAV definitions: %v\n", err)
	}

	pathsToScan := make(map[string]bool)
	for _, finding := range maliciousFindings {
		if finding.ModulePath != "" {
			pathsToScan[finding.ModulePath] = true
		}
	}

	suspiciousDirs := []string{
		"/lib/modules",
		"/usr/lib/modules",
		"/boot",
		"/etc",
		"/tmp",
		"/var/tmp",
	}

	for _, dir := range suspiciousDirs {
		if _, err := os.Stat(dir); err == nil {
			pathsToScan[dir] = true
		}
	}

	virusFound := false

	for path := range pathsToScan {
		printCyan("[SCANNING] %s\n", path)

		infected, output, err := scanWithClamAV(path)
		if err != nil {
			printWarning("    Scan failed: %v\n", err)
			continue
		}

		if infected {
			virusFound = true
			printDanger("    🚨 MALWARE DETECTED in %s\n", path)
			printDanger("    %s\n", strings.TrimSpace(output))

			printDanger("    [ACTION REQUIRED] Remove infected file:\n")
			printDanger("        sudo rm -f %s\n", path)
			printDanger("        sudo rmmod %s (if module is loaded)\n", filepath.Base(path))
		} else {
			printGreen("    [CLEAN] No malware found\n")
		}
	}

	if virusFound {
		printDanger("\n🚨 CRITICAL: Malware detected in system files!\n")
		printDanger("   Immediate action required to clean the system.\n")
	} else {
		printSuccess("\n[✓] No malware detected by ClamAV\n")
	}
}

func scanFullSystem() {
	printHeader("\n[+] Performing full system scan with ClamAV\n")
	printHeader("=========================================\n")

	if !isClamAVInstalled() {
		return
	}

	printWarning("[!] Full system scan may take a long time...\n")

	cmd := exec.Command("clamscan", "--infected", "--recursive", "/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		err := cmd.Run()
		if err != nil {
			if cmd.ProcessState.ExitCode() == 1 {
				printDanger("\n[!] Viruses found during full system scan!\n")
			} else {
				printWarning("\n[-] Full system scan completed with errors: %v\n", err)
			}
		} else {
			printSuccess("\n[✓] Full system scan completed - no viruses found\n")
		}
	}()

	printCyan("Full system scan started in background...\n")
	printCyan("Check system logs or run 'clamscan --recursive /' for detailed results.\n")
}

func analyzeSuspiciousCalls() {
	printHeader("\n[+] Deep analysis of suspicious syscalls\n")
	printHeader("========================================\n")

	symbols, err := readKernelSymbols()
	if err != nil {
		printDanger("Error reading symbols: %v\n", err)
		return
	}

	suspiciousAddrs := []uint64{
		0xffffffffa2f8df3e,
		0xffffffffa2f8df45,
		0xfffffeb1fffffe8f,
	}

	for _, addr := range suspiciousAddrs {
		if isHighlySuspicious(addr) {
			printDanger("\nAnalyzing HIGHLY SUSPICIOUS address: 0x%016x\n", addr)
		} else {
			printWarning("\nAnalyzing suspicious address: 0x%016x\n", addr)
		}
		analyzeAddress(addr, symbols)
	}
}

func analyzeAddress(addr uint64, symbols []KernelSymbol) {
	printBlue("  Memory page analysis:\n")

	data, err := readKernelMemory(addr & ^uint64(0xfff), 4096)
	if err != nil {
		printYellow("  Cannot read memory: %v\n", err)
	} else {
		if isLikelyCode(data) {
			printGreen("  Contains executable code patterns\n")
		} else {
			printYellow("  Does not appear to be executable code\n")
		}
	}

	printBlue("  Closest symbols:\n")
	found := false
	for _, sym := range symbols {
		if sym.Address <= addr && sym.Address >= addr-0x1000 {
			offset := addr - sym.Address
			printCyan("    +0x%04x: %s %s\n", offset, sym.Type, sym.Name)
			found = true
		}
	}
	if !found {
		printYellow("    No symbols found in vicinity\n")
	}

	modules, _ := getLoadedModules()
	for _, mod := range modules {
		if addr >= mod.Address && addr < mod.Address+mod.Size {
			printGreen("  Located in module: %s (0x%016x-0x%016x)\n",
				mod.Name, mod.Address, mod.Address+mod.Size)
			printCyan("  Module path: %s\n", mod.Path)
			return
		}
	}
	printRed("  Not in any known module - HIGH SUSPICION!\n")
}

func isLikelyCode(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	commonOpcodes := []byte{0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec}
	for _, opcode := range commonOpcodes {
		for i := 0; i < len(data) && i < 100; i++ {
			if data[i] == opcode {
				return true
			}
		}
	}
	return false
}

func checkBPFPrograms() {
	printHeader("\n[+] Checking for BPF programs\n")
	printHeader("============================\n")

	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		printGreen("BPF filesystem mounted\n")

		if output, err := execCommand("bpftool", "prog", "list"); err == nil {
			printGreen("BPF programs:\n")
			fmt.Println(output)
		} else {
			printYellow("bpftool not available or no BPF programs\n")
		}
	} else {
		printYellow("BPF filesystem not mounted\n")
	}
}

func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func checkSystemInfo() {
	printHeader("\n[+] System Information\n")
	printHeader("=====================\n")

	if info, err := os.ReadFile("/proc/version"); err == nil {
		printCyan("Kernel: %s", info)
	}

	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		printCyan("Security modules: %s", data)
	}

	printHeader("\n[+] Loaded Kernel Modules:\n")
	if modules, err := getLoadedModules(); err == nil {
		for _, mod := range modules {
			printCyan("  %s: 0x%016x (size: %d)\n", mod.Name, mod.Address, mod.Size)
			if mod.Path != "" {
				printCyan("    Path: %s\n", mod.Path)
			}
		}
	}
}

func runSecurityChecks() {
	printHeader("\n[+] Running Security Checks\n")
	printHeader("===========================\n")

	if _, err := os.Stat("/sys/kernel/debug/kprobes"); err == nil {
		if data, err := os.ReadFile("/sys/kernel/debug/kprobes/list"); err == nil {
			printCyan("Active kprobes:\n")
			fmt.Println(string(data))
		}
	}

	if _, err := os.Stat("/sys/kernel/livepatch"); err == nil {
		printCyan("Livepatch directory exists - checking for patches...\n")
		if files, err := os.ReadDir("/sys/kernel/livepatch"); err == nil {
			for _, file := range files {
				if file.IsDir() {
					printCyan("  Livepatch: %s\n", file.Name())
				}
			}
		}
	}
}
