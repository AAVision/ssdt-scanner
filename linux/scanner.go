package linux

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gookit/color"
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

var (
	successStyle = color.New(color.Green, color.OpBold)
	dangerStyle  = color.New(color.Red, color.OpBold)
	warningStyle = color.New(color.Yellow, color.OpBold)
	headerStyle  = color.New(color.Cyan, color.OpBold)
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
	headerStyle.Printf("[+] Reading kernel symbols...\n")
	symbols, err := readKernelSymbols()
	if err != nil {
		return err
	}

	headerStyle.Printf("[+] Getting loaded modules...\n")
	modules, err := getLoadedModules()
	if err != nil {
		warningStyle.Printf("[-] Warning: Could not get module info: %v\n", err)
	}

	kernelBase, err := getKernelBase()
	if err != nil {
		return err
	}

	successStyle.Printf("[+] Kernel base: 0x%016x\n", kernelBase)

	textStart, textEnd, err := getKernelTextRange()
	if err != nil {
		warningStyle.Printf("[-] Warning: Could not get kernel text range: %v\n", err)
	} else {
		successStyle.Printf("[+] Kernel text: 0x%016x - 0x%016x\n", textStart, textEnd)
	}

	syscallTableAddr, err := getSysCallTableAddress()
	if err != nil {
		return err
	}
	successStyle.Printf("[+] sys_call_table @ 0x%016x\n", syscallTableAddr)

	tableData, err := readKernelMemory(syscallTableAddr, 512*8)
	if err != nil {
		return fmt.Errorf("failed to read sys_call_table: %v", err)
	}

	headerStyle.Printf("\n[+] Analyzing system call table for hooks...\n")
	headerStyle.Printf("=============================================\n")

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
				color.Greenf("[✓] %s -> 0x%016x (%s)\n", syscallName, syscallAddr, symbol.Name)
			} else if inModule {
				color.Greenf("[✓] %s -> 0x%016x (module: %s)\n", syscallName, syscallAddr, moduleName)
			} else {
				color.Greenf("[✓] %s -> 0x%016x (kernel text)\n", syscallName, syscallAddr)
			}
		} else {

			if isHighlySuspicious(syscallAddr) {
				highlySuspiciousCount++
				dangerStyle.Printf("[!] HIGHLY SUSPICIOUS/MALICIOUS: %s -> 0x%016x\n", syscallName, syscallAddr)

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
				color.Yellowf("[!] SUSPICIOUS: %s -> 0x%016x\n", syscallName, syscallAddr)

				maliciousFindings = append(maliciousFindings, MaliciousFinding{
					SyscallNumber: syscallNum,
					SyscallName:   syscallName,
					Address:       syscallAddr,
					ModuleName:    moduleName,
					ModulePath:    modulePath,
					Severity:      "MEDIUM",
				})
			}

			color.Bluef("    Nearby symbols:\n")
			foundNearby := false
			for _, sym := range symbols {
				if sym.Address > syscallAddr && sym.Address < syscallAddr+0x1000 {
					color.Cyanf("      +0x%04x: %s %s\n", sym.Address-syscallAddr, sym.Type, sym.Name)
					foundNearby = true
				}
			}
			if !foundNearby {
				color.Yellowf("      No nearby symbols found\n")
			}
			fmt.Println()
		}
	}

	headerStyle.Printf("\n[+] Analysis complete:\n")
	successStyle.Printf("    Valid entries: %d\n", validCount)
	if suspiciousCount > 0 {
		warningStyle.Printf("    Suspicious entries: %d\n", suspiciousCount)
	}
	if highlySuspiciousCount > 0 {
		dangerStyle.Printf("    HIGHLY SUSPICIOUS/MALICIOUS entries: %d\n", highlySuspiciousCount)
	}

	return nil
}

func isClamAVInstalled() bool {
	_, err := exec.LookPath("clamscan")
	return err == nil
}

func updateClamAV() error {
	headerStyle.Printf("[+] Updating ClamAV virus definitions...\n")

	if _, err := exec.LookPath("freshclam"); err == nil {
		cmd := exec.Command("freshclam")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			warningStyle.Printf("[-] freshclam failed: %v\n", err)
			warningStyle.Printf("    Continuing with existing definitions...\n")
		} else {
			successStyle.Printf("[+] ClamAV definitions updated successfully\n")
		}
	} else {
		warningStyle.Printf("[-] freshclam not found, using existing definitions\n")
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

	headerStyle.Printf("\n[+] Scanning malicious paths with ClamAV\n")
	headerStyle.Printf("======================================\n")

	if !isClamAVInstalled() {
		dangerStyle.Printf("[-] ClamAV is not installed. Cannot scan for malware.\n")
		warningStyle.Printf("[!] Install ClamAV with: sudo apt-get install clamav clamav-daemon\n")
		return
	}

	if err := updateClamAV(); err != nil {
		warningStyle.Printf("[-] Failed to update ClamAV definitions: %v\n", err)
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
		color.Cyanf("[SCANNING] %s\n", path)

		infected, output, err := scanWithClamAV(path)
		if err != nil {
			warningStyle.Printf("    Scan failed: %v\n", err)
			continue
		}

		if infected {
			virusFound = true
			dangerStyle.Printf("    🚨 MALWARE DETECTED in %s\n", path)
			dangerStyle.Printf("    %s\n", strings.TrimSpace(output))

			dangerStyle.Printf("    [ACTION REQUIRED] Remove infected file:\n")
			dangerStyle.Printf("        sudo rm -f %s\n", path)
			dangerStyle.Printf("        sudo rmmod %s (if module is loaded)\n", filepath.Base(path))
		} else {
			color.Greenf("    [CLEAN] No malware found\n")
		}
	}

	if virusFound {
		dangerStyle.Printf("\n🚨 CRITICAL: Malware detected in system files!\n")
		dangerStyle.Printf("   Immediate action required to clean the system.\n")
	} else {
		successStyle.Printf("\n[✓] No malware detected by ClamAV\n")
	}
}

func scanFullSystem() {
	headerStyle.Printf("\n[+] Performing full system scan with ClamAV\n")
	headerStyle.Printf("=========================================\n")

	if !isClamAVInstalled() {
		return
	}

	warningStyle.Printf("[!] Full system scan may take a long time...\n")

	cmd := exec.Command("clamscan", "--infected", "--recursive", "/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		err := cmd.Run()
		if err != nil {
			if cmd.ProcessState.ExitCode() == 1 {
				dangerStyle.Printf("\n[!] Viruses found during full system scan!\n")
			} else {
				warningStyle.Printf("\n[-] Full system scan completed with errors: %v\n", err)
			}
		} else {
			successStyle.Printf("\n[✓] Full system scan completed - no viruses found\n")
		}
	}()

	color.Cyanf("Full system scan started in background...\n")
	color.Cyanf("Check system logs or run 'clamscan --recursive /' for detailed results.\n")
}

func analyzeSuspiciousCalls() {
	headerStyle.Printf("\n[+] Deep analysis of suspicious syscalls\n")
	headerStyle.Printf("========================================\n")

	symbols, err := readKernelSymbols()
	if err != nil {
		dangerStyle.Printf("Error reading symbols: %v\n", err)
		return
	}

	suspiciousAddrs := []uint64{
		0xffffffffa2f8df3e,
		0xffffffffa2f8df45,
		0xfffffeb1fffffe8f,
	}

	for _, addr := range suspiciousAddrs {
		if isHighlySuspicious(addr) {
			dangerStyle.Printf("\nAnalyzing HIGHLY SUSPICIOUS address: 0x%016x\n", addr)
		} else {
			warningStyle.Printf("\nAnalyzing suspicious address: 0x%016x\n", addr)
		}
		analyzeAddress(addr, symbols)
	}
}

func analyzeAddress(addr uint64, symbols []KernelSymbol) {
	color.Bluef("  Memory page analysis:\n")

	data, err := readKernelMemory(addr & ^uint64(0xfff), 4096)
	if err != nil {
		color.Yellowf("  Cannot read memory: %v\n", err)
	} else {
		if isLikelyCode(data) {
			color.Greenf("  Contains executable code patterns\n")
		} else {
			color.Yellowf("  Does not appear to be executable code\n")
		}
	}

	color.Bluef("  Closest symbols:\n")
	found := false
	for _, sym := range symbols {
		if sym.Address <= addr && sym.Address >= addr-0x1000 {
			offset := addr - sym.Address
			color.Cyanf("    +0x%04x: %s %s\n", offset, sym.Type, sym.Name)
			found = true
		}
	}
	if !found {
		color.Yellowf("    No symbols found in vicinity\n")
	}

	modules, _ := getLoadedModules()
	for _, mod := range modules {
		if addr >= mod.Address && addr < mod.Address+mod.Size {
			color.Greenf("  Located in module: %s (0x%016x-0x%016x)\n",
				mod.Name, mod.Address, mod.Address+mod.Size)
			color.Cyanf("  Module path: %s\n", mod.Path)
			return
		}
	}
	color.Redf("  Not in any known module - HIGH SUSPICION!\n")
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
	headerStyle.Printf("\n[+] Checking for BPF programs\n")
	headerStyle.Printf("============================\n")

	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		color.Greenf("BPF filesystem mounted\n")

		if output, err := execCommand("bpftool", "prog", "list"); err == nil {
			color.Greenf("BPF programs:\n")
			fmt.Println(output)
		} else {
			color.Yellowf("bpftool not available or no BPF programs\n")
		}
	} else {
		color.Yellowf("BPF filesystem not mounted\n")
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
	headerStyle.Printf("\n[+] System Information\n")
	headerStyle.Printf("=====================\n")

	if info, err := os.ReadFile("/proc/version"); err == nil {
		color.Cyanf("Kernel: %s", info)
	}

	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		color.Cyanf("Security modules: %s", data)
	}

	headerStyle.Printf("\n[+] Loaded Kernel Modules:\n")
	if modules, err := getLoadedModules(); err == nil {
		for _, mod := range modules {
			color.Cyanf("  %s: 0x%016x (size: %d)\n", mod.Name, mod.Address, mod.Size)
			if mod.Path != "" {
				color.Cyanf("    Path: %s\n", mod.Path)
			}
		}
	}
}

func runSecurityChecks() {
	headerStyle.Printf("\n[+] Running Security Checks\n")
	headerStyle.Printf("===========================\n")

	if _, err := os.Stat("/sys/kernel/debug/kprobes"); err == nil {
		if data, err := os.ReadFile("/sys/kernel/debug/kprobes/list"); err == nil {
			color.Cyanf("Active kprobes:\n")
			fmt.Println(string(data))
		}
	}

	if _, err := os.Stat("/sys/kernel/livepatch"); err == nil {
		color.Cyanf("Livepatch directory exists - checking for patches...\n")
		if files, err := os.ReadDir("/sys/kernel/livepatch"); err == nil {
			for _, file := range files {
				if file.IsDir() {
					color.Cyanf("  Livepatch: %s\n", file.Name())
				}
			}
		}
	}
}

func RunScanner() {

	if err := analyzeSyscallHooks(); err != nil {
		dangerStyle.Printf("[-] Error: %v\n", err)
	}

	analyzeSuspiciousCalls()
	checkBPFPrograms()
	checkSystemInfo()
	runSecurityChecks()

	scanMaliciousPaths()

	headerStyle.Printf("\n[+] Optional: Full System Scan\n")
	headerStyle.Printf("=============================\n")
	warningStyle.Printf("Do you want to perform a full system scan with ClamAV? (y/N): ")

	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		scanFullSystem()
	}

	successStyle.Printf("\n[+] All checks completed\n")

	if len(maliciousFindings) > 0 {
		dangerStyle.Printf("\n🚨 SECURITY WARNING: Suspicious system call hooks detected!\n")
		dangerStyle.Printf("   Review the findings above and take appropriate action.\n")
	}
}
