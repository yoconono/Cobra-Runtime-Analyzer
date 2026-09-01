package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Proc is one running process: its on-disk executable and the code files
// (executable + shared libraries) mapped into it.
type Proc struct {
	PID   int
	Exe   string
	Files []string
}

// RunningProcs walks /proc and returns per-process code files, so callers can
// attribute a shared library back to the executable(s) using it. Processes we
// cannot read (missing CAP_SYS_PTRACE, or already exited) are skipped.
func RunningProcs() (procs []Proc, err error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	for {
		names, readErr := d.Readdirnames(256)
		for _, name := range names {
			if _, e := strconv.Atoi(name); e != nil {
				continue
			}
			base := "/proc/" + name
			pid, _ := strconv.Atoi(name)
			p := Proc{PID: pid}
			if exe, e := os.Readlink(base + "/exe"); e == nil {
				if c := cleanMapPath(exe); c != "" {
					p.Exe = c
				}
			}
			set := make(map[string]struct{})
			if p.Exe != "" {
				set[p.Exe] = struct{}{}
			}
			collectMaps(base+"/maps", set)
			if len(set) == 0 {
				continue
			}
			for f := range set {
				p.Files = append(p.Files, f)
			}
			procs = append(procs, p)
		}
		if len(names) == 0 || readErr != nil {
			break
		}
	}
	return procs, nil
}

// RunningFiles walks /proc and returns the deduplicated set of on-disk
// executable and shared-library files backing currently running processes,
// along with the number of processes observed.
//
// Reading /proc/<pid>/exe and /proc/<pid>/maps for processes owned by other
// users requires CAP_SYS_PTRACE (granted to the service via the systemd unit).
// Processes we cannot read are skipped silently.
func RunningFiles() (files []string, procCount int, err error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, 0, err
	}
	defer d.Close()

	set := make(map[string]struct{})
	for {
		names, readErr := d.Readdirnames(256)
		for _, name := range names {
			if _, e := strconv.Atoi(name); e != nil {
				continue // not a pid directory
			}
			procCount++
			base := "/proc/" + name
			if exe, e := os.Readlink(base + "/exe"); e == nil {
				if p := cleanMapPath(exe); p != "" {
					set[p] = struct{}{}
				}
			}
			collectMaps(base+"/maps", set)
		}
		if len(names) == 0 || readErr != nil {
			break
		}
	}

	files = make([]string, 0, len(set))
	for p := range set {
		files = append(files, p)
	}
	return files, procCount, nil
}

func collectMaps(path string, set map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return // permission denied or process already gone
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for sc.Scan() {
		// maps line: address perms offset dev inode pathname
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue // anonymous mapping, no pathname
		}
		perms := fields[1]
		name := strings.Join(fields[5:], " ")
		// Only code: executable pages, or shared objects even if not currently +x.
		if !strings.Contains(perms, "x") && !isSharedObject(name) {
			continue
		}
		if p := cleanMapPath(name); p != "" {
			set[p] = struct{}{}
		}
	}
}

func isSharedObject(p string) bool {
	return strings.Contains(filepath.Base(p), ".so")
}

// cleanMapPath keeps only real, on-disk code paths and drops pseudo/volatile ones.
func cleanMapPath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		return "" // [heap], [vdso], [stack], anonymous, etc.
	}
	if strings.HasSuffix(p, " (deleted)") {
		return "" // binary replaced on disk (e.g. after an upgrade)
	}
	switch {
	case strings.HasPrefix(p, "/dev/"),
		strings.HasPrefix(p, "/proc/"),
		strings.HasPrefix(p, "/sys/"),
		strings.HasPrefix(p, "/run/"),
		strings.HasPrefix(p, "/tmp/"),
		strings.HasPrefix(p, "/memfd:"):
		return ""
	}
	return p
}
