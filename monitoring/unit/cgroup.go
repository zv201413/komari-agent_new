package monitoring

import (
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// cgroupMemoryLimit reads the cgroup memory limit.
// Returns 0 if not in a cgroup-limited environment or on error.
func cgroupMemoryLimit() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	var limitBytes uint64

	// Try cgroup v2 first: /sys/fs/cgroup/memory.max
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if val, err := strconv.ParseUint(s, 10, 64); err == nil {
				limitBytes = val
			}
		}
	} else {
		log.Printf("[cgroup] cannot read /sys/fs/cgroup/memory.max: %v", err)
	}

	// Fallback to cgroup v1: /sys/fs/cgroup/memory/memory.limit_in_bytes
	if limitBytes == 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
			s := strings.TrimSpace(string(data))
			if val, err := strconv.ParseUint(s, 10, 64); err == nil {
				limitBytes = val
			}
		} else {
			log.Printf("[cgroup] cannot read /sys/fs/cgroup/memory/memory.limit_in_bytes: %v", err)
		}
	}

	if limitBytes == 0 {
		return 0
	}

	// Filter out default "unlimited" values.
	// cgroup v1 sets limit_in_bytes to a huge page-aligned value (~2^63) when unlimited.
	// cgroup v2 returns "max" (handled above). Use 1TB as the practical threshold.
	const oneTerabyte = 1099511627776 // 1024^4
	if limitBytes >= oneTerabyte {
		return 0
	}

	return limitBytes
}

// cgroupMemoryUsage reads the actual cgroup memory usage (not from /proc/meminfo).
// Returns 0 if not in a cgroup-limited environment or on error.
func cgroupMemoryUsage() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Try cgroup v2 first: /sys/fs/cgroup/memory.current
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		s := strings.TrimSpace(string(data))
		if val, err := strconv.ParseUint(s, 10, 64); err == nil && val > 0 {
			return val
		}
	}

	// Fallback to cgroup v1: /sys/fs/cgroup/memory/memory.usage_in_bytes
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if val, err := strconv.ParseUint(s, 10, 64); err == nil && val > 0 {
			return val
		}
	}

	return 0
}

// cgroupCPUQuota reads the cgroup CPU quota and returns the effective core count.
// Returns 0 if not in a cgroup-limited environment or on error.
func cgroupCPUQuota() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Try cgroup v2 first: /sys/fs/cgroup/cpu.max
	// Format: "$QUOTA $PERIOD" or "max $PERIOD"
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) == 2 && fields[0] != "max" {
			quota, errQ := strconv.ParseFloat(fields[0], 64)
			period, errP := strconv.ParseFloat(fields[1], 64)
			if errQ == nil && errP == nil && period > 0 {
				cores := quota / period
				if cores > 0 {
					return cores
				}
			}
		}
	} else {
		log.Printf("[cgroup] cannot read /sys/fs/cgroup/cpu.max: %v", err)
	}

	// Fallback to cgroup v1
	quotaData, errQ := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	periodData, errP := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if errQ == nil && errP == nil {
		quota, errQ := strconv.ParseFloat(strings.TrimSpace(string(quotaData)), 64)
		period, errP := strconv.ParseFloat(strings.TrimSpace(string(periodData)), 64)
		// quota == -1 means unlimited in cgroup v1
		if errQ == nil && errP == nil && quota > 0 && period > 0 {
			cores := quota / period
			if cores > 0 {
				return cores
			}
		}
	} else {
		if errQ != nil {
			log.Printf("[cgroup] cannot read /sys/fs/cgroup/cpu/cpu.cfs_quota_us: %v", errQ)
		}
		if errP != nil {
			log.Printf("[cgroup] cannot read /sys/fs/cgroup/cpu/cpu.cfs_period_us: %v", errP)
		}
	}

	return 0
}

// CgroupAwareCPUCores returns the effective CPU core count as float64.
// Preserves fractional cores (e.g. 0.5, 3.1) instead of rounding up.
// Returns the raw quota/period value rounded to 1 decimal place when cgroup
// limits fewer cores than the host reports.
func CgroupAwareCPUCores(physicalCores int) float64 {
	cgCores := cgroupCPUQuota()
	if cgCores > 0 && cgCores < float64(physicalCores) {
		// Round to 1 decimal place: 0.5 → 0.5, 3.14 → 3.1, 2.0 → 2.0
		return math.Round(cgCores*10) / 10
	}
	return float64(physicalCores)
}

// CgroupAwareMemTotal returns the effective memory total, preferring cgroup limit
// over /proc/meminfo MemTotal when the limit is smaller.
func CgroupAwareMemTotal(procMemTotal uint64) uint64 {
	cgLimit := cgroupMemoryLimit()
	if cgLimit > 0 && cgLimit < procMemTotal {
		return cgLimit
	}
	return procMemTotal
}

// CgroupMemUsed returns the actual cgroup memory usage.
// Returns 0 if not available (caller should fall back to /proc/meminfo).
func CgroupMemUsed() uint64 {
	return cgroupMemoryUsage()
}
