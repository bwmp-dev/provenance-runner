package gvisor

import "strconv"

type ociSpec struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Hostname   string     `json:"hostname"`
	Mounts     []ociMount `json:"mounts"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal        bool            `json:"terminal"`
	User            ociUser         `json:"user"`
	Args            []string        `json:"args"`
	Env             []string        `json:"env"`
	Cwd             string          `json:"cwd"`
	Capabilities    ociCapabilities `json:"capabilities"`
	Rlimits         []ociRlimit     `json:"rlimits"`
	NoNewPrivileges bool            `json:"noNewPrivileges"`
}

type ociUser struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Umask          uint32   `json:"umask"`
	AdditionalGids []uint32 `json:"additionalGids"`
}

type ociCapabilities struct {
	Bounding    []string `json:"bounding"`
	Effective   []string `json:"effective"`
	Inheritable []string `json:"inheritable"`
	Permitted   []string `json:"permitted"`
	Ambient     []string `json:"ambient"`
}

type ociRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options"`
}

type ociLinux struct {
	Namespaces    []ociNamespace `json:"namespaces"`
	Resources     ociResources   `json:"resources"`
	CgroupsPath   string         `json:"cgroupsPath"`
	MaskedPaths   []string       `json:"maskedPaths"`
	ReadonlyPaths []string       `json:"readonlyPaths"`
}

type ociNamespace struct {
	Type string `json:"type"`
}

type ociResources struct {
	Devices []ociDeviceCgroup `json:"devices"`
	Memory  ociMemory         `json:"memory"`
	CPU     ociCPU            `json:"cpu"`
	PIDs    ociPIDs           `json:"pids"`
}

type ociDeviceCgroup struct {
	Allow  bool   `json:"allow"`
	Access string `json:"access"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
	Swap  int64 `json:"swap"`
}

type ociCPU struct {
	Quota  int64  `json:"quota"`
	Period uint64 `json:"period"`
}

type ociPIDs struct {
	Limit int64 `json:"limit"`
}

func buildSpec(config configuration, rootFS, inputs, containerID string) ociSpec {
	const cpuPeriod = uint64(100_000)
	command := append([]string{config.Command}, config.Arguments...)
	emptyCapabilities := []string{}
	return ociSpec{
		OCIVersion: "1.1.0",
		Process: ociProcess{
			Terminal: false,
			User: ociUser{
				UID:            containerUID,
				GID:            containerGID,
				Umask:          0o077,
				AdditionalGids: []uint32{},
			},
			Args: command,
			Env:  environmentVariables(config.Environment),
			Cwd:  "/workspace",
			Capabilities: ociCapabilities{
				Bounding:    emptyCapabilities,
				Effective:   emptyCapabilities,
				Inheritable: emptyCapabilities,
				Permitted:   emptyCapabilities,
				Ambient:     emptyCapabilities,
			},
			Rlimits: []ociRlimit{
				{Type: "RLIMIT_CORE", Hard: 0, Soft: 0},
				{Type: "RLIMIT_FSIZE", Hard: uint64(config.DiskBytes), Soft: uint64(config.DiskBytes)},
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
				{Type: "RLIMIT_NPROC", Hard: uint64(config.PIDs), Soft: uint64(config.PIDs)},
			},
			NoNewPrivileges: true,
		},
		Root:     ociRoot{Path: rootFS, Readonly: true},
		Hostname: "provenance",
		Mounts: []ociMount{
			{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=0755", "size=65536"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/workspace", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "mode=0700", "uid=" + strconv.FormatUint(uint64(containerUID), 10), "gid=" + strconv.FormatUint(uint64(containerGID), 10), "size=" + strconv.FormatInt(config.DiskBytes, 10)}},
			{Destination: "/inputs", Type: "bind", Source: inputs, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}},
		},
		Linux: ociLinux{
			Namespaces: []ociNamespace{{Type: "pid"}, {Type: "network"}, {Type: "mount"}, {Type: "ipc"}, {Type: "uts"}, {Type: "cgroup"}},
			Resources: ociResources{
				Devices: []ociDeviceCgroup{{Allow: false, Access: "rwm"}},
				Memory:  ociMemory{Limit: config.MemoryBytes, Swap: config.MemoryBytes},
				CPU:     ociCPU{Quota: config.CPUMillis * int64(cpuPeriod) / 1000, Period: cpuPeriod},
				PIDs:    ociPIDs{Limit: config.PIDs},
			},
			CgroupsPath: "provenance/" + containerID,
			MaskedPaths: []string{
				"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/firmware",
			},
			ReadonlyPaths: []string{
				"/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
			},
		},
	}
}
