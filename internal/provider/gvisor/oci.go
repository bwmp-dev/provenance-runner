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
	Devices       []ociDevice    `json:"devices"`
	Resources     ociResources   `json:"resources"`
	CgroupsPath   string         `json:"cgroupsPath"`
	MaskedPaths   []string       `json:"maskedPaths"`
	ReadonlyPaths []string       `json:"readonlyPaths"`
}

type ociDevice struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Major    int64  `json:"major"`
	Minor    int64  `json:"minor"`
	FileMode uint32 `json:"fileMode"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
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
	Type   string `json:"type,omitempty"`
	Major  *int64 `json:"major,omitempty"`
	Minor  *int64 `json:"minor,omitempty"`
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
	devices := standardDevices()
	deviceRules := []ociDeviceCgroup{{Allow: false, Access: "rwm"}}
	for _, device := range devices {
		major, minor := device.Major, device.Minor
		deviceRules = append(deviceRules, ociDeviceCgroup{Allow: true, Type: device.Type, Major: &major, Minor: &minor, Access: "rwm"})
	}
	workspaceBytes := (config.DiskBytes + 1) / 2
	temporaryBytes := config.DiskBytes - workspaceBytes
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
			{Destination: "/workspace", Type: "tmpfs", Source: "tmpfs", Options: writableTmpfsOptions(workspaceBytes)},
			{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: writableTmpfsOptions(temporaryBytes)},
			{Destination: "/inputs", Type: "bind", Source: inputs, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}},
		},
		Linux: ociLinux{
			Namespaces: []ociNamespace{{Type: "pid"}, {Type: "network"}, {Type: "mount"}, {Type: "ipc"}, {Type: "uts"}, {Type: "cgroup"}},
			Devices:    devices,
			Resources: ociResources{
				Devices: deviceRules,
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

func standardDevices() []ociDevice {
	return []ociDevice{
		{Path: "/dev/null", Type: "c", Major: 1, Minor: 3, FileMode: 0o666},
		{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5, FileMode: 0o666},
		{Path: "/dev/full", Type: "c", Major: 1, Minor: 7, FileMode: 0o666},
		{Path: "/dev/random", Type: "c", Major: 1, Minor: 8, FileMode: 0o666},
		{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9, FileMode: 0o666},
		{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0, FileMode: 0o666},
	}
}

func writableTmpfsOptions(size int64) []string {
	return []string{
		"nosuid",
		"nodev",
		"mode=0700",
		"uid=" + strconv.FormatUint(uint64(containerUID), 10),
		"gid=" + strconv.FormatUint(uint64(containerGID), 10),
		"size=" + strconv.FormatInt(size, 10),
	}
}
