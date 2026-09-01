package pluginname

import "strings"

func ValidPaper(value string) bool {
	if len(value) == 0 || len(value) > 64 || !asciiAlphanumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphanumeric(character) && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	switch strings.ToLower(value) {
	case "bukkit", "minecraft", "mojang", "spigot", "paper":
		return false
	default:
		return true
	}
}

func asciiAlphanumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
