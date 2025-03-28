package main

import (
	"strings"
)

// splitAndTrim разделяет строку по разделителю и обрезает пробелы
func splitAndTrim(s string, sep string) []string {
	if s == "" {
		return nil
	}
	
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	return result
} 