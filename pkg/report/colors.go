package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"k8s-scanner/pkg/scanner"
	"github.com/fatih/color"
)

// ColorPrinter handles colored output for terminal
type ColorPrinter struct {
	writer     io.Writer
	colorize   bool
	
	// Color functions
	critical   func(format string, a ...interface{}) string
	high       func(format string, a ...interface{}) string
	medium     func(format string, a ...interface{}) string
	low        func(format string, a ...interface{}) string
	success    func(format string, a ...interface{}) string
	warning    func(format string, a ...interface{}) string
	failed     func(format string, a ...interface{}) string
	info       func(format string, a ...interface{}) string
	title      func(format string, a ...interface{}) string
	subtitle   func(format string, a ...interface{}) string
	bold       func(format string, a ...interface{}) string
	dim        func(format string, a ...interface{}) string
}

// NewColorPrinter creates a new color printer
func NewColorPrinter(writer io.Writer) *ColorPrinter {
	cp := &ColorPrinter{
		writer:   writer,
		colorize: isTerminal(writer),
	}
	
	if cp.colorize {
		cp.critical = color.New(color.FgRed, color.Bold).SprintfFunc()
		cp.high = color.New(color.FgRed).SprintfFunc()
		cp.medium = color.New(color.FgYellow).SprintfFunc()
		cp.low = color.New(color.FgBlue).SprintfFunc()
		cp.success = color.New(color.FgGreen).SprintfFunc()
		cp.warning = color.New(color.FgYellow).SprintfFunc()
		cp.failed = color.New(color.FgRed).SprintfFunc()
		cp.info = color.New(color.FgCyan).SprintfFunc()
		cp.title = color.New(color.FgWhite, color.Bold).SprintfFunc()
		cp.subtitle = color.New(color.FgWhite).SprintfFunc()
		cp.bold = color.New(color.Bold).SprintfFunc()
		cp.dim = color.New(color.Faint).SprintfFunc()
	} else {
		// No-op functions for non-terminal output
		noop := func(format string, a ...interface{}) string { return fmt.Sprintf(format, a...) }
		cp.critical = noop
		cp.high = noop
		cp.medium = noop
		cp.low = noop
		cp.success = noop
		cp.warning = noop
		cp.failed = noop
		cp.info = noop
		cp.title = noop
		cp.subtitle = noop
		cp.bold = noop
		cp.dim = noop
	}
	
	return cp
}

// isTerminal checks if the writer is a terminal
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return f == os.Stdout || f == os.Stderr
	}
	return false
}

// Printf prints formatted text
func (cp *ColorPrinter) Printf(format string, a ...interface{}) {
	fmt.Fprintf(cp.writer, format, a...)
}

// PrintTitle prints a colored title
func (cp *ColorPrinter) PrintTitle(title string) {
	cp.Printf("%s\n", cp.title(title))
}

// PrintSubtitle prints a colored subtitle
func (cp *ColorPrinter) PrintSubtitle(subtitle string) {
	cp.Printf("%s\n", cp.subtitle(subtitle))
}

// PrintSeverity prints text with severity-based color
func (cp *ColorPrinter) PrintSeverity(severity scanner.Severity, format string, a ...interface{}) {
	text := fmt.Sprintf(format, a...)
	
	switch severity {
	case scanner.SeverityCritical:
		cp.Printf("%s", cp.critical(text))
	case scanner.SeverityHigh:
		cp.Printf("%s", cp.high(text))
	case scanner.SeverityMedium:
		cp.Printf("%s", cp.medium(text))
	case scanner.SeverityLow:
		cp.Printf("%s", cp.low(text))
	default:
		cp.Printf("%s", text)
	}
}

// PrintStatus prints text with status-based color
func (cp *ColorPrinter) PrintStatus(status scanner.Status, format string, a ...interface{}) {
	text := fmt.Sprintf(format, a...)
	
	switch status {
	case scanner.StatusPassed:
		cp.Printf("%s", cp.success(text))
	case scanner.StatusFailed:
		cp.Printf("%s", cp.failed(text))
	case scanner.StatusWarning:
		cp.Printf("%s", cp.warning(text))
	default:
		cp.Printf("%s", text)
	}
}

// PrintSuccess prints success message
func (cp *ColorPrinter) PrintSuccess(format string, a ...interface{}) {
	cp.Printf("%s", cp.success(format, a...))
}

// PrintWarning prints warning message
func (cp *ColorPrinter) PrintWarning(format string, a ...interface{}) {
	cp.Printf("%s", cp.warning(format, a...))
}

// PrintError prints error message
func (cp *ColorPrinter) PrintError(format string, a ...interface{}) {
	cp.Printf("%s", cp.failed(format, a...))
}

// PrintInfo prints info message
func (cp *ColorPrinter) PrintInfo(format string, a ...interface{}) {
	cp.Printf("%s", cp.info(format, a...))
}

// PrintBold prints bold text
func (cp *ColorPrinter) PrintBold(format string, a ...interface{}) {
	cp.Printf("%s", cp.bold(format, a...))
}

// PrintDim prints dim text
func (cp *ColorPrinter) PrintDim(format string, a ...interface{}) {
	cp.Printf("%s", cp.dim(format, a...))
}

// GetSeverityIcon returns an icon for the severity
func (cp *ColorPrinter) GetSeverityIcon(severity scanner.Severity) string {
	switch severity {
	case scanner.SeverityCritical:
		return "🔴"
	case scanner.SeverityHigh:
		return "🟠"
	case scanner.SeverityMedium:
		return "🟡"
	case scanner.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

// GetStatusIcon returns an icon for the status
func (cp *ColorPrinter) GetStatusIcon(status scanner.Status) string {
	switch status {
	case scanner.StatusPassed:
		return "✅"
	case scanner.StatusFailed:
		return "❌"
	case scanner.StatusWarning:
		return "⚠️"
	default:
		return "❓"
	}
}

// PrintProgressBar prints a simple progress bar
func (cp *ColorPrinter) PrintProgressBar(current, total int, width int) {
	if total == 0 {
		return
	}
	
	percentage := float64(current) / float64(total)
	filled := int(percentage * float64(width))
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	
	cp.Printf("[%s] %d/%d (%.1f%%)", bar, current, total, percentage*100)
}

// PrintSeparator prints a separator line
func (cp *ColorPrinter) PrintSeparator(char string, length int) {
	cp.Printf("%s\n", strings.Repeat(char, length))
}

// PrintBox prints text in a box
func (cp *ColorPrinter) PrintBox(text string, width int) {
	if width < len(text)+4 {
		width = len(text) + 4
	}
	
	padding := (width - len(text) - 2) / 2
	leftPadding := padding
	rightPadding := width - len(text) - 2 - leftPadding
	
	cp.Printf("┌%s┐\n", strings.Repeat("─", width-2))
	cp.Printf("│%s%s%s│\n", strings.Repeat(" ", leftPadding), text, strings.Repeat(" ", rightPadding))
	cp.Printf("└%s┘\n", strings.Repeat("─", width-2))
}

// SeverityToString converts severity to colored string
func (cp *ColorPrinter) SeverityToString(severity scanner.Severity) string {
	icon := cp.GetSeverityIcon(severity)
	text := strings.ToUpper(string(severity))
	
	switch severity {
	case scanner.SeverityCritical:
		return fmt.Sprintf("%s %s", icon, cp.critical(text))
	case scanner.SeverityHigh:
		return fmt.Sprintf("%s %s", icon, cp.high(text))
	case scanner.SeverityMedium:
		return fmt.Sprintf("%s %s", icon, cp.medium(text))
	case scanner.SeverityLow:
		return fmt.Sprintf("%s %s", icon, cp.low(text))
	default:
		return fmt.Sprintf("%s %s", icon, text)
	}
}

// StatusToString converts status to colored string
func (cp *ColorPrinter) StatusToString(status scanner.Status) string {
	icon := cp.GetStatusIcon(status)
	text := strings.ToUpper(string(status))
	
	switch status {
	case scanner.StatusPassed:
		return fmt.Sprintf("%s %s", icon, cp.success(text))
	case scanner.StatusFailed:
		return fmt.Sprintf("%s %s", icon, cp.failed(text))
	case scanner.StatusWarning:
		return fmt.Sprintf("%s %s", icon, cp.warning(text))
	default:
		return fmt.Sprintf("%s %s", icon, text)
	}
}