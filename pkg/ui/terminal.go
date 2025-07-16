package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
)

// TerminalUI provides enhanced terminal output with progress bars and typing effects
type TerminalUI struct {
	quietMode bool
}

// NewTerminalUI creates a new terminal UI instance
func NewTerminalUI(quiet bool) *TerminalUI {
	return &TerminalUI{
		quietMode: quiet,
	}
}

// TypeWriter simulates typing effect for text output
func (ui *TerminalUI) TypeWriter(text string, delay time.Duration) {
	if ui.quietMode {
		fmt.Print(text)
		return
	}

	for _, char := range text {
		fmt.Print(string(char))
		if char != ' ' && char != '\n' {
			time.Sleep(delay)
		}
	}
}

// TypeWriterLine outputs text with typing effect and adds newline
func (ui *TerminalUI) TypeWriterLine(text string, delay time.Duration) {
	ui.TypeWriter(text, delay)
	fmt.Println()
}

// ShowBanner displays the application banner with typing effect
func (ui *TerminalUI) ShowBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    Kubernetes Security Scanner                                ║
║                     CIS Benchmark & NIST SP 800-190                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`
	ui.TypeWriterLine(banner, 2*time.Millisecond)
}

// ShowScanStart displays scan initialization message
func (ui *TerminalUI) ShowScanStart(standards []string, namespace string) {
	ui.TypeWriterLine("🚀 Initializing security scan...", 20*time.Millisecond)
	
	standardsStr := strings.Join(standards, ", ")
	ui.TypeWriterLine(fmt.Sprintf("📋 Standards: %s", strings.ToUpper(standardsStr)), 15*time.Millisecond)
	
	if namespace != "" {
		ui.TypeWriterLine(fmt.Sprintf("🎯 Namespace: %s", namespace), 15*time.Millisecond)
	} else {
		ui.TypeWriterLine("🎯 Scope: All namespaces", 15*time.Millisecond)
	}
	
	ui.TypeWriterLine("", 0)
}

// CreateProgressBar creates a new progress bar with custom styling
func (ui *TerminalUI) CreateProgressBar(max int, description string) *progressbar.ProgressBar {
	if ui.quietMode {
		return progressbar.NewOptions(max,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionSetDescription(description),
			progressbar.OptionSetVisibility(false),
		)
	}

	return progressbar.NewOptions(max,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "▐",
			BarEnd:        "▌",
		}),
		progressbar.OptionShowBytes(false),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprintf(os.Stderr, "\n")
		}),
	)
}

// ShowScanComplete displays scan completion message
func (ui *TerminalUI) ShowScanComplete(findings int, duration time.Duration) {
	ui.TypeWriterLine("", 0)
	ui.TypeWriterLine("✅ Scan completed successfully!", 20*time.Millisecond)
	ui.TypeWriterLine(fmt.Sprintf("📊 Total findings: %d", findings), 15*time.Millisecond)
	ui.TypeWriterLine(fmt.Sprintf("⏱️  Duration: %v", duration.Round(time.Millisecond)), 15*time.Millisecond)
	ui.TypeWriterLine("", 0)
}

// ShowError displays error message with typing effect
func (ui *TerminalUI) ShowError(message string) {
	ui.TypeWriterLine(fmt.Sprintf("❌ Error: %s", message), 20*time.Millisecond)
}

// ShowWarning displays warning message with typing effect
func (ui *TerminalUI) ShowWarning(message string) {
	ui.TypeWriterLine(fmt.Sprintf("⚠️  Warning: %s", message), 20*time.Millisecond)
}

// ShowInfo displays info message with typing effect
func (ui *TerminalUI) ShowInfo(message string) {
	ui.TypeWriterLine(fmt.Sprintf("ℹ️  %s", message), 15*time.Millisecond)
}

// ShowStep displays a step in the process
func (ui *TerminalUI) ShowStep(step string) {
	ui.TypeWriterLine(fmt.Sprintf("🔄 %s", step), 15*time.Millisecond)
}