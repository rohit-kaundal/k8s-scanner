package main

import (
	"os"

	"k8s-scanner/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	if err := cmd.Execute(); err != nil {
		logrus.WithError(err).Fatal("Failed to execute command")
	}
}