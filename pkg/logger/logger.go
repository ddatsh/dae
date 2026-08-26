/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"time"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// 设置全局时区
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.UTC
	}
	time.Local = loc
}

func SetLogger(log *logrus.Logger, logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&prefixed.TextFormatter{
		DisableTimestamp: disableTimestamp,
		ForceColors:      true,
		FullTimestamp:    true,
		ForceFormatting:  true,
		TimestampFormat:  "15:04:05",
	})
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}
}
