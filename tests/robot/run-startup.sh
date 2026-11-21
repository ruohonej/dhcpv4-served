#!/bin/bash
# Compatibility for callers already inside the mapped namespace.
exec bash tests/robot/run-suite.sh startup_rejection work/startup work/robot-fixture
