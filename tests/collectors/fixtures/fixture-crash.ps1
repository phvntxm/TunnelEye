# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Dies without writing output.

param([string] $OutFile)
[Console]::Error.WriteLine('fatal crash')
exit 3
