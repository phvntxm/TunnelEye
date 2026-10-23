# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Writes broken JSON.

param([string] $OutFile)
[IO.File]::WriteAllText($OutFile, '{"module": "fixture-badjson", ')
