// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ptrace

import (
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

var (
	// precompiledProgramNames is the sorted list of all precompiled program
	// names. It is populated at generation time and used by `ListPrecompiled`.
	precompiledProgramNames = []string{
	"ptrace_stub_allow",
	"ptrace_stub_kill_thread",
	"ptrace_stub_return_error",
	}
)

// PrecompilationDisabledAtBuildTime is a constant that is used to
// indicate that precompilation was disabled at build time.
const PrecompilationDisabledAtBuildTime = false

// GetPrecompiled returns the precompiled program for the given name,
// and whether that program name exists.
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool) {
	switch programName {
	case "ptrace_stub_allow":
		return precompiledseccomp.Program{
				Name: "ptrace_stub_allow",
				Bytecode32: []uint32{
					0x00000020,
					0x00000004,
					0x01000015,
					0xc00000b7,
					0x00000020,
					0x00000000,
					0x00000006,
					0x7fff0000,
				},
				VarOffsets: map[string][]int{
				},
			}, true
	case "ptrace_stub_kill_thread":
		return precompiledseccomp.Program{
				Name: "ptrace_stub_kill_thread",
				Bytecode32: []uint32{
					0x00000020,
					0x00000004,
					0x20000015,
					0xc00000b7,
					0x00000020,
					0x00000000,
					0x01000035,
					0x000000a7,
					0x02010025,
					0x000000a7,
					0x12090015,
					0x00000081,
					0x110c0015,
					0x000000dc,
					0x00000020,
					0x00000010,
					0x19000015,
					0x00000001,
					0x00000020,
					0x00000014,
					0x17000015,
					0x00000000,
					0x00000020,
					0x00000018,
					0x15000015,
					0x00000009,
					0x00000020,
					0x0000001c,
					0x13120015,
					0x00000000,
					0x00000020,
					0x00000018,
					0x11000015,
					0x00000013,
					0x00000020,
					0x0000001c,
					0x0f0e0015,
					0x00000000,
					0x00000020,
					0x00000014,
					0x0d000015,
					0x00000000,
					0x00000020,
					0x00000010,
					0x000a0015,
					0x00000409,
					0x0a090015,
					0x00012f00,
					0x01000035,
					0x000000d7,
					0x07040025,
					0x000000d7,
					0x01000035,
					0x000000ac,
					0x05010025,
					0x000000ac,
					0x05040015,
					0x0000005d,
					0x04030015,
					0x000000ad,
					0x01000035,
					0x00000104,
					0x02010015,
					0x00000104,
					0x01000015,
					0x000000de,
					0x00000006,
					0x7fff0000,
					0x00000006,
					0x00000000,
				},
				VarOffsets: map[string][]int{
				},
			}, true
	case "ptrace_stub_return_error":
		return precompiledseccomp.Program{
				Name: "ptrace_stub_return_error",
				Bytecode32: []uint32{
					0x00000020,
					0x00000004,
					0x20000015,
					0xc00000b7,
					0x00000020,
					0x00000000,
					0x01000035,
					0x000000a7,
					0x02010025,
					0x000000a7,
					0x12090015,
					0x00000081,
					0x110c0015,
					0x000000dc,
					0x00000020,
					0x00000010,
					0x19000015,
					0x00000001,
					0x00000020,
					0x00000014,
					0x17000015,
					0x00000000,
					0x00000020,
					0x00000018,
					0x15000015,
					0x00000009,
					0x00000020,
					0x0000001c,
					0x13120015,
					0x00000000,
					0x00000020,
					0x00000018,
					0x11000015,
					0x00000013,
					0x00000020,
					0x0000001c,
					0x0f0e0015,
					0x00000000,
					0x00000020,
					0x00000014,
					0x0d000015,
					0x00000000,
					0x00000020,
					0x00000010,
					0x000a0015,
					0x00000409,
					0x0a090015,
					0x00012f00,
					0x01000035,
					0x000000d7,
					0x07040025,
					0x000000d7,
					0x01000035,
					0x000000ac,
					0x05010025,
					0x000000ac,
					0x05040015,
					0x0000005d,
					0x04030015,
					0x000000ad,
					0x01000035,
					0x00000104,
					0x02010015,
					0x00000104,
					0x01000015,
					0x000000de,
					0x00000006,
					0x7fff0000,
					0x00000006,
					0x00050000,
				},
				VarOffsets: map[string][]int{
				},
			}, true
	}
	return precompiledseccomp.Program{}, false
}

// ListPrecompiled returns a list of all registered program names.
func ListPrecompiled() []string {
	return append([]string(nil), precompiledProgramNames...)
}

