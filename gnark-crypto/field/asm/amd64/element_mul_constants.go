// Copyright 2020 ConsenSys Software Inc.
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

package amd64

func (f *FFAmd64) generateMulBy3() {
	f.Comment("MulBy3(x *Element)")
	stackSize := f.StackSize(1+f.NbWords*2, 0, 0)
	registers := f.FnHeader("MulBy3", stackSize, 8)
	defer f.AssertCleanStack(stackSize, 0)
	// registers
	x := registers.Pop()
	t := registers.PopN(f.NbWords)

	f.MOVQ("x+0(FP)", x)

	f.Mov(x, t)
	f.Add(t, t)

	f.Reduce(&registers, t)
	f.Add(x, t)
	f.Reduce(&registers, t)
	f.Mov(t, x)

	f.RET()
}

func (f *FFAmd64) generateMulBy5() {
	f.Comment("MulBy5(x *Element)")
	stackSize := f.StackSize(1+f.NbWords*2, 0, 0)
	registers := f.FnHeader("MulBy5", stackSize, 8)
	defer f.AssertCleanStack(stackSize, 0)

	// registers
	x := registers.Pop()
	t := registers.PopN(f.NbWords)

	f.MOVQ("x+0(FP)", x)

	f.Mov(x, t)
	f.Add(t, t)
	f.Reduce(&registers, t)
	f.Add(t, t)
	f.Reduce(&registers, t)
	f.Add(x, t)
	f.Reduce(&registers, t)

	f.Mov(t, x)
	f.RET()
}
