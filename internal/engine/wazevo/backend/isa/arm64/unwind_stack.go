package arm64

import (
	"encoding/binary"
	"reflect"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

func stackView(sp, top uintptr) []byte {
	l := int(top - sp)
	var stackBuf []byte
	//nolint:staticcheck
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&stackBuf))
	hdr.Data = sp
	hdr.Len = l
	hdr.Cap = l
	return stackBuf
}

// UnwindStack implements wazevo.unwindStack.
func UnwindStack(sp, _, top uintptr, returnAddresses []uintptr) []uintptr {
	stackBuf := stackView(sp, top)
	l := len(stackBuf)

	for i := uint64(0); i < uint64(l); {
		//       (high address)
		//    +-----------------+
		//    |     .......     |
		//    |      ret Y      |  <----+
		//    |     .......     |       |
		//    |      ret 0      |       |
		//    |      arg X      |       |  size_of_arg_ret
		//    |     .......     |       |
		//    |      arg 1      |       |
		//    |      arg 0      |  <----+
		//    | size_of_arg_ret |
		//    |  ReturnAddress  |
		//    +-----------------+ <----+
		//    |   ...........   |      |
		//    |   spill slot M  |      |
		//    |   ............  |      |
		//    |   spill slot 2  |      |
		//    |   spill slot 1  |      | frame size
		//    |   spill slot 1  |      |
		//    |   clobbered N   |      |
		//    |   ............  |      |
		//    |   clobbered 0   | <----+
		//    |     xxxxxx      |  ;; unused space to make it 16-byte aligned.
		//    |   frame_size    |
		//    +-----------------+ <---- SP
		//       (low address)

		frameSize := binary.LittleEndian.Uint64(stackBuf[i:])
		i += frameSize +
			16 // frame size + aligned space.
		retAddr := binary.LittleEndian.Uint64(stackBuf[i:])
		i += 8 // ret addr.
		sizeOfArgRet := binary.LittleEndian.Uint64(stackBuf[i:])
		i += 8 + sizeOfArgRet
		returnAddresses = append(returnAddresses, uintptr(retAddr))
		if len(returnAddresses) == wasmdebug.MaxFrames {
			break
		}
	}
	return returnAddresses
}

// FrameEnd implements wazevo.frameEnd. It returns the address right after the
// compiled function frame that owns sp, i.e. the end of the stack region the
// function itself owns, and returns 0 when the boundary cannot be determined.
//
// A Go call site puts two records on the stack in the same layout UnwindStack
// walks: the Go call's own record, then the record of the function that made
// the call. Each record is a 16-byte header, the body, the return address and
// the size of the caller's argument area:
//
//	+-----------------+ <---- sp
//	|   frame_size    |       ;; body size: go call args (16 bytes of header
//	|   slice_size    |       ;; for the Go call record, the frame for a
//	|      body       |       ;; compiled function record)
//	|  ReturnAddress  |
//	| size_of_arg_ret |
//	|   arg/result    |       ;; the caller's argument area for this call
//	+-----------------+ <---- the next record, or the returned end address
//
// So the two levels are walked exactly like UnwindStack, and the end address is
// the bottom of the stack of the function that made the Go call.
func FrameEnd(sp, _, top uintptr) uintptr {
	if sp == 0 || sp >= top {
		return 0
	}
	stackBuf := stackView(sp, top)
	limit := uint64(len(stackBuf))

	// The Go call record, then the record of the function that made the call.
	i := uint64(0)
	for level := 0; level < 2; level++ {
		if i+32 > limit {
			return 0
		}
		bodySize := binary.LittleEndian.Uint64(stackBuf[i:])
		if bodySize&0xf != 0 { // Bodies are always 16-byte aligned.
			return 0
		}
		sizeOfArgRetSlot := i + bodySize + 24
		if sizeOfArgRetSlot+8 > limit {
			return 0
		}
		sizeOfArgRet := binary.LittleEndian.Uint64(stackBuf[sizeOfArgRetSlot:])
		i = sizeOfArgRetSlot + 8 + sizeOfArgRet
		if i > limit {
			return 0
		}
	}
	return sp + uintptr(i)
}

// GoCallStackView implements wazevo.goCallStackView.
func GoCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	//                  (high address)
	//              +-----------------+ <----+
	//              |   xxxxxxxxxxx   |      | ;; optional unused space to make it 16-byte aligned.
	//           ^  |  arg[N]/ret[M]  |      |
	// sliceSize |  |  ............   |      | sliceSize
	//           |  |  arg[1]/ret[1]  |      |
	//           v  |  arg[0]/ret[0]  | <----+
	//              |    sliceSize    |
	//              |   frame_size    |
	//              +-----------------+ <---- stackPointerBeforeGoCall
	//                 (low address)
	ptr := unsafe.Pointer(stackPointerBeforeGoCall)
	data := (*uint64)(unsafe.Add(ptr, 16)) // skips the (frame_size, sliceSize).
	size := *(*uint64)(unsafe.Add(ptr, 8))
	return unsafe.Slice(data, size)
}
