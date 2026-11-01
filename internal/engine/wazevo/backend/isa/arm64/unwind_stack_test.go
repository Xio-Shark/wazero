package arm64

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/testing/require"
)

func TestUnwindStack(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents []uint64
		exp      []uintptr
	}{
		{
			name: "top / with frame and arg-ret-space",
			contents: []uint64{
				32,                 // Frame size: 16 byte-aligned.
				0,                  // reserved.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xaa,               // return address.
				48,                 // size_of_arg_ret: 16-byte aligned.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
			},
			exp: []uintptr{0xaa},
		},
		{
			name: "top / without frame / with arg-ret-space",
			contents: []uint64{
				0,                  // Frame size: 16 byte-aligned.
				0,                  // reserved.
				0xaa,               // return address.
				48,                 // size_of_arg_ret: 16-byte aligned.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
			},
			exp: []uintptr{0xaa},
		},
		{
			name: "top / without frame and arg-ret-space",
			contents: []uint64{
				0,    // Frame size: 16 byte-aligned.
				0,    // reserved.
				0xaa, // return address.
				0,    // size_of_arg_ret: 16-byte aligned.
			},
			exp: []uintptr{0xaa},
		},
		{
			name: "three frames",
			contents: []uint64{
				// ------------ first frame -------------
				32,                 // Frame size: 16 byte-aligned.
				0,                  // reserved.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xffffffffffffffff, // in frame.
				0xaa,               // return address.
				48,                 // size_of_arg_ret: 16-byte aligned.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				// ------------ second frame -----------------
				0,                  // Frame size: 16 byte-aligned.
				0,                  // reserved.
				0xbb,               // return address.
				48,                 // size_of_arg_ret: 16-byte aligned.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				0xeeeeeeeeeeeeeeee, // in arg-ret space.
				// ------------ third frame -----------------
				0,    // Frame size: 16 byte-aligned.
				0,    // reserved.
				0xcc, // return address.
				0,    // size_of_arg_ret: 16-byte aligned.
			},
			exp: []uintptr{0xaa, 0xbb, 0xcc},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, len(tc.contents)*8+1)
			for i, v := range tc.contents {
				binary.LittleEndian.PutUint64(buf[i*8:], v)
			}
			sp := uintptr(unsafe.Pointer(&buf[0]))
			returnAddresses := UnwindStack(sp, 0, uintptr(unsafe.Pointer(&buf[len(buf)-1])), nil)
			require.Equal(t, tc.exp, returnAddresses)
		})
	}
}

// appendRecord appends one frame-like record to buf and returns it. A record is
// laid out as UnwindStack walks it: a 16-byte header, the body, the return
// address, the size of the caller's argument area, then that area itself.
func appendRecord(buf []uint64, bodySize, argRetSize uint64) []uint64 {
	buf = append(buf, bodySize, 0)
	for i := uint64(0); i < bodySize/8; i++ {
		buf = append(buf, 0xffffffffffffffff)
	}
	buf = append(buf, 0xbb) // return address.
	buf = append(buf, argRetSize)
	for i := uint64(0); i < argRetSize/8; i++ {
		buf = append(buf, 0xeeeeeeeeeeeeeeee)
	}
	return buf
}

func TestFrameEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		// goCallBody and goCallArgs are the Go call record's body size (the Go
		// call's argument area) and its own argument area size.
		goCallBody, goCallArgs uint64
		// frameBody and frameArgs are the same for the calling function's frame.
		frameBody, frameArgs uint64
	}{
		{
			name:       "go call record then function frame",
			goCallBody: 16, goCallArgs: 0,
			frameBody: 32, frameArgs: 16,
		},
		{
			name:       "function frame without argument area",
			goCallBody: 16, goCallArgs: 0,
			frameBody: 16, frameArgs: 0,
		},
		{
			name:       "go call with arguments",
			goCallBody: 48, goCallArgs: 32,
			frameBody: 32, frameArgs: 0,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			words := appendRecord(nil, tc.goCallBody, tc.goCallArgs)
			words = appendRecord(words, tc.frameBody, tc.frameArgs)
			raw := make([]byte, len(words)*8)
			for i, v := range words {
				binary.LittleEndian.PutUint64(raw[i*8:], v)
			}
			sp := uintptr(unsafe.Pointer(&raw[0]))
			// FrameEnd treats top as the end of the stack, so that the records
			// fill the whole region.
			top := sp + uintptr(len(raw))
			require.Equal(t, top, FrameEnd(sp, 0, top))
		})
	}

	t.Run("truncated", func(t *testing.T) {
		raw := make([]byte, 8)
		sp := uintptr(unsafe.Pointer(&raw[0]))
		require.Equal(t, uintptr(0), FrameEnd(sp, 0, sp+uintptr(len(raw))))
	})

	t.Run("misaligned frame size", func(t *testing.T) {
		// A second record whose body size is not 16-byte aligned.
		words := appendRecord(nil, 16, 0)
		words = append(words, 24, 0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xbb, 0)
		raw := make([]byte, len(words)*8)
		for i, v := range words {
			binary.LittleEndian.PutUint64(raw[i*8:], v)
		}
		sp := uintptr(unsafe.Pointer(&raw[0]))
		require.Equal(t, uintptr(0), FrameEnd(sp, 0, sp+uintptr(len(raw))))
	})

	t.Run("empty stack", func(t *testing.T) {
		require.Equal(t, uintptr(0), FrameEnd(0, 0, 0))
	})
}
