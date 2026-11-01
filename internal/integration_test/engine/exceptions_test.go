package adhoc

// Exception handling integration tests for the interpreter engine.
//
// Background: these tests cover the Emscripten/pdfium-style EH pattern where
// exceptions propagate across multiple function call frames, each of which may
// have its own try_table handler (catch_all_ref + throw_ref cleanup pattern).
//
// The interpreter bug fixed here: when an inner callWithUnwind (e.g., in a
// "child" function) recovered a *thrownException whose matching try_table
// handler belonged to an outer (grandparent) callNativeFunc invocation,
// doRestore incorrectly restored grandparent's frame while still inside
// child's callNativeFunc.  The child then started executing grandparent's
// body, eventually calling popTryHandler on an already-empty slice and
// panicking with "slice bounds out of range [:-1]".
//
// The fix: callWithUnwind only handles handlers whose savedFrames length is >=
// the caller's frame count (i.e., handlers set up at the current or deeper
// call depth).  Handlers from outer invocations are re-panicked so that the
// correct outer callWithUnwind catches them.

import (
	"context"
	_ "embed"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/internal/wasmruntime"
)

//go:embed testdata/eh_cross_callnative.wasm
var ehCrossCallnativeWasm []byte

//go:embed testdata/eh_pdfium.wasm
var ehPdfiumWasm []byte

//go:embed testdata/eh_throw_ref_null.wasm
var ehThrowRefNullWasm []byte

//go:embed testdata/eh_br_orphan.wasm
var ehBrOrphanWasm []byte

//go:embed testdata/eh_br_stale_handler.wasm
var ehBrStaleHandlerWasm []byte

//go:embed testdata/eh_locals_corrupted.wasm
var ehLocalsCorruptedWasm []byte

//go:embed testdata/eh_locals_nested_nocatch.wasm
var ehLocalsNestedNocatchWasm []byte

//go:embed testdata/eh_locals_nested_catch.wasm
var ehLocalsNestedCatchWasm []byte

//go:embed testdata/eh_locals_cross_func.wasm
var ehLocalsCrossFuncWasm []byte

//go:embed testdata/eh_br_own_label.wasm
var ehBrOwnLabelWasm []byte

//go:embed testdata/eh_catch_outside.wasm
var ehCatchOutsideWasm []byte

// TestExceptionHandlingInterpreter runs EH tests only for the interpreter.
func TestExceptionHandlingInterpreter(t *testing.T) {
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runEHTests(t, cfg)
}

// TestExceptionHandlingCompiler runs EH tests for the compiler where supported.
func TestExceptionHandlingCompiler(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runEHTests(t, cfg)
}

func runEHTests(t *testing.T, cfg wazero.RuntimeConfig) {
	t.Run("cross_frame_catch", func(t *testing.T) {
		testEHCrossFrameCatch(t, cfg)
	})
	t.Run("pdfium_rethrow_pattern", func(t *testing.T) {
		testEHPdfiumRethrow(t, cfg)
	})
	t.Run("throw_ref_null", func(t *testing.T) {
		testThrowRefNull(t, cfg)
	})
	t.Run("br_exits_try_table", func(t *testing.T) {
		testBrExitsTryTable(t, cfg)
	})
	t.Run("br_stale_handler", func(t *testing.T) {
		testBrStaleHandler(t, cfg)
	})
	t.Run("locals_corrupted", func(t *testing.T) {
		testEHLocalsCorrupted(t, cfg)
	})
	t.Run("locals_nested_nocatch", func(t *testing.T) {
		testEHLocalsNestedNocatch(t, cfg)
	})
	t.Run("locals_nested_catch", func(t *testing.T) {
		testEHLocalsNestedCatch(t, cfg)
	})
	t.Run("locals_cross_func", func(t *testing.T) {
		testEHLocalsCrossFunc(t, cfg)
	})
	t.Run("br_own_label", func(t *testing.T) {
		testEHBrOwnLabel(t, cfg)
	})
	t.Run("catch_outside", func(t *testing.T) {
		testEHCatchOutside(t, cfg)
	})
}

// testEHCrossFrameCatch is the core reproducer for the interpreter bug:
// try_table in grandparent, exception thrown in grandchild,
// propagating through child which has no handler of its own.
// The grandparent's handler must catch it correctly.
func testEHCrossFrameCatch(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehCrossCallnativeWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// grandparent has a try_table, calls child, child calls grandchild which throws.
	// Grandparent's handler must catch via cross-frame propagation.
	res, err := mod.ExportedFunction("test_cross_frame_catch").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))

	// Rethrow pattern: child has catch_all_ref + throw_ref, grandparent catches the rethrow.
	res, err = mod.ExportedFunction("test_rethrow_cross_frame").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(2), api.DecodeI32(res[0]))
}

// testEHPdfiumRethrow tests the Emscripten destructor-cleanup pattern:
// catch_all_ref captures the exnref, runs cleanup, then rethrows via throw_ref.
// This pattern appears in pdfium.wasm for C++ exception handling.
func testEHPdfiumRethrow(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehPdfiumWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// One-level: leaf throws, level2 catches + rethrows, outer catches.
	res, err := mod.ExportedFunction("test_one_level_rethrow").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))

	// Two-level: throw → catch_all_ref + throw_ref → catch_all_ref + throw_ref → catch.
	res, err = mod.ExportedFunction("test_two_level_rethrow").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// testThrowRefNull verifies that throw_ref on a null exnref traps with
// "null reference" (not "unreachable"). This was a bug where the interpreter
// used ErrRuntimeUnreachable instead of ErrRuntimeNullReference.
func testThrowRefNull(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehThrowRefNullWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// Call with null exnref (0) — should trap as "null reference".
	_, err = mod.ExportedFunction("throw_ref_null").Call(ctx, 0)
	require.ErrorIs(t, err, wasmruntime.ErrRuntimeNullReference)
}

// testBrExitsTryTable verifies that br/br_if that exits a try_table block
// correctly pops the try handler. Without the fix, orphaned handlers would
// cause a popTryHandler underflow panic ("slice bounds out of range [:-1]").
func testBrExitsTryTable(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehBrOrphanWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// The function calls loop_with_try (which exits try_table via br_if),
	// then catches a throw in its own try_table. Should return 1.
	res, err := mod.ExportedFunction("test").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// testBrStaleHandler verifies that br exiting a try_table pops the handler
// so it doesn't interfere with later exception dispatch. Without the fix,
// the stale handler from try_table A incorrectly catches a throw meant for
// the outer handler, returning 99 instead of 1.
func testBrStaleHandler(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehBrStaleHandlerWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// Without fix: stale handler A catches $tag1 -> wrong checkpoint restore.
	// With fix: outer handler catches $tag1 -> returns 1.
	res, err := mod.ExportedFunction("test").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// testEHLocalsCorrupted verifies that locals mutated inside a try_table body
// retain their throw-time values when an exception is caught (issue #2503).
func testEHLocalsCorrupted(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehLocalsCorruptedWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// f() sets flag=1, enters try_table, sets flag=0, then throws.
	// The handler reads flag — must be 0 (throw-time), not 1 (entry-time).
	res, err := mod.ExportedFunction("f").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), api.DecodeI32(res[0]))
}

// testEHLocalsNestedNocatch verifies that a try_table with no catch clauses
// nested inside one with catch clauses doesn't break locals tracking.
func testEHLocalsNestedNocatch(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehLocalsNestedNocatchWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// The inner try_table (no catch) must not break the outer try body's
	// locals save-area tracking. flag must be 0 at throw time.
	res, err := mod.ExportedFunction("f").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), api.DecodeI32(res[0]))
}

// testEHLocalsNestedCatch verifies that nested try_tables in the same function
// share the locals save area so an outer handler sees throw-time local values
// modified inside the inner try body.
func testEHLocalsNestedCatch(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehLocalsNestedCatchWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// Inner try catches $t2, but thrower throws $t1 → outer catches.
	// flag was set to 0 inside the inner body; outer must see 0.
	res, err := mod.ExportedFunction("f").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), api.DecodeI32(res[0]))
}

// testEHLocalsCrossFunc verifies cross-function try_table nesting: function A
// has a try_table and calls B which also has a try_table. B throws an exception
// caught by A. A's handler must see A's locals, not B's.
func testEHLocalsCrossFunc(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehLocalsCrossFuncWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// A sets flag=0 inside its try body, then calls B which throws.
	// A's handler must see flag=0 (A's throw-time value).
	res, err := mod.ExportedFunction("f").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), api.DecodeI32(res[0]))
}

// testEHBrOwnLabel verifies that br to a try_table's own label pops its handler.
func testEHBrOwnLabel(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehBrOwnLabelWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	res, err := mod.ExportedFunction("run").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// testEHCatchOutside verifies that a catch clause jumping outside an enclosing
// try_table pops that try_table's handler.
func testEHCatchOutside(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehCatchOutsideWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	res, err := mod.ExportedFunction("run").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// tryTableRecursionWasmHex is the reproducer of issue #2573: a function that
// recurses through a try_table that has a catch_all clause.
//
//	(module
//	  (func $rec (export "rec") (param i32) (result i32)
//	    (if (i32.eqz (local.get 0)) (then (return (i32.const 0))))
//	    (block $L (result i32)
//	      (block $H
//	        (try_table (result i32) (catch_all $H)
//	          (call $rec (i32.sub (local.get 0) (i32.const 1))))
//	        (br $L))
//	      (i32.const -1))))
const tryTableRecursionWasmHex = "0061736d0100000001060160017f017f030201000707010372656300000a24012200200045044041000f0b027f02401f7f010200200041016b10000b0c010b417f0b0b"

// TestExceptionHandlingTryTableStackUsage verifies that entering a try_table
// saves only the current frame, not the whole wasm stack. Before the fix, each
// active handler retained a full-stack copy, so recursion through a try_table
// allocated O(depth × stack): 2000 levels used over 200MB and bypassed
// callStackCeiling.
func TestExceptionHandlingTryTableStackUsage(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}

	bin, err := hex.DecodeString(tryTableRecursionWasmHex)
	require.NoError(t, err)

	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, bin, wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	const depth = 2000
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	res, err := mod.ExportedFunction("rec").Call(ctx, depth)
	require.NoError(t, err)
	require.Equal(t, int32(0), api.DecodeI32(res[0]))

	runtime.ReadMemStats(&after)

	// Each active handler retains one frame copy (a few dozen bytes) plus the
	// fixed register save area (~1KiB), so this stays linear in depth at around
	// 5KiB per level. A whole-stack copy per level needs over 200MiB for the same
	// program, so the bound has room to spare without being flaky.
	const maxAllocated = 32 << 20 // 32MiB
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > maxAllocated {
		t.Fatalf("recursing %d try_tables allocated %d bytes, want at most %d",
			depth, allocated, maxAllocated)
	}
}

// TestExceptionHandlingTryTableAfterStackGrowth verifies that catching still
// works when the wasm stack grew after the handler was set up. The handler
// copies the frame to the heap but leaves the caller frames in place, so
// restoring has to switch back to the stack the checkpoint was taken on.
func TestExceptionHandlingTryTableAfterStackGrowth(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}

	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, buildEHStackGrowthModule(),
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// Deep enough that the initial 10KB stack has to grow several times
	// between entering the try_table and throwing.
	res, err := mod.ExportedFunction("run").Call(ctx, 2000)
	require.NoError(t, err)
	require.Equal(t, int32(42), api.DecodeI32(res[0]))
}

// buildEHStackGrowthModule builds a module whose exported "run" enters a
// try_table and then recurses 2000 levels deep before throwing, so the
// exception is caught by a handler that was set up on a smaller stack:
//
//	(tag $t)
//	(func $deep (param i32)
//	  (if (local.get 0)
//	    (then (call $deep (i32.sub (local.get 0) (i32.const 1))) (return)))
//	  (throw $t))
//	(func (export "run") (param i32) (result i32)
//	  (block
//	    (try_table (catch_all 0)
//	      (call $deep (local.get 0))))
//	  (i32.const 42))
func buildEHStackGrowthModule() []byte {
	m := &wasm.Module{
		// Type 0: (i32) -> (), type 1: (i32) -> (i32), type 2: () -> () for the tag.
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeI32}},
			{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}},
			{},
		},
		TagSection:      []wasm.Tag{{Type: 2}},
		FunctionSection: []wasm.Index{0, 1},
		ExportSection: []wasm.Export{
			{Type: wasm.ExternTypeFunc, Name: "run", Index: 1},
		},
	}

	// $deep: local.get 0; if void; call $deep(0 - 1); return; end; throw 0.
	m.CodeSection = append(m.CodeSection, wasm.Code{Body: []byte{
		wasm.OpcodeLocalGet, 0,
		wasm.OpcodeIf, 0x40, // void
		wasm.OpcodeLocalGet, 0,
		wasm.OpcodeI32Const, 0x01,
		wasm.OpcodeI32Sub,
		wasm.OpcodeCall, 0,
		wasm.OpcodeReturn,
		wasm.OpcodeEnd,      // end if
		wasm.OpcodeThrow, 0, // throw tag 0
		wasm.OpcodeEnd, // end function
	}})

	// run: block; try_table (catch_all 0); local.get 0; call $deep; end; end;
	// i32.const 42; end.
	m.CodeSection = append(m.CodeSection, wasm.Code{Body: []byte{
		wasm.OpcodeBlock, 0x40, // void
		wasm.OpcodeTryTable, 0x40, // void
		1,                      // catch count
		wasm.CatchKindCatchAll, // catch_all
		0,                      // label 0 (the enclosing block)
		wasm.OpcodeLocalGet, 0,
		wasm.OpcodeCall, 0, // $deep
		wasm.OpcodeEnd, // end try_table
		wasm.OpcodeEnd, // end block
		wasm.OpcodeI32Const, 42,
		wasm.OpcodeEnd, // end function
	}})

	return encodeModule(m)
}

// TestExceptionHandlingCompilationCache verifies that
// the compilation cache round-trips the catchClauseTable correctly.
func TestExceptionHandlingCompilationCache(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}

	cacheDir := t.TempDir()

	for _, tc := range []struct {
		name string
		wasm []byte
		fn   string
		args []uint64
		want int32
	}{
		{"cross_frame_catch", ehCrossCallnativeWasm, "test_cross_frame_catch", nil, 1},
		{"pdfium_rethrow", ehPdfiumWasm, "test_one_level_rethrow", nil, 1},
		{"br_exits_try_table", ehBrOrphanWasm, "test", nil, 1},
		{"br_stale_handler", ehBrStaleHandlerWasm, "test", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// First: compile fresh and populate the file cache.
			cache1, err := wazero.NewCompilationCacheWithDir(cacheDir)
			require.NoError(t, err)
			cfg1 := wazero.NewRuntimeConfigCompiler().
				WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling).
				WithCompilationCache(cache1)
			r1 := wazero.NewRuntimeWithConfig(ctx, cfg1)
			mod1, err := r1.InstantiateWithConfig(ctx, tc.wasm,
				wazero.NewModuleConfig().WithStartFunctions())
			require.NoError(t, err)
			res, err := mod1.ExportedFunction(tc.fn).Call(ctx, tc.args...)
			require.NoError(t, err)
			require.Equal(t, tc.want, api.DecodeI32(res[0]))
			r1.Close(ctx)
			cache1.Close(ctx)

			// Second: new runtime loading from file cache.
			// Without the fix, catchClauseTable is empty → panic.
			cache2, err := wazero.NewCompilationCacheWithDir(cacheDir)
			require.NoError(t, err)
			cfg2 := wazero.NewRuntimeConfigCompiler().
				WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling).
				WithCompilationCache(cache2)
			r2 := wazero.NewRuntimeWithConfig(ctx, cfg2)
			mod2, err := r2.InstantiateWithConfig(ctx, tc.wasm,
				wazero.NewModuleConfig().WithStartFunctions())
			require.NoError(t, err)
			res, err = mod2.ExportedFunction(tc.fn).Call(ctx, tc.args...)
			require.NoError(t, err)
			require.Equal(t, tc.want, api.DecodeI32(res[0]))
			r2.Close(ctx)
			cache2.Close(ctx)
		})
	}
}
