//go:build js && wasm

package main

import (
	"errors"
	"fmt"
	"syscall/js"
)

// await blocks the calling goroutine until p settles and returns its value or
// its rejection as an error. It must run on a goroutine of its own, never on
// the one servicing a synchronous JS callback: that goroutine IS the event
// loop's turn, and the promise cannot settle until it returns. Both handlers
// are released whichever one fires.
func await(p js.Value) (js.Value, error) {
	type outcome struct {
		v   js.Value
		err error
	}
	ch := make(chan outcome, 1)
	onFulfilled := js.FuncOf(func(_ js.Value, args []js.Value) any {
		v := js.Undefined()
		if len(args) > 0 {
			v = args[0]
		}
		ch <- outcome{v: v}
		return nil
	})
	onRejected := js.FuncOf(func(_ js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 {
			msg = jsErrorMessage(args[0])
		}
		ch <- outcome{err: errors.New(msg)}
		return nil
	})
	defer onFulfilled.Release()
	defer onRejected.Release()
	p.Call("then", onFulfilled, onRejected)
	out := <-ch
	return out.v, out.err
}

// jsErrorMessage renders a rejection reason: "Name: message" for an Error
// with a specific name, the message alone for a plain Error, String(x) else.
func jsErrorMessage(v js.Value) string {
	if v.Type() == js.TypeObject {
		if m := v.Get("message"); m.Type() == js.TypeString {
			if name := v.Get("name"); name.Type() == js.TypeString && name.String() != "" && name.String() != "Error" {
				return name.String() + ": " + m.String()
			}
			return m.String()
		}
	}
	return js.Global().Get("String").Invoke(v).String()
}

// promisify returns a JS Promise that work settles. work runs on its own
// goroutine so it may await other promises; a panic becomes a rejection
// rather than a dead runtime. The executor releases itself after running —
// syscall/js permits releasing a Func from inside its own invocation.
func promisify(work func() (any, error)) js.Value {
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer executor.Release()
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(jsError("internal", fmt.Sprintf("internal error: %v", r)))
				}
			}()
			v, err := work()
			if err != nil {
				code, msg := userError(err)
				reject.Invoke(jsError(code, msg))
				return
			}
			resolve.Invoke(v)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

// jsError is `new Error(msg)` with a machine-readable .code the page can
// switch on.
func jsError(code, msg string) js.Value {
	e := js.Global().Get("Error").New(msg)
	e.Set("code", code)
	return e
}

// toUint8Array copies b into a fresh Uint8Array.
func toUint8Array(b []byte) js.Value {
	u := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u, b)
	return u
}

// fromUint8Array copies a Uint8Array (or ArrayBuffer) into Go memory.
func fromUint8Array(v js.Value) ([]byte, error) {
	if v.InstanceOf(js.Global().Get("ArrayBuffer")) {
		v = js.Global().Get("Uint8Array").New(v)
	}
	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, errors.New("expected a Uint8Array")
	}
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b, nil
}

// errNoWebCrypto is reported when crypto.subtle is missing — an insecure
// origin, since browsers expose WebCrypto only on https and localhost.
var errNoWebCrypto = errors.New("webcrypto: crypto.subtle is unavailable — signing needs a secure context (https or localhost)")

// subtle returns the SubtleCrypto object or errNoWebCrypto.
func subtle() (js.Value, error) {
	c := js.Global().Get("crypto")
	if c.IsUndefined() || c.IsNull() {
		return js.Undefined(), errNoWebCrypto
	}
	s := c.Get("subtle")
	if s.IsUndefined() || s.IsNull() {
		return js.Undefined(), errNoWebCrypto
	}
	return s, nil
}
