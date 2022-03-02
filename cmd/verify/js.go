//+build js

package main

import (
	"bytes"
	"encoding/json"
	"github.com/inblockio/aqua-verifier-go/api"
	"github.com/inblockio/aqua-verifier-go/verify"
	"syscall/js"
	"sync"
)

var (
	endpoint = "http://localhost:9352/rest.php"
	verbose  = false
)

func exportJSMethods() {
	// find the endpoint and token values (from DOM, set by page?)
	// instantiate an API instance
	a, err := api.NewAPI(endpoint, "")
	if err != nil {
		return
	}
	// promiseConstructor is used to wrap any blocking methods
	promiseConstructor := js.Global().Get("Promise")
	// jsError is used to return any errors
	jsError := js.Global().Get("Error")

	// https://github.com/gptankit/go-wasm/blob/main/gowasmfetch/fetcher/gofetch/gofetch.go:41
	// wrapper to return error as js.Error
	jerr := func (err error) interface{} {
		return jsError.New(err.Error())
	}

	// export API methods
	js.Global().Set("GetHashChainInfo",
		// Wrap the API method in a Promise
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 2 {
				return jsError.New("GetHashChainInfo takes two arguments: id_type, id")
			}
			id_type := args[0].String()
			id := args[1].String()
			handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				resolve := args[0]
				reject := args[1]
				go func() {
					rev, err := a.GetHashChainInfo(id_type, id)
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}
					b, err := json.Marshal(rev)
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}
					resolve.Invoke(string(b))
				}()
				return nil
			})
			return promiseConstructor.New(handler)
		}))

	js.Global().Set("GetRevisionHashes",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return jsError.New("GetRevisionHashes takes onearguments: verification_hash")
			}

			verification_hash := args[0].String()
			handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				resolve := args[0]
				reject := args[1]
				go func() {
					hashes, err := a.GetRevisionHashes(verification_hash)
					if err == nil {
						b, e := json.Marshal(hashes)
						if e != nil {
							reject.Invoke(jerr(err))
							return
						}
						resolve.Invoke(string(b))
						return
					}
					resolve.Invoke(jerr(err))
					return
				}()
				return nil
			})
			return promiseConstructor.New(handler)
		}))
	js.Global().Set("GetRevision",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return jsError.New("GetRevision takes one argument: revision_hash")
			}

			revision := args[0].String()
			handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				resolve := args[0]
				reject := args[1]

				go func() {
					rev, err := a.GetRevision(revision)
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}
					b, err := json.Marshal(rev)
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}
					resolve.Invoke(string(b))
				}()
				return nil
			})
			return promiseConstructor.New(handler)
		}))
	js.Global().Set("GetServerInfo",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				resolve := args[0]
				reject := args[1]
				go func() {
					i, err := a.GetServerInfo()
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}

					b, err := json.Marshal(i)
					if err != nil {
						reject.Invoke(jerr(err))
						return
					}
					resolve.Invoke(string(b))
				}()
				return nil
			})
			return promiseConstructor.New(handler)
		}))
	// export verifier methods
	js.Global().Set("VerifyOfflineData",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 3 {
				return jsError.New("VerifyOfflineData takes three arguments: data (JSON string), doVerifyMerkleProof (bool), depth (int)")
			}
			data := args[0].String()
			doVerifyMerkleProof := args[1].Bool()
			depth := args[2].Int()
			handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				resolve := args[0]
				reject := args[1]
				go func() {
					// revisionData is json encoded string as arg[0]
					d := json.NewDecoder(bytes.NewBufferString(data))
					r := new(api.OfflineRevisionInfo)
					e := d.Decode(r)
					if e != nil {
						reject.Invoke(jerr(e))
						return
					}
					resolve.Invoke(verify.VerifyOfflineData(r, doVerifyMerkleProof, depth))
				}()
				return nil
			})
			return promiseConstructor.New(handler)
		}))
}

func main() {
	exportJSMethods()
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
