//+build js

package main

import (
	"bytes"
	"encoding/json"
	"github.com/inblockio/aqua-verifier-go/api"
	"github.com/inblockio/aqua-verifier-go/verify"
	"syscall/js"
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

	// export API methods
	js.Global().Set("GetHashChainInfo",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			id_type := args[0].String()
			id := args[1].String()
			rev, err := a.GetHashChainInfo(id_type, id)
			if err != nil {
				return err
			}
			return rev
		}))

	js.Global().Set("GetRevisionHashes",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			verification_hash := args[0].String()
			hashes, err := a.GetRevisionHashes(verification_hash)
			if err == nil {
				return hashes
			}
			return err
		}))
	// export verifier methods
	js.Global().Set("VerifyOfflineData",
		js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			// TODO check len args
			// revisionData is json encoded string as arg[0]
			d := json.NewDecoder(bytes.NewBufferString(args[0].String()))
			r := new(api.OfflineRevisionInfo)
			e := d.Decode(r)
			if e != nil {
				return e
			}

			doVerifyMerkleProof := args[1].Bool()
			depth := args[2].Int()

			return verify.VerifyOfflineData(r, doVerifyMerkleProof, depth)
		}))
}
func main() {
	exportJSMethods()
}
