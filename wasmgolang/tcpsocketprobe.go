package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpHeaders{
		contextID: contextID,
	}
}

/*func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	//data, err := proxywasm.GetPluginConfiguration()
	//if err != nil {
	//	proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
	//}
	ctx.port = "14001"
	return types.OnPluginStartStatusOK
}*/

type httpHeaders struct {
	types.DefaultHttpContext
	contextID uint32
}

func (ctx *httpHeaders) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	/*if _, err := proxywasm.GetHttpRequestHeader("content-length"); err != nil {
		if err := proxywasm.SendHttpResponse(400, nil, []byte("content must be provided"), -1); err != nil {
			panic(err)
		}
		return types.ActionPause
	}*/

	handleAppProbeTCPSocket()
	return types.ActionPause
}

func handleAppProbeTCPSocket() {
	//d := &net.Dialer{
	//LocalAddr: "localhost", // Need to specify?
	//	Timeout: 1 * time.Second,
	//}
	proxywasm.LogCritical("handleAppProbeTCPSocket")
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:3306"))
	proxywasm.LogCriticalf("handleAppProbeTCPSocket after dial %v", err)
	if err != nil {
		if err := proxywasm.SendHttpResponse(http.StatusInternalServerError, nil, []byte("content must be provided"), -1); err != nil {
			panic(err)
		}
	} else {
		conn.Close()
		if err := proxywasm.SendHttpResponse(http.StatusOK, nil, []byte("content must be provided"), -1); err != nil {
			panic(err)
		}
	}
}

// Override types.DefaultHttpContext.
func (ctx *httpHeaders) OnHttpStreamDone() {
	proxywasm.LogInfof("%d finished", ctx.contextID)
}
