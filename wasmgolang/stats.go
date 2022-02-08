package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

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
	port string
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{port: ctx.port}
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
	}
	ctx.port = string(data)
	return types.OnPluginStartStatusOK
}

type httpContext struct {
	types.DefaultHttpContext
	port string
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	if _, err := proxywasm.GetHttpRequestHeader("content-length"); err != nil {
		if err := proxywasm.SendHttpResponse(400, nil, []byte("content must be provided"), -1); err != nil {
			panic(err)
		}
		return types.ActionPause
	}

	ctx.handleAppProbeTCPSocket()
	return types.ActionPause
}

func (ctx *httpContext) handleAppProbeTCPSocket() {
	d := &net.Dialer{
		//LocalAddr: "localhost", // Need to specify?
		Timeout: 1 * time.Second,
	}
	// TODO(jaellio): change from local host and use pod id
	conn, err := d.Dial("tcp", fmt.Sprintf("localhost:%s", ctx.port))
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
