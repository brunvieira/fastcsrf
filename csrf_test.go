package fastcsrf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type TestHandler struct {
}

func (h *TestHandler) HandleStatusOK(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (h *TestHandler) HandleApp(ctx *fasthttp.RequestCtx) {
	fmt.Fprint(ctx, "app")
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func startServerOnPort(t *testing.T, port int, h fasthttp.RequestHandler) io.Closer {
	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("cannot start tcp server on port %d: %s", port, err)
	}
	go fasthttp.Serve(ln, h)
	return ln
}

var testHandler = TestHandler{}
var testStatusOk = testHandler.HandleStatusOK

func TestDefaultUsage(t *testing.T) {
	h := CSRF(testStatusOk)

	ln := startServerOnPort(t, 8081, h)
	defer ln.Close()

	req, err := http.NewRequest("GET", "http://localhost:8081", nil)
	assert.Nil(t, err, "Test Then Handler should be able to create a  Request")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode, "Test Then Handler Order should return an OK status")

	cookies := resp.Cookies()
	cookiesMap := make(map[string]interface{}, len(cookies))
	for _, cookie := range cookies {
		cookiesMap[cookie.Name] = cookie.Value
	}
	assert.Len(t, cookiesMap[DefaultCSRFConfig.CookieName], int(DefaultCSRFConfig.TokenLength), "Cookie token must have length equals to config")

}
