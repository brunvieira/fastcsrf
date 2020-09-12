# Fast CSRF

[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/brunvieira/fastcsrf)

Fast CSRF is a port of [echo](https://github.com/labstack/echo)'s CSRF middleware but for the fasthttp
Library.

# Usage

```go
type TestHandler struct {
}

func (h *TestHandler) HandleStatusOK(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
}

var testHandler = TestHandler{}
var testStatusOk = testHandler.HandleStatusOK

fasthttp.ListenAndServe(":8080", CSRF(testStatusOk))
```

# License

MIT