# Fast CSRF

[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/brunvieira/fastcsrf)

Fast CSRF is a port of [echo](https://github.com/labstack/echo)'s CSRF middleware but for the fasthttp
Library.

# Usage

```go
package main

import (
    "github.com/brunvieira/fastcsrf"
    "github.com/valyala/fasthttp"    
)

func testStatusOk(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
}
func main() {
    // use with default values
    fasthttp.ListenAndServe(":8080", CSRF(testStatusOk))
    
    // use with custom config
    config := CSRFConfig{}
    config.TokenLength = 64
    config.TokenLookup = "form:csrfToken" // now it will look for the csrfToken field in the post/put form. See docs for options
    config.CookieName = "fastcsrf"
    config.CookieDomain = "github.com"
    config.CookiePath = "/brunvieira"
    config.CookieMaxAge = 24 * 60 * 1000
    config.CookieSecure = true
    config.CookieHTTPOnly = true
   
    fasthttp.ListenAndServe(":8081", CSRFWithConfig(c)(testStatusOk))
} 

```

# License

MIT