package fastcsrf

import (
	"crypto/subtle"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type (
	// CSRFConfig defines the config for CSRF middleware
	CSRFConfig struct {
		TokenLength uint8 `yaml:"token_length"`
		// Optional. Default value 32.

		// TokenLookup is a string in the form of "<source>:<key>" that is used
		// to extract token from the request.
		// Optional. Default value "header:X-CSRF-Token".
		// Possible values:
		// - "header:<name>"
		// - "form:<name>"
		// - "query:<name>"
		TokenLookup string `yaml:"token_lookup"`

		// Context key to store generated CSRF token into context.
		// Optional. Default value "csrf".
		ContextKey string `yaml:"context_key"`

		// Name of the CSRF cookie. This cookie will store CSRF token.
		// Optional. Default value "csrf".
		CookieName string `yaml:"cookie_name"`

		// Domain of the CSRF cookie.
		// Optional. Default value none.
		CookieDomain string `yaml:"cookie_domain"`

		// Path of the CSRF cookie.
		// Optional. Default value none.
		CookiePath string `yaml:"cookie_path"`

		// Max age (in seconds) of the CSRF cookie.
		// Optional. Default value 86400 (24hr).
		CookieMaxAge int `yaml:"cookie_max_age"`

		// Indicates if CSRF cookie is secure.
		// Optional. Default value false.
		CookieSecure bool `yaml:"cookie_secure"`

		// Indicates if CSRF cookie is HTTP only.
		// Optional. Default value false.
		CookieHTTPOnly bool `yaml:"cookie_http_only"`
	}

	// csrfTokenExtractor defines a function that takes `fasthttp.RequestCtx` and returns
	// either a token or an error.
	csrfTokenExtractor func(*fasthttp.RequestCtx) ([]byte, error)
)

const (
	// CSRFTokenNotFound defines the error for a Token not found
	CSRFTokenNotFound = "CSRF Token not found"

	// DefaultTokenLookup defines `X-CSRF-TOKEN` as the default token lookup
	DefaultTokenLookup = "X-CSRF-TOKEN"

	// InvalidCSRFToken defines the error for an invalid CSRF token
	InvalidCSRFToken = "Invalid token"
)

var (
	// DefaultCSRFConfig is the default CSRF middleware config.
	DefaultCSRFConfig = CSRFConfig{
		TokenLength:  32,
		TokenLookup:  "header:" + DefaultTokenLookup,
		ContextKey:   "csrf",
		CookieName:   "_csrf",
		CookieMaxAge: 86400,
	}
)

// CSRF returns a Cross-Site Request Forgery (CSRF) middleware.
// See: https://en.wikipedia.org/wiki/Cross-site_request_forgery
func CSRF(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	c := DefaultCSRFConfig
	return CSRFWithConfig(c)(next)
}

// CSRFWithConfig returns a CSRF middleware with config.
// See `CSRF(fasthttp.RequestHandler)`.
func CSRFWithConfig(config CSRFConfig) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if config.TokenLength == 0 {
		config.TokenLength = DefaultCSRFConfig.TokenLength
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultCSRFConfig.TokenLookup
	}
	if config.ContextKey == "" {
		config.ContextKey = DefaultCSRFConfig.ContextKey
	}
	if config.CookieName == "" {
		config.CookieName = DefaultCSRFConfig.CookieName
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = DefaultCSRFConfig.CookieMaxAge
	}
	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := csrfTokenFromHeader(parts[1])
	switch parts[0] {
	case "form":
		extractor = csrfTokenFromForm(parts[1])
	case "query":
		extractor = csrfTokenFromQuery(parts[1])
	}

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {
			req := ctx.Request
			method := req.Header.Method()
			token := req.Header.Cookie(config.CookieName)

			// Generate token
			if sliceIsEmpty(token) {
				token = randomToken(config.TokenLength)
			}

			switch string(method) {
			case fasthttp.MethodGet, fasthttp.MethodHead, fasthttp.MethodOptions, fasthttp.MethodTrace:
			default:
				// Validate token only for requests which are not defined as 'safe' by RFC7231
				clientToken, err := extractor(ctx)
				if err != nil {
					ctx.Error(err.Error(), fasthttp.StatusBadRequest)
					return
				}
				if !validateCSRFToken(token, clientToken) {
					ctx.Error(InvalidCSRFToken, fasthttp.StatusForbidden)
					return
				}
			}

			// Set CSRF cookie
			cookie := new(fasthttp.Cookie)
			cookie.SetKey(config.CookieName)
			cookie.SetValueBytes(token)
			if config.CookiePath != "" {
				cookie.SetPath(config.CookiePath)
			}
			if config.CookieDomain != "" {
				cookie.SetDomain(config.CookieDomain)
			}
			cookie.SetExpire(time.Now().Add(time.Duration(config.CookieMaxAge) * time.Second))
			cookie.SetSecure(config.CookieSecure)
			cookie.SetHTTPOnly(config.CookieHTTPOnly)
			ctx.SetUserValue(config.ContextKey, token)
			ctx.Response.Header.SetCookie(cookie)
			ctx.Response.Header.Add("Vary", "Cookie")
			next(ctx)
		})
	}

}

// csrfTokenFromForm returns a `csrfTokenExtractor` that extracts token from the
// provided request header.
func csrfTokenFromHeader(header string) csrfTokenExtractor {
	return func(ctx *fasthttp.RequestCtx) ([]byte, error) {
		srcToken := ctx.Request.Header.Peek(header)
		return copyCSRFTokenFromRequest(srcToken)
	}
}

// csrfTokenFromForm returns a `csrfTokenExtractor` that extracts token from the
// provided form parameter.
func csrfTokenFromForm(param string) csrfTokenExtractor {
	return func(ctx *fasthttp.RequestCtx) ([]byte, error) {
		srcToken := ctx.PostArgs().Peek(param)
		return copyCSRFTokenFromRequest(srcToken)
	}
}

// csrfTokenFromQuery returns a `csrfTokenExtractor` that extracts token from the
// provided query parameter.
func csrfTokenFromQuery(param string) csrfTokenExtractor {
	return func(ctx *fasthttp.RequestCtx) ([]byte, error) {
		srcToken := ctx.QueryArgs().Peek(param)
		return copyCSRFTokenFromRequest(srcToken)
	}
}

func validateCSRFToken(token, clientToken []byte) bool {
	return subtle.ConstantTimeCompare(token, clientToken) == 1
}

func copyCSRFTokenFromRequest(srcToken []byte) ([]byte, error) {
	var dstToken []byte
	dstToken = append(dstToken, srcToken...)
	if sliceIsEmpty(dstToken) {
		return nil, errors.New(CSRFTokenNotFound)
	}
	return dstToken, nil
}

func sliceIsEmpty(slice []byte) bool {
	return len(slice) == 0
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

// randomToken generates a random token with the given size
func randomToken(size uint8) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b

}
