package handler

import (
	"bytes"
	"net/http"

	"github.com/golang/glog"
)

func (h *handler) modifyProxyResponse(response *http.Response) error {
	if response.StatusCode == http.StatusUnauthorized {
		request := response.Request
		glog.Infof("%s %s >>> upstream responded with Unauthorized", request.RemoteAddr, request.RequestURI)
		handleRedirect(h, recycleHTTPResponse(response), request)
	}

	return nil
}

type httpResponseWriter struct {
	response *http.Response
	body     *bytes.Buffer
}

var emptyResponse = &http.Response{}

func recycleHTTPResponse(response *http.Response) http.ResponseWriter {
	request := response.Request
	*response = *emptyResponse
	response.Request = request
	response.StatusCode = http.StatusOK
	return &httpResponseWriter{response: response}
}

func (w *httpResponseWriter) Header() http.Header {
	header := w.response.Header
	if header == nil {
		header = make(http.Header)
		w.response.Header = header
	}
	return header
}

func (w *httpResponseWriter) Write(buf []byte) (int, error) {
	body := w.body
	if body == nil {
		body = new(bytes.Buffer)
		w.body = body
	}

	written, err := body.Write(buf)
	w.response.ContentLength = int64(body.Len())
	return written, err
}

func (w *httpResponseWriter) WriteHeader(statusCode int) {
	w.response.StatusCode = statusCode
}
