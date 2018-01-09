package handler

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
)

func badRequest(err error, responseWriter http.ResponseWriter, request *http.Request) {
	internalServerError(err, responseWriter, request)
}

func internalServerError(err error, responseWriter http.ResponseWriter, request *http.Request) {
	httpError(http.StatusInternalServerError, err, responseWriter, request)
}

func httpError(statusCode int, err error, responseWriter http.ResponseWriter, request *http.Request) {
	statusText := http.StatusText(statusCode)
	log := fmt.Sprintf("%s %s <<< %d %s - %s", request.RemoteAddr, request.RequestURI, statusCode, statusText, err)
	if statusCode >= http.StatusInternalServerError {
		glog.Error(log)
	} else {
		glog.Info(log)
	}
	msg := fmt.Sprintf("%d %s\n", statusCode, statusText)
	http.Error(responseWriter, msg, statusCode)
}
