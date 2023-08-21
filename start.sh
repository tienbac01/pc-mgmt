#!/bin/bash
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 --reload --timeout 500 --certfile=./cert.pem --keyfile=./key.pem
