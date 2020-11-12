#!/bin/bash
protoc --proto_path=message --go_out=message message.proto
