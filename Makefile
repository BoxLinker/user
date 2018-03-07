all: push

PREFIX=registry.cn-beijing.aliyuncs.com/cabernety#index.boxlinker.com/boxlinker

IMAGE_APP=user-server
IMAGE_APP_TAG=v1.0.1#${shell git describe --tags --long}

build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w' -o user
	docker build -t ${PREFIX}/${IMAGE_APP}:${IMAGE_APP_TAG} .

push: build
	docker push ${PREFIX}/${IMAGE_APP}:${IMAGE_APP_TAG}
