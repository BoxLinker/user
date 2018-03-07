FROM alpine:latest
RUN apk update
RUN apk add ca-certificates
RUN apk add -U tzdata
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
# RUN mkdir -p /app/config

WORKDIR /bin

COPY .env.prod /bin/.env
COPY user /bin/user-server

CMD ["./user-server"]
