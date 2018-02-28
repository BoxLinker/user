FROM alpine:latest
RUN apk update
RUN apk add ca-certificates
RUN apk add -U tzdata
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir -p /app/config

COPY .env.prod /app/.env
COPY user /app/user

CMD /app/user 
