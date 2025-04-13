FROM alpine:3.11.3@sha256:ab00606a42621fb68f2ed6ad3c88be54397f981a7b70a79db3d1172b11c4367d AS stage
MAINTAINER Helen Chan <hwchan@cse.cuhk.edu.hk>

# adopted from Dockerfile by Nicolas Favre-Felix <n.favrefelix@gmail.com> for webdis

RUN apk update && apk add wget make gcc libevent-dev msgpack-c-dev musl-dev bsd-compat-headers jq
RUN wget -q https://api.github.com/repos/nicolasff/webdis/tags -O /dev/stdout | jq '.[] | .name' | head -1  | sed 's/"//g' > latest
RUN wget https://github.com/nicolasff/webdis/archive/$(cat latest).tar.gz -O webdis-latest.tar.gz
RUN tar -xvzf webdis-latest.tar.gz
RUN cd webdis-$(cat latest) && make && make install && cd ..
RUN sed -i -e 's/"daemonize":.*true,/"daemonize": false,/g' /etc/webdis.prod.json

# main image
FROM alpine:3.11.3@sha256:ab00606a42621fb68f2ed6ad3c88be54397f981a7b70a79db3d1172b11c4367d
RUN apk update && apk add libevent msgpack-c
COPY --from=stage /usr/local/bin/webdis /usr/local/bin/
COPY --from=stage /etc/webdis.prod.json /etc/webdis.prod.json
ADD update_webdis_config.sh /
ENV REDIS_HOST "127.0.0.1"
ENV REDIS_PORT "6379"
CMD sh /update_webdis_config.sh /etc/webdis.prod.json && /usr/local/bin/webdis /etc/webdis.prod.json

EXPOSE 7379
