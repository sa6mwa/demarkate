FROM busybox:latest
ARG HOME=/demarkate
ENV HOME $HOME
WORKDIR $HOME
copy bin/demarkate $HOME
CMD ["./demarkate"]
