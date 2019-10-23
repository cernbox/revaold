# docker build .
# docker run -it -v /home/gonzalhu/go/src/github.com/cernbox/revaold:/root/go/src/github.com/cernbox/revaold 15f1b9804d2c bash
FROM cern/cc7-base
RUN yum groupinstall "Development Tools" -y
RUN curl -O https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.12.linux-amd64.tar.gz
RUN echo "PATH=$PATH:/usr/local/go/bin" >> /root/.bashrc
WORKDIR /root/revaold
