FROM cern/cc7-base
RUN yum groupinstall "Development Tools" -y
RUN curl -O https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.12.linux-amd64.tar.gz
RUN echo "PATH=$PATH:/usr/local/go/bin" >> /root/.bashrc
