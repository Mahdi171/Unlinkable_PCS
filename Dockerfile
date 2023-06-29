# Use a base image with Ubuntu 22.04
FROM ubuntu:22.04

# Install system dependencies
# Install system dependencies
RUN apt update -y && apt upgrade -y && apt-get install -y sudo && apt-get install -y wget && apt-get install -y nano &&  \
    sudo apt-get install -y git-core curl zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev libcurl4-openssl-dev libffi-dev && \
    sudo apt-get install -y flex && sudo apt-get install -y bison && sudo apt-get install -y libgmp3-dev && \
    cd /usr/src && \
    wget https://www.python.org/ftp/python/3.8.3/Python-3.8.3.tgz && \
    tar xzf Python-3.8.3.tgz && \
    cd Python-3.8.3 && \
    sudo ./configure --enable-optimizations && \
    make && \
    sudo make install

# Install PBC library
RUN wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar xf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    sudo ./configure && \
    make && \
    sudo make install

# Install Charm-crypto library
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    sudo ./configure.sh && \
    make && \
    sudo make install

# Set up Python environment
RUN sudo apt-get install -y python3-pip

# Copy the requirements.txt file to the container
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip3 install -r /app/requirements.txt


COPY PCS/* /app/PCS/
RUN mkdir -p /app/PCS/parameters
RUN cd ..
COPY Generic_ul-PCS/* /app/Generic/
RUN mkdir -p /app/Generic/parameters
RUN touch /app/Generic/Generic.xlsx
RUN cd ..
COPY RBAC_ul-PCS/* /app/RBAC/
RUN mkdir -p /app/RBAC/parameters
RUN cd ..
COPY ul-PCS_with_SP/* /app/SP/
RUN mkdir -p /app/SP/parameters
RUN cd ..
