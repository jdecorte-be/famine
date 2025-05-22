FROM gcc:8.2

WORKDIR /tmp

RUN    curl -O https://www.nasm.us/pub/nasm/releasebuilds/2.14/nasm-2.14.tar.gz \
    && tar -xf nasm-2.14.tar.gz \
    && cd nasm-2.14 \
    && sh autogen.sh \
    && sh configure \
    && make \
    && make install \
    && cd ..

WORKDIR /
