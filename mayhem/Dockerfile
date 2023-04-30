FROM debian:bookworm as build 
RUN apt update && apt install build-essential clang llvm scons -y

COPY . /liblithium
WORKDIR /liblithium/fuzz

RUN scons

FROM debian:bookworm
COPY --from=build /liblithium/fuzz/liblithium-fuzz .