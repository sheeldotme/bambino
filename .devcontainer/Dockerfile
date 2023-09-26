FROM registry.access.redhat.com/ubi9@sha256:bd30f546dfb78ef0fb7789376afd22671319007af473f03370dafab34302c857

RUN dnf update \
  && dnf install -y git sudo \
  && useradd -m -d /home/core -s /bin/bash core \
  && usermod -G wheel core \
  && echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER core

ENV USER="core"
ENV PATH="${PATH}:/nix/var/nix/profiles/default/bin"

RUN setfacl -k /tmp \
  && curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix/tag/v0.11.0 | sh -s -- install linux --extra-conf 'sandbox = false' --init none --no-confirm \
  && sudo chown -R core:core /nix \
  && nix run nixpkgs#direnv hook bash | sudo tee -a /etc/bashrc

COPY flake.nix flake.lock .envrc /workspaces/bambino/

RUN cd /workspaces/bambino \
  && nix profile install nixpkgs#direnv \
  && nix run nixpkgs#direnv allow
