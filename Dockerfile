# Copyright 2024 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builder image used to create a non-root user and to pick the SSL CA certs from
FROM alpine:3.18.0 as builder
RUN apk --update add ca-certificates
RUN adduser --disabled-password --gecos "" --uid 1001 nonroot


FROM scratch

ARG TARGETARCH
ARG TARGETOS
ARG REPO
ARG FLAVOR

# Copy the user info so we can run the container as a non-root user
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
# Copy the base SSL CA certs so we can make HTTPS requests
COPY --from=builder /etc/ssl/cert.pem /etc/ssl/cert.pem

# Run as non-root
USER nonroot:nonroot
WORKDIR /home/nonroot

ADD bin/authservice-${FLAVOR}-${TARGETOS}-${TARGETARCH} /usr/local/bin/authservice
ENTRYPOINT ["/usr/local/bin/authservice"]
