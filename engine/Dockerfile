FROM ghcr.io/graalvm/graalvm-ce:java11-21.3.0

# For SDKMAN to work we need unzip & zip
RUN microdnf install yum ; yum install -y unzip zip

RUN \
    # Install SDKMAN
    curl -s "https://get.sdkman.io" | bash; \
    source "$HOME/.sdkman/bin/sdkman-init.sh"; \
    # Install Maven
    sdk install maven; \
    # Install GraalVM Native Image
    gu install native-image;

RUN source "$HOME/.sdkman/bin/sdkman-init.sh" && mvn --version

RUN native-image --version

# Always use source sdkman-init.sh before any command, so that we will be able to use 'mvn' command
ENTRYPOINT bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && $0"
