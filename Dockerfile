FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-11-jdk \
    wget \
    unzip \
    curl \
    git \
    adb \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/android-sdk/cmdline-tools/latest /opt/android-sdk/platforms
RUN wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-tools \
    && cp -r /tmp/cmdline-tools/cmdline-tools/* /opt/android-sdk/cmdline-tools/latest/ \
    && rm -rf /tmp/cmdline-tools /tmp/cmdline-tools.zip

RUN yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk "platform-tools" "platforms;android-30" "build-tools;30.0.3" "system-images;android-30;google_apis;x86_64" >/tmp/sdkmanager.log 2>&1 || true

RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.1/apktool_2.9.1.jar -O /opt/apktool.jar && \
    printf '#!/bin/sh\njava -jar /opt/apktool.jar "$@"\n' > /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool

WORKDIR /app
COPY . /app
RUN python3 -m pip install --no-cache-dir -r requirements.txt
RUN chmod +x /app/run_pipeline.sh /app/setup.sh /app/pre_flight_check.py /app/cleanup.py
ENTRYPOINT ["/app/run_pipeline.sh"]
