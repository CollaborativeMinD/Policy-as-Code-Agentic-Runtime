# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS interpreter
ARG PYTHON_APK
RUN if [ -n "$PYTHON_APK" ]; then apk add --no-cache "python-3.13=$PYTHON_APK" libstdc++; fi

FROM interpreter AS build
RUN python -m venv /build-tools
ENV PATH="/build-tools/bin:$PATH"
WORKDIR /src
COPY . .
RUN python -m pip install --no-cache-dir -r requirements-build.lock \
    && python -m build --wheel --no-isolation --outdir /dist
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir -r requirements-postgres.lock \
    && /opt/venv/bin/python -m pip install --no-index --no-deps /dist/*.whl
RUN /opt/venv/bin/python -m pip check

FROM interpreter AS runtime
ARG SERVICE_UID
ARG SERVICE_GID
ARG REVISION
LABEL org.opencontainers.image.revision="$REVISION"
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/venv /opt/venv
RUN mkdir -p /state && touch /state/.volume-initialized && chmod 0700 /state && chown -R "$SERVICE_UID:$SERVICE_GID" /state
WORKDIR /state
USER ${SERVICE_UID}:${SERVICE_GID}
ENTRYPOINT ["prompt-chain-run"]
