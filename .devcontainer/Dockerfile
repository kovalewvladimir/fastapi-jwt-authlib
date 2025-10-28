FROM python:3.13-alpine3.22

# Timezone
ENV TZ=Europe/Moscow
RUN apk add --update --no-cache tzdata \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

# git
RUN apk add --update --no-cache git

# UV installation
COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /uvx /bin/
ENV UV_PROJECT_ENVIRONMENT="/usr/local/"
# Install dependencies
COPY pyproject.toml uv.lock /tmp/uv/
RUN uv sync --no-cache --all-groups --project /tmp/uv && rm -rf /tmp/uv/

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true