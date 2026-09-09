# Runs the Flask-Aegis interactive playground -- NOT intended as a
# production deployment base image for applications *using*
# Flask-Aegis. See docs/DEPLOYMENT.md for that.
#
# Build:
#   docker build -t flask-aegis-playground .
# Run:
#   docker run --rm -p 5050:5050 flask-aegis-playground
# Then open http://127.0.0.1:5050
#
# Verification note: this Dockerfile was written without a local Docker
# daemon available in the environment that authored it, so `docker
# build`/`docker run` themselves have not been executed end-to-end.
# What WAS verified directly: the exact command in CMD below
# (`python -m flask_aegis.playground --host 0.0.0.0 --port 5050`) was
# run locally outside a container and confirmed to bind and serve
# correctly. Please run the build yourself and file an issue if
# anything here doesn't work as described.

FROM python:3.12-slim

# The playground has no compiled dependencies of its own -- Flask,
# Click, and PyYAML are all pure Python, so no build-essential/gcc
# layer is needed.
WORKDIR /app

# Install the package itself from this repo checkout rather than from
# PyPI, so the image always reflects the code you're building from.
# README.md must be copied too -- pyproject.toml declares it as the
# package readme (`readme = "README.md"`), and pip's build backend
# reads it during metadata generation; without it the build still
# succeeds but produces an empty package long-description.
COPY pyproject.toml README.md ./
COPY flask_aegis ./flask_aegis
RUN pip install --no-cache-dir .

EXPOSE 5050

# Run as a non-root user inside the container.
RUN useradd --create-home --shell /bin/bash aegis
USER aegis

# Security note: 0.0.0.0 here binds within the container's own network
# namespace -- the container boundary (and whether you publish the port
# with `docker run -p`) is what actually controls external reachability,
# not this bind address. The playground itself still carries real
# capability on some attack demos (see flask_aegis/playground/README.md
# -- SSTI genuinely evaluates Jinja server-side); don't publish this
# container's port on a host or network you don't fully trust.
CMD ["python", "-m", "flask_aegis.playground", "--host", "0.0.0.0", "--port", "5050"]
