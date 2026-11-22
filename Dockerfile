# A self-contained pilot box: patient-zero and nothing else, running as an unprivileged user.
#   docker build -t patient-zero .
#   docker run --rm -v "$PWD":/work patient-zero check /work           # check a project folder
#   docker run --rm -it -v "$PWD/pilot":/pilot patient-zero pilot run /pilot
# See docs/pilot/HOSTING.md.
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 pz
COPY --chown=pz:pz . /src
RUN pip install --no-cache-dir "/src[sign]" && rm -rf /src
USER pz
WORKDIR /work
ENTRYPOINT ["pz"]
CMD ["--help"]
