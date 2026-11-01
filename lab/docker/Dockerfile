# FlightCheck image: lab-init, authoritative servers, emulated resolvers and the probe.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY flightcheck ./flightcheck
COPY scenarios ./scenarios
RUN pip install --no-cache-dir .
ENTRYPOINT ["flightcheck"]
