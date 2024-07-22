# Proxy Server

A simple proxy server implemented in Go. This server handles incoming requests, applies rate limiting, and processes metrics using Prometheus.

## Features

- **Rate Limiting:** Uses the `golang.org/x/time/rate` package to limit the rate of incoming requests.
- **Metrics Collection:** Integrates with Prometheus for monitoring.
- **Caching:** Implements caching using `github.com/patrickmn/go-cache`.
- **Circuit Breaker:** Utilizes `github.com/sony/gobreaker` to manage failure recovery.

## Requirements

- Go 1.18 or higher
- Prometheus
- Docker (optional, for running in a container)

## Installation

1. **Clone the repository:**

  ```sh
  git clone https://github.com/yourusername/proxy-server.git
  cd proxy-server
  ```

2. **Download dependencies:**

  ```sh
  go mod tidy
  ```

3. **Build the project:**

  ```sh
  go build -o proxy-server
  ```

## Usage

1. **Run the server:**

  ```sh
  ./proxy-server
  ```

2. **Configuration:**

  Make sure you have a `config.yaml` file in the root directory. This file should contain configuration settings for the server. Example configuration:

  ```yaml
  server:
    port: 8080
  prometheus:
    metrics_path: /metrics
  ```

3. **Accessing Metrics:**

  The Prometheus metrics can be accessed at `http://localhost:8080/metrics` by default.

## Running with Docker

1. **Build the Docker image:**

  ```sh
  docker build -t proxy-server .
  ```

2. **Run the Docker container:**

  ```sh
  docker run -p 8080:8080 proxy-server
  ```

## Contributing

Contributions are welcome! Please create an issue or a pull request for any bug fixes, enhancements, or new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Prometheus](https://prometheus.io/) for metrics collection.
- [Go](https://golang.org/) for a fantastic programming language.
- [HashiCorp's LRU Cache](https://github.com/hashicorp/golang-lru) for caching implementation.
- [Patrick Mn's Go Cache](https://github.com/patrickmn/go-cache) for caching.
- [Sony's Go Breaker](https://github.com/sony/gobreaker) for circuit breaker implementation.
