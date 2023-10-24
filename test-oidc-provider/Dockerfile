# Use the official Rust image as the base image
FROM rust:latest as builder

# Set the working directory in the container
WORKDIR /app

# Copy the Rust project files into the container
COPY . .

# Build your Rust application
RUN cargo build --release

# Create a smaller image for running the application
FROM debian:bookworm-slim as runtime

# Copy the built binary from the builder stage into the final image
COPY --from=builder /app/target/release/test-oidc-provider /usr/local/bin/test-oidc-provider

# Run your application when the container starts
CMD ["test-oidc-provider"]