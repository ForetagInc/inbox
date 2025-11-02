FROM rust:1.91.0-slim AS build
WORKDIR /usr/src/inbox
COPY . .
RUN cargo install --path .
RUN cargo build --release

FROM rust:1.91.0-slim AS runtime
COPY --from=build /usr/src/inbox/target/release/inbox .
EXPOSE 25
EXPOSE 587
EXPOSE 3000
CMD ["./inbox"]
