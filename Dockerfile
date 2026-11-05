FROM php:8.3-alpine

# Install sqlite and pdo_sqlite
RUN apk add --no-cache sqlite-dev \
    && docker-php-ext-install pdo_sqlite

# Set up outside-docroot telemetry data directory
RUN mkdir -p /var/lib/telemetry /var/www/html \
    && chown -R www-data:www-data /var/lib/telemetry /var/www/html

WORKDIR /var/www/html

# Copy application source code
COPY src/ /var/www/html/

# Environment configuration
ENV TELEMETRY_DATA_DIR=/var/lib/telemetry \
    PORT=8080

EXPOSE 8080

USER www-data

CMD ["php", "-d", "display_errors=0", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]
