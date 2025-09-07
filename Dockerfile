# Use PHP with Apache
FROM php:8.2-apache

# Enable useful extensions (optional, remove if not needed)
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy your PHP files into Apache web root
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# Expose web server port
EXPOSE 80
