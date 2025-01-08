# Use Ubuntu as the base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install Python 3
RUN apt-get update && apt-get install -y python3 python3-pip

# Set Python 3 as the default Python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Add a working directory (optional)
WORKDIR /app

# Copy the content of the directory (if needed)
COPY . /app

# Command to keep the container running
CMD ["python3", "--version"]