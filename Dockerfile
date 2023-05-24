# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Set the working directory to /app
WORKDIR /app

# Copy the contents of the api directory to the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Set environment variables
ENV FLASK_APP=main.py
ENV FLASK_ENV=development

# Expose port 5000 for the Flask app
EXPOSE 5000

# Run the command to start the Flask app
CMD ["flask", "run", "--host", "0.0.0.0"]
