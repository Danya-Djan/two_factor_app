FROM python:3.10-slim

# Prevents Python from buffering stdout and stderr.
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container.
WORKDIR /app

# Copy only requirements file first to leverage Docker cache.
COPY requirements.txt /app/

# Install dependencies.
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code.
COPY . /app/

# Expose the port that the app runs on.
EXPOSE 8000

# Command to run the application.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"] 