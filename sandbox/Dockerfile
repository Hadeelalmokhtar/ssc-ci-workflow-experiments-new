FROM python:3.10

WORKDIR /app

# Install strace (for dynamic syscall tracing)
RUN apt-get update && apt-get install -y strace && rm -rf /var/lib/apt/lists/*

# Copy everything
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure scripts module works
ENV PYTHONPATH=/app

CMD ["python", "scripts/run_analysis.py", "packages/clean_test.py"]
