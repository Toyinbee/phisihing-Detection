# ✅ Use a slim Python 3.10 image for faster builds
FROM python:3.10-slim

# ✅ Environment configs to avoid .pyc files and enable streaming logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_HEADLESS=true

# ✅ Set working directory
WORKDIR /app

# ✅ Copy project files
COPY . /app

# ✅ Ensure 'data' directory exists for feedback & model updates
RUN mkdir -p /app/data

# ✅ Declare a volume for persistent data (like new_data.csv)
VOLUME ["/app/data"]

# ✅ Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# ✅ Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# ✅ Expose Streamlit default port
EXPOSE 8501

# ✅ Run the Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
