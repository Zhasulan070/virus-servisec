FROM python:3.8-slim-buster
WORKDIR /app
COPY . .
RUN pip3 -V
RUN pip3 install pipenv
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
CMD ["python", "server.py"]