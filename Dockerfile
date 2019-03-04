FROM python:3.6-alpine

RUN apk update && \
    apk upgrade

RUN pip install requests==2.21.0
RUN pip install duo-client==4.1.0

WORKDIR /usr/src/app
COPY duo_log_grabber.py .

CMD [ "python", "./duo_log_grabber.py" ]
