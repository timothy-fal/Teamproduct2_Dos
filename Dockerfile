FROM ubuntu
ENV DEBIAN_FRONTEND=noninteractive

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1



RUN apt-get update
RUN apt-get install sudo -y
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt-get install apache2 -y
RUN apt-get install apache2-utils -y
RUN apt-get install iptables -y
RUN apt-get install tcpdump libpcap0.8-dev -y


COPY requirements.txt .
RUN python3 -m pip install -r requirements.txt
RUN apt-get clean


WORKDIR /app
COPY . /app
RUN python3 firewall.py

COPY ./webshop /var/www/html

EXPOSE 80
CMD ["apache2ctl","-D","FOREGROUND"]

