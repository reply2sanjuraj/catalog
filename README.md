

Step 1 Create the database 
File: database_setup.py 
$ python database_setup.py 

Step 2 Initialize the database with sample data
File: categories.json, items.json

Step 3 Populate the database with samples
File: lotsofcategory_items.py
$ python lotsofcategory_items.py

Step 4 Install the required packages and configure apache to serve web app
$ sudo apt-get upgrade
$ sudo apt-get install python python-pip ntp finger
$ sudo apt-get install git virtualenv apache2 libapache2-mod-wsgi postgresql postgresql-contrib python-flask python-sqlalchemy
$ virtualenv catalog
$ source catalog/bin/activate
$ sudo vi /etc/apache2/conf-available/wsgi.conf

<VirtualHost *:80>
	WSGIScriptAlias / /var/www/html/catalog/app.py
	<Directory /var/www/html/catalog>
		Order allow,deny
		Allow from all
	</Directory>
	Alias /static /var/www/html/catalog/static
	<Directory /var/www/html/catalog/static>
		Order deny,allow
		Allow from all
	</Directory>
</VirtualHost>
$ a2enconf wsgi
$ a2ensite wsgi
$ sudo ufw status
$ sudo ufw allow ssh
$ sudo ufw allow 2200/tcp
$ sudo ufw allow 123/tcp
$ sudo ufw allow 80/tcp
$ sudo ufw allow www
$ sudo ufw enable
$ sudo ufw status
$ sudo ufw allow 5000/tcp
$ sudo ufw enable
$ sudo ufw status
$ sudo vi /etc/ufw/sysctl.conf
	net/ipv4/ip_forward=1
:wq
$ sudo vi /etc/ufw/before.rules 
	*nat
	:POSTROUTING ACCEPT [0:0]
	-A POSTROUTING -o eth0 -j MASQUERADE
:wq
$ sudo ufw disable
$ sudo ufw enable
$ sudo ufw status

 
$ Create the application file and supporting templates and static css file
$ cd /var/www/html
$ git init 
$ git clone https://github.com/<yourname>/catalog.git
$ python app.py

Step 5 Access the web app from http://publicip:5000





